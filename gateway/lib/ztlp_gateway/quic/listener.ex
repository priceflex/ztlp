defmodule ZtlpGateway.Quic.Listener do
  @moduledoc """
  QUIC listener for ZTLP (msquic via `:quicer`).

  Accepts QUIC connections with ALPN `ztlp/1`, completes the TLS 1.3
  handshake, and hands each connection to a `ZtlpGateway.Quic.Connection`
  process which runs the stream-0 ZTLP handshake and proxies data streams.

  Persistent material (R3 in ztlp-cloud-demo-plan.md) lives in `data_dir`
  (default `ZTLP_GATEWAY_QUIC_DATA_DIR` or `/var/lib/ztlp/gateway`):

    * `quic-cert.pem` / `quic-key.pem` — self-signed ECDSA P-256 server cert.
      The Rust client TOFU-pins the leaf's SHA-256 under SNI `localhost`, so
      this MUST be stable across restarts or already-enrolled clients break.
    * `quic-static.key` — hex X25519 seed, the gateway's Noise static identity.

  Env: `ZTLP_GATEWAY_QUIC_ENABLED` (true/false), `ZTLP_GATEWAY_QUIC_PORT`
  (default 23097), `ZTLP_GATEWAY_QUIC_ACCEPTORS` (default 8).
  """

  use GenServer
  require Logger

  alias ZtlpGateway.Quic.{Connection, Handshake}

  @alpn [~c"ztlp/1"]
  @default_port 23097
  @default_acceptors 8

  defstruct [:listener, :port, :data_dir, :static_pub, :static_priv, :node_id, acceptors: []]

  # ---------------------------------------------------------------------------
  # API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
  end

  @doc "Actual bound UDP port (useful when started with `port: 0`)."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server), do: GenServer.call(server, :port)

  @doc "Should the QUIC listener be part of the supervision tree?"
  def enabled? do
    case System.get_env("ZTLP_GATEWAY_QUIC_ENABLED") do
      nil -> Application.get_env(:ztlp_gateway, :quic_enabled, false)
      v -> v in ["1", "true", "TRUE", "yes"]
    end
  end

  def default_port do
    case System.get_env("ZTLP_GATEWAY_QUIC_PORT") do
      nil -> Application.get_env(:ztlp_gateway, :quic_port, @default_port)
      p -> String.to_integer(p)
    end
  end

  def default_data_dir do
    System.get_env("ZTLP_GATEWAY_QUIC_DATA_DIR") ||
      Application.get_env(:ztlp_gateway, :quic_data_dir, "/var/lib/ztlp/gateway")
  end

  # ---------------------------------------------------------------------------
  # GenServer
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, default_port())
    data_dir = Keyword.get(opts, :data_dir, default_data_dir())
    n_acceptors = Keyword.get(opts, :acceptors, acceptors_from_env())

    File.mkdir_p!(data_dir)
    {certfile, keyfile} = ensure_cert_pair(data_dir)
    {static_pub, static_priv} = Handshake.load_or_create_static_key(Path.join(data_dir, "quic-static.key"))
    node_id = ZtlpGateway.Config.node_id()

    listen_opts = %{
      alpn: @alpn,
      certfile: certfile,
      keyfile: keyfile,
      idle_timeout_ms: 90_000,
      handshake_idle_timeout_ms: 10_000,
      peer_bidi_stream_count: 256,
      peer_unidi_stream_count: 0
    }

    case :quicer.listen(port, listen_opts) do
      {:ok, listener} ->
        bound = bound_port(listener, port)

        state = %__MODULE__{
          listener: listener,
          port: bound,
          data_dir: data_dir,
          static_pub: static_pub,
          static_priv: static_priv,
          node_id: node_id
        }

        acceptors = for _ <- 1..n_acceptors, do: spawn_acceptor(state)

        Logger.info(
          "[Quic.Listener] ZTLP QUIC listening on UDP #{bound} (ALPN ztlp/1, static=#{Base.encode16(static_pub, case: :lower)})"
        )

        {:ok, %{state | acceptors: acceptors}}

      {:error, reason} ->
        {:stop, {:quic_listen_failed, reason}}

      {:error, reason, detail} ->
        {:stop, {:quic_listen_failed, reason, detail}}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  @impl true
  def handle_info({:accepted, pid}, state) do
    # A Connection process left the acceptor pool by accepting a connection;
    # keep the pool size constant.
    acceptors = [spawn_acceptor(state) | List.delete(state.acceptors, pid)]
    {:noreply, %{state | acceptors: acceptors}}
  end

  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    if pid in state.acceptors do
      if reason != :normal, do: Logger.warning("[Quic.Listener] acceptor died: #{inspect(reason)}; respawning")
      acceptors = [spawn_acceptor(state) | List.delete(state.acceptors, pid)]
      {:noreply, %{state | acceptors: acceptors}}
    else
      {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{listener: listener}) when listener != nil do
    :quicer.close_listener(listener, 1_000)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # ---------------------------------------------------------------------------
  # Acceptors
  # ---------------------------------------------------------------------------
  #
  # Each acceptor IS a `Quic.Connection` process: it blocks in `:quicer.accept`,
  # registers the stream-0 acceptor BEFORE finishing the TLS handshake (so the
  # client's first stream can never be orphaned), then tells us `{:accepted,
  # self()}` so we spawn a replacement. This is quicer's documented pattern.

  defp spawn_acceptor(state) do
    args = %{
      listener: state.listener,
      owner: self(),
      static_pub: state.static_pub,
      static_priv: state.static_priv,
      node_id: state.node_id
    }

    {:ok, pid} = Connection.start(args)
    Process.monitor(pid)
    pid
  end

  # ---------------------------------------------------------------------------
  # Persistent self-signed cert (pure OTP, no openssl binary needed)
  # ---------------------------------------------------------------------------

  defp ensure_cert_pair(data_dir) do
    certfile = Path.join(data_dir, "quic-cert.pem")
    keyfile = Path.join(data_dir, "quic-key.pem")

    unless File.exists?(certfile) and File.exists?(keyfile) do
      %{cert: cert_der, key: key} =
        :public_key.pkix_test_root_cert(~c"ztlp-gateway", key: {:namedCurve, :secp256r1})

      cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
      key_pem = :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, key)])

      File.write!(keyfile, key_pem)
      File.chmod!(keyfile, 0o600)
      File.write!(certfile, cert_pem)
      Logger.info("[Quic.Listener] generated self-signed QUIC cert at #{certfile}")
    end

    {String.to_charlist(certfile), String.to_charlist(keyfile)}
  end

  defp bound_port(listener, requested) do
    case :quicer.sockname(listener) do
      {:ok, {_ip, port}} -> port
      _ -> requested
    end
  end

  defp acceptors_from_env do
    case System.get_env("ZTLP_GATEWAY_QUIC_ACCEPTORS") do
      nil -> @default_acceptors
      n -> String.to_integer(n)
    end
  end
end
