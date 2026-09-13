defmodule ZtlpGateway.Quic.Handshake do
  @moduledoc """
  Stream-0 handshake state machine for ZTLP-over-QUIC (responder side).

  Byte-exact with `proto/src/quic_transport.rs::run_initiator_handshake`:

      C->S  service_hash        16 raw bytes, NOT framed
      C->S  frame(msg1)         Noise XX msg1: e(32) || cleartext payload(16 = client NodeID)
      S->C  session_id          12 raw bytes, NOT framed, random
      S->C  frame(msg2)         e(32) || enc s(48) || enc payload(16 NodeID + 16 tag)
      C->S  frame(msg3)         enc s(48) || enc payload(16 NodeID + 16 tag)

  Pure step function: feed it whatever bytes the QUIC stream delivered,
  get back bytes to send. Reuses `ZtlpGateway.Handshake` for the Noise
  math (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, empty prologue) and
  `ZtlpGateway.Quic.Frame` for the L2 magic framing.

  Every Noise payload carries the sender's 16-byte NodeID (Rust
  `handshake.rs::write_message`, SAST fne-nxah); payloads shorter than
  that are a protocol error, exactly as on the Rust side.

  Post-handshake there is NO Noise transport encryption on the data
  streams (QUIC TLS 1.3 provides it); `transport_keys` are returned for
  parity/diagnostics only.
  """

  alias ZtlpGateway.Crypto
  alias ZtlpGateway.Handshake, as: Noise
  alias ZtlpGateway.Quic.Frame

  @service_hash_len 16
  @session_id_len 12
  @node_id_len 16

  @type t :: %__MODULE__{
          phase: :await_msg1 | :await_msg3,
          buf: binary(),
          noise: Noise.state(),
          node_id: binary(),
          service_hash: binary() | nil,
          session_id: binary() | nil
        }

  defstruct phase: :await_msg1, buf: <<>>, noise: nil, node_id: nil, service_hash: nil, session_id: nil

  @type result :: %{
          service_hash: binary(),
          session_id: binary(),
          client_static_pub: binary(),
          client_node_id: binary(),
          transport_keys: %{i2r_key: binary(), r2i_key: binary()}
        }

  @doc "Start a responder for one QUIC connection's stream 0."
  @spec new(binary(), binary(), binary()) :: t()
  def new(static_pub, static_priv, node_id)
      when byte_size(static_pub) == 32 and byte_size(static_priv) == 32 and
             byte_size(node_id) == @node_id_len do
    %__MODULE__{noise: Noise.init_responder(static_pub, static_priv), node_id: node_id}
  end

  @doc """
  Feed bytes received on stream 0.

  Returns `{:continue, state, bytes_to_send}` while more input is needed,
  `{:done, result, bytes_to_send}` once msg3 verified, or `{:error, reason}`.
  """
  @spec step(t(), binary()) :: {:continue, t(), binary()} | {:done, result(), binary()} | {:error, atom()}
  def step(%__MODULE__{buf: buf} = st, data) when is_binary(data) do
    advance(%{st | buf: buf <> data}, <<>>)
  end

  # --- msg1: need 16 raw bytes + one full frame -------------------------------

  defp advance(%{phase: :await_msg1, buf: buf} = st, out)
       when byte_size(buf) < @service_hash_len do
    {:continue, st, out}
  end

  defp advance(%{phase: :await_msg1, buf: buf} = st, out) do
    <<svc::binary-size(@service_hash_len), rest::binary>> = buf

    case Frame.decode(rest) do
      {:more, _} ->
        {:continue, st, out}

      {:error, reason} ->
        {:error, reason}

      {:ok, msg1, tail} ->
        with {:ok, noise, _client_nid} <- msg1(st.noise, msg1) do
          session_id = :crypto.strong_rand_bytes(@session_id_len)
          {noise, msg2} = Noise.create_msg2(noise, st.node_id)

          st = %{st | phase: :await_msg3, buf: tail, noise: noise, service_hash: svc, session_id: session_id}
          advance(st, out <> session_id <> Frame.encode(msg2))
        end
    end
  end

  # --- msg3: one full frame ----------------------------------------------------

  defp advance(%{phase: :await_msg3, buf: buf} = st, out) do
    case Frame.decode(buf) do
      {:more, _} ->
        {:continue, st, out}

      {:error, reason} ->
        {:error, reason}

      {:ok, msg3, _tail} ->
        case Noise.handle_msg3(st.noise, msg3) do
          {:error, reason} ->
            {:error, reason}

          {_noise, payload} when byte_size(payload) < @node_id_len ->
            {:error, :msg3_payload_too_short}

          {noise, <<client_nid::binary-size(@node_id_len), _app::binary>>} ->
            {:ok, keys} = Noise.split(noise)

            {:done,
             %{
               service_hash: st.service_hash,
               session_id: st.session_id,
               client_static_pub: noise.rs,
               client_node_id: client_nid,
               transport_keys: keys
             }, out}
        end
    end
  end

  defp msg1(noise, msg1) do
    case Noise.handle_msg1(noise, msg1) do
      {:error, reason} -> {:error, reason}
      {_noise, payload} when byte_size(payload) < @node_id_len -> {:error, :msg1_payload_too_short}
      {noise, <<nid::binary-size(@node_id_len), _::binary>>} -> {:ok, noise, nid}
    end
  end

  # --- persisted static identity (R3-style: never regenerate per start) -------

  @doc """
  Load the gateway's QUIC-path X25519 static key from `path` (64 hex chars,
  same style as `demo/gateway-identity.key`), generating and persisting it
  (mode 0600) if absent. Returns `{pub, priv}`.
  """
  @spec load_or_create_static_key(Path.t()) :: {binary(), binary()}
  def load_or_create_static_key(path) do
    case File.read(path) do
      {:ok, hex} ->
        priv = hex |> String.trim() |> Base.decode16!(case: :mixed)
        32 = byte_size(priv)
        {pub, ^priv} = :crypto.generate_key(:ecdh, :x25519, priv)
        {pub, priv}

      {:error, :enoent} ->
        {pub, priv} = Crypto.generate_keypair()
        File.mkdir_p!(Path.dirname(path))
        File.write!(path, Base.encode16(priv, case: :lower) <> "\n")
        File.chmod!(path, 0o600)
        {pub, priv}
    end
  end
end
