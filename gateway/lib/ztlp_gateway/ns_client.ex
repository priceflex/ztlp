defmodule ZtlpGateway.NsClient do
  @moduledoc """
  UDP client for querying ZTLP-NS namespace server.

  Maintains a UDP socket and provides `query_key/1` to look up
  ZTLP_KEY records by public key. Uses the NS wire protocol with
  query type `0x05` (pubkey lookup).

  ## Wire Protocol

  Query (to NS):
  ```
  <<0x05, pubkey_hex_len::16, pubkey_hex::binary>>
  ```

  Responses (from NS):
  - `0x02` + record wire format = found
  - `0x03` + ... = not found
  - `0x04` + ... = revoked
  - `0xFF` = invalid query

  ## Caching

  Successful lookups are cached locally with TTL from the record.
  Cache entries are `{pubkey_hex, {record_map, expires_at}}`.

  ## Trust Chain Verification

  After decoding a record, we verify:
  1. The record's Ed25519 signature is valid
  2. The signer's public key is a configured trust anchor

  For the prototype, trust chain walking beyond one level (record →
  trust anchor) is not implemented. The gateway operator configures
  which NS signing keys to trust.

  ## Fault Tolerance

  If the NS server is unreachable (timeout), `query_key/1` returns
  `{:error, :timeout}`. The Identity module falls back to local cache
  only — the gateway doesn't crash.
  """

  use GenServer

  alias ZtlpGateway.{Config, Crypto}

  @ns_cache :ztlp_gateway_ns_cache

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(_args) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @doc """
  Query ZTLP-NS for a ZTLP_KEY record matching the given public key.

  The `pubkey` is a 32-byte X25519 public key. It's hex-encoded and
  sent to NS via the `0x05` query type.

  Returns:
  - `{:ok, record_map}` — record found and verified
  - `{:error, :not_found}` — no matching record
  - `{:error, :revoked}` — key has been revoked
  - `{:error, :timeout}` — NS server didn't respond in time
  - `{:error, :invalid_response}` — couldn't parse the response
  - `{:error, :invalid_signature}` — record signature verification failed
  - `{:error, :untrusted_signer}` — signer is not a trust anchor
  """
  @spec query_key(binary()) :: {:ok, map()} | {:error, atom()}
  def query_key(pubkey) when byte_size(pubkey) == 32 do
    pubkey_hex = Base.encode16(pubkey, case: :lower)

    # Check local NS cache first
    case cache_lookup(pubkey_hex) do
      {:ok, _} = hit -> hit
      :miss -> GenServer.call(__MODULE__, {:query_key, pubkey_hex}, 10_000)
    end
  end

  @doc """
  Add a trust anchor for verifying NS records.

  The public key is the Ed25519 key that signs records in ZTLP-NS.
  """
  @spec add_trust_anchor(String.t(), binary()) :: :ok
  def add_trust_anchor(label, public_key) when is_binary(label) and byte_size(public_key) == 32 do
    GenServer.call(__MODULE__, {:add_trust_anchor, label, public_key})
  end

  @doc "List configured trust anchors."
  @spec trust_anchors() :: [{String.t(), binary()}]
  def trust_anchors do
    GenServer.call(__MODULE__, :list_trust_anchors)
  end

  @doc "Clear the NS query cache."
  @spec clear_cache() :: :ok
  def clear_cache do
    GenServer.call(__MODULE__, :clear_cache)
  end

  @doc "Clear all trust anchors."
  @spec clear_trust_anchors() :: :ok
  def clear_trust_anchors do
    GenServer.call(__MODULE__, :clear_trust_anchors)
  end

  # ── GenServer Callbacks ────────────────────────────────────────────

  @impl true
  def init(:ok) do
    # Open a UDP socket for sending queries (port 0 = OS-assigned)
    case :gen_udp.open(0, [:binary, {:active, false}]) do
      {:ok, socket} ->
        # Create cache table
        if :ets.whereis(@ns_cache) == :undefined do
          :ets.new(@ns_cache, [:named_table, :set, :public, read_concurrency: true])
        end

        {:ok, %{socket: socket, trust_anchors: %{}}}

      {:error, reason} ->
        # Don't crash the supervision tree — start without a socket
        require Logger
        Logger.warn("NsClient: failed to open UDP socket: #{inspect(reason)}")
        {:ok, %{socket: nil, trust_anchors: %{}}}
    end
  end

  @impl true
  def handle_call({:query_key, _pubkey_hex}, _from, %{socket: nil} = state) do
    # No socket available — can't query
    {:reply, {:error, :no_socket}, state}
  end

  def handle_call({:query_key, pubkey_hex}, _from, state) do
    # Check cache again (in case another caller cached it while we waited)
    case cache_lookup(pubkey_hex) do
      {:ok, _} = hit ->
        {:reply, hit, state}

      :miss ->
        result = do_query(state.socket, pubkey_hex, state.trust_anchors)

        # Cache successful results
        case result do
          {:ok, record_map} ->
            ttl = Map.get(record_map, :ttl, 86400)
            expires_at = System.system_time(:second) + ttl
            :ets.insert(@ns_cache, {pubkey_hex, {record_map, expires_at}})

          _ ->
            :ok
        end

        {:reply, result, state}
    end
  end

  def handle_call({:add_trust_anchor, label, public_key}, _from, state) do
    {:reply, :ok, %{state | trust_anchors: Map.put(state.trust_anchors, label, public_key)}}
  end

  def handle_call(:list_trust_anchors, _from, state) do
    {:reply, Map.to_list(state.trust_anchors), state}
  end

  def handle_call(:clear_cache, _from, state) do
    if :ets.whereis(@ns_cache) != :undefined do
      :ets.delete_all_objects(@ns_cache)
    end

    {:reply, :ok, state}
  end

  def handle_call(:clear_trust_anchors, _from, state) do
    {:reply, :ok, %{state | trust_anchors: %{}}}
  end

  @impl true
  def terminate(_reason, %{socket: socket}) when not is_nil(socket) do
    :gen_udp.close(socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # ── Private: Query Execution ───────────────────────────────────────

  defp do_query(socket, pubkey_hex, trust_anchors) do
    host = Config.get(:ns_server_host)
    port = Config.get(:ns_server_port)
    timeout = Config.get(:ns_query_timeout_ms)

    # Build the 0x05 query
    pk_len = byte_size(pubkey_hex)
    query = <<0x05, pk_len::16, pubkey_hex::binary>>

    # Send and wait for response
    :gen_udp.send(socket, host, port, query)

    case :gen_udp.recv(socket, 0, timeout) do
      {:ok, {_ip, _port, response}} ->
        parse_response(response, trust_anchors)

      {:error, :timeout} ->
        {:error, :timeout}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ── Private: Response Parsing ──────────────────────────────────────

  defp parse_response(<<0x02, record_bin::binary>>, trust_anchors) do
    # Record found — decode the wire format
    case decode_record(record_bin) do
      {:ok, record_map} ->
        # Verify the signature
        case verify_record(record_map) do
          true ->
            # Check trust anchor
            case verify_trust(record_map, trust_anchors) do
              :ok -> {:ok, record_map}
              {:error, _} = err -> err
            end

          false ->
            {:error, :invalid_signature}
        end

      {:error, _} = err ->
        err
    end
  end

  defp parse_response(<<0x03, _rest::binary>>, _trust_anchors), do: {:error, :not_found}
  defp parse_response(<<0x04, _rest::binary>>, _trust_anchors), do: {:error, :revoked}
  defp parse_response(<<0xFF>>, _trust_anchors), do: {:error, :invalid_query}
  defp parse_response(_, _trust_anchors), do: {:error, :invalid_response}

  # ── Private: Record Wire Format Decoding ───────────────────────────
  # Mirrors ZtlpNs.Record.decode/1 — we can't reference it directly
  # since gateway and NS are separate Mix projects.
  #
  # Wire format:
  # <<type_byte::8, name_len::16, name::binary-size(name_len),
  #   data_len::32, data_bin::binary-size(data_len),
  #   created_at::64, ttl::32, serial::64,
  #   sig_len::16, signature::binary-size(sig_len),
  #   pub_len::16, public_key::binary-size(pub_len)>>

  @type_map %{1 => :key, 2 => :svc, 3 => :relay, 4 => :policy, 5 => :revoke, 6 => :bootstrap}

  defp decode_record(data) when is_binary(data) do
    <<type_byte::8, name_len::16, rest::binary>> = data
    <<name::binary-size(name_len), rest2::binary>> = rest
    <<data_len::32, rest3::binary>> = rest2
    <<data_bin::binary-size(data_len), rest4::binary>> = rest3
    <<created_at::unsigned-big-64, ttl::unsigned-big-32, serial::unsigned-big-64, rest5::binary>> = rest4
    <<sig_len::16, sig::binary-size(sig_len), pub_len::16, pub::binary-size(pub_len)>> = rest5

    type = Map.get(@type_map, type_byte, :unknown)
    record_data = :erlang.binary_to_term(data_bin, [:safe])

    # Reconstruct the canonical bytes (everything before the signature)
    canonical = <<type_byte::8,
      name_len::16, name::binary,
      data_len::32, data_bin::binary,
      created_at::unsigned-big-64,
      ttl::unsigned-big-32,
      serial::unsigned-big-64>>

    {:ok, %{
      name: name,
      type: type,
      data: record_data,
      signature: sig,
      signer_public_key: pub,
      created_at: created_at,
      ttl: ttl,
      serial: serial,
      canonical: canonical
    }}
  rescue
    _ -> {:error, :invalid_wire_format}
  end

  # ── Private: Signature Verification ────────────────────────────────

  defp verify_record(%{canonical: canonical, signature: sig, signer_public_key: pub})
       when is_binary(sig) and is_binary(pub) and byte_size(sig) == 64 and byte_size(pub) == 32 do
    Crypto.verify(canonical, sig, pub)
  end

  defp verify_record(_), do: false

  # ── Private: Trust Anchor Verification ─────────────────────────────

  defp verify_trust(%{signer_public_key: _pub}, trust_anchors) when map_size(trust_anchors) == 0 do
    # No trust anchors configured — accept all signed records
    # (prototype convenience; production would require at least one anchor)
    :ok
  end

  defp verify_trust(%{signer_public_key: pub}, trust_anchors) do
    trusted? = Enum.any?(trust_anchors, fn {_label, anchor_key} -> anchor_key == pub end)

    if trusted? do
      :ok
    else
      {:error, :untrusted_signer}
    end
  end

  # ── Private: Cache ─────────────────────────────────────────────────

  defp cache_lookup(pubkey_hex) do
    case :ets.lookup(@ns_cache, pubkey_hex) do
      [{^pubkey_hex, {record_map, expires_at}}] ->
        if System.system_time(:second) < expires_at do
          {:ok, record_map}
        else
          # Expired — remove and miss
          :ets.delete(@ns_cache, pubkey_hex)
          :miss
        end

      [] ->
        :miss
    end
  rescue
    # Table might not exist yet
    ArgumentError -> :miss
  end
end
