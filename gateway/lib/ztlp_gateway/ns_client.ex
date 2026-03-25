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
  @group_cache :ztlp_gateway_group_cache
  @user_cache :ztlp_gateway_user_cache
  @revocation_cache :ztlp_gateway_revocation_cache
  @revocation_cache_ttl 300  # 5 minutes TTL for revocation status cache

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
  def query_key(pubkey, timeout \\ 10_000) when byte_size(pubkey) == 32 do
    pubkey_hex = Base.encode16(pubkey, case: :lower)

    # Check local NS cache first
    case cache_lookup(pubkey_hex) do
      {:ok, _} = hit -> hit
      :miss -> GenServer.call(__MODULE__, {:query_key, pubkey_hex}, timeout)
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

  @doc """
  Query ZTLP-NS for a GROUP record by name.

  Returns `{:ok, record_map}` or `{:error, reason}`.
  Results are cached with TTL.
  """
  @spec query_group(String.t()) :: {:ok, map()} | {:error, atom()}
  def query_group(group_name) when is_binary(group_name) do
    case group_cache_lookup(group_name) do
      {:ok, _} = hit -> hit
      :miss -> GenServer.call(__MODULE__, {:query_group, group_name}, 10_000)
    end
  end

  @doc """
  Query ZTLP-NS for a USER record by name.

  Returns `{:ok, record_map}` or `{:error, reason}`.
  Results are cached with TTL.
  """
  @spec query_user(String.t()) :: {:ok, map()} | {:error, atom()}
  def query_user(user_name) when is_binary(user_name) do
    case user_cache_lookup(user_name) do
      {:ok, _} = hit -> hit
      :miss -> GenServer.call(__MODULE__, {:query_user, user_name}, 10_000)
    end
  end

  @doc """
  Check if a user is a member of a group.

  Queries the GROUP record from NS and checks the members list.
  Results are cached.
  """
  @spec is_group_member?(String.t(), String.t()) :: boolean()
  def is_group_member?(group_name, user_name) do
    case query_group(group_name) do
      {:ok, record_map} ->
        members = Map.get(record_map, :members) ||
                  Map.get(record_map, "members") ||
                  get_in(record_map, [:data, "members"]) ||
                  get_in(record_map, [:data, :members]) ||
                  []
        user_name in members
      _ ->
        false
    end
  end

  @doc """
  Check if a name (device, user, or group) has been revoked in NS.

  Results are cached with a short TTL (5 minutes) to avoid hitting NS
  on every connection while still detecting revocations promptly.

  Returns `true` if revoked, `false` otherwise.
  """
  @spec is_revoked?(String.t()) :: boolean()
  def is_revoked?(name) when is_binary(name) do
    case revocation_cache_lookup(name) do
      {:ok, result} -> result
      :miss -> GenServer.call(__MODULE__, {:check_revoked, name}, 10_000)
    end
  end

  @doc """
  Check if a device's owner (user) has been revoked.

  For revocation cascading: when a device connects, check if the device
  itself is revoked OR if the device's owner is revoked. Returns `true`
  if either the device or its owner is revoked.
  """
  @spec is_identity_revoked?(String.t()) :: boolean()
  def is_identity_revoked?(name) when is_binary(name) do
    # Check if the name itself is revoked
    if is_revoked?(name) do
      true
    else
      # If it's a device, also check the owner
      case query_device_owner(name) do
        {:ok, owner} when is_binary(owner) and owner != "" ->
          is_revoked?(owner)
        _ ->
          false
      end
    end
  end

  @doc """
  Query the owner of a device from NS.

  Returns `{:ok, owner_name}` or `{:error, reason}`.
  """
  @spec query_device_owner(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def query_device_owner(device_name) when is_binary(device_name) do
    case do_name_query_direct(device_name, 0x10) do
      {:ok, record_map} ->
        owner = get_in(record_map, [:data, "owner"]) ||
                get_in(record_map, [:data, :owner]) ||
                Map.get(record_map, :owner) ||
                Map.get(record_map, "owner")
        if owner, do: {:ok, owner}, else: {:error, :no_owner}
      error ->
        error
    end
  end

  @doc """
  Get the role of a user from their USER record.

  Returns the role string (e.g., "admin", "tech", "user") or nil.
  """
  @spec user_role(String.t()) :: String.t() | nil
  def user_role(user_name) do
    case query_user(user_name) do
      {:ok, record_map} ->
        Map.get(record_map, :role) ||
          Map.get(record_map, "role") ||
          get_in(record_map, [:data, "role"]) ||
          get_in(record_map, [:data, :role])
      _ ->
        nil
    end
  end

  # ── GenServer Callbacks ────────────────────────────────────────────

  @impl true
  def init(:ok) do
    # Open a UDP socket for sending queries (port 0 = OS-assigned)
    case :gen_udp.open(0, [:binary, {:active, false}]) do
      {:ok, socket} ->
        # Create cache tables
        if :ets.whereis(@ns_cache) == :undefined do
          :ets.new(@ns_cache, [:named_table, :set, :public, read_concurrency: true])
        end

        if :ets.whereis(@group_cache) == :undefined do
          :ets.new(@group_cache, [:named_table, :set, :public, read_concurrency: true])
        end

        if :ets.whereis(@user_cache) == :undefined do
          :ets.new(@user_cache, [:named_table, :set, :public, read_concurrency: true])
        end

        if :ets.whereis(@revocation_cache) == :undefined do
          :ets.new(@revocation_cache, [:named_table, :set, :public, read_concurrency: true])
        end

        {:ok, %{socket: socket, trust_anchors: %{}}}

      {:error, reason} ->
        # Don't crash the supervision tree — start without a socket
        require Logger
        Logger.warning("NsClient: failed to open UDP socket: #{inspect(reason)}")
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

  def handle_call({:query_group, group_name}, _from, state) do
    case group_cache_lookup(group_name) do
      {:ok, _} = hit ->
        {:reply, hit, state}

      :miss ->
        result = do_name_query(state.socket, group_name, 0x12, state.trust_anchors)

        case result do
          {:ok, record_map} ->
            ttl = Map.get(record_map, :ttl, 86400)
            expires_at = System.system_time(:second) + ttl
            :ets.insert(@group_cache, {group_name, {record_map, expires_at}})

          _ ->
            :ok
        end

        {:reply, result, state}
    end
  end

  def handle_call({:check_revoked, name}, _from, state) do
    case revocation_cache_lookup(name) do
      {:ok, result} ->
        {:reply, result, state}

      :miss ->
        # Query NS for any record type — if we get :revoked back, it's revoked
        # We try the name as a generic query; the NS response code 0x04 means revoked
        result = do_revocation_check(state.socket, name)

        # Cache the result
        expires_at = System.system_time(:second) + @revocation_cache_ttl
        if :ets.whereis(@revocation_cache) != :undefined do
          :ets.insert(@revocation_cache, {name, {result, expires_at}})
        end

        {:reply, result, state}
    end
  end

  def handle_call({:query_name_direct, name, type_byte}, _from, state) do
    result = do_name_query(state.socket, name, type_byte, state.trust_anchors)
    {:reply, result, state}
  end

  def handle_call({:query_user, user_name}, _from, state) do
    case user_cache_lookup(user_name) do
      {:ok, _} = hit ->
        {:reply, hit, state}

      :miss ->
        result = do_name_query(state.socket, user_name, 0x11, state.trust_anchors)

        case result do
          {:ok, record_map} ->
            ttl = Map.get(record_map, :ttl, 86400)
            expires_at = System.system_time(:second) + ttl
            :ets.insert(@user_cache, {user_name, {record_map, expires_at}})

          _ ->
            :ok
        end

        {:reply, result, state}
    end
  end

  def handle_call(:clear_cache, _from, state) do
    if :ets.whereis(@ns_cache) != :undefined do
      :ets.delete_all_objects(@ns_cache)
    end

    if :ets.whereis(@group_cache) != :undefined do
      :ets.delete_all_objects(@group_cache)
    end

    if :ets.whereis(@user_cache) != :undefined do
      :ets.delete_all_objects(@user_cache)
    end

    if :ets.whereis(@revocation_cache) != :undefined do
      :ets.delete_all_objects(@revocation_cache)
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

  # ── Private: Revocation Check ────────────────────────────────────────

  # Check if a name is revoked by querying NS.
  # We query for a KEY record (type 0x01) — if NS responds with 0x04,
  # the name is revoked regardless of record type.
  defp do_revocation_check(nil, _name), do: false

  defp do_revocation_check(socket, name) do
    host = Config.get(:ns_server_host)
    port = Config.get(:ns_server_port)
    timeout = Config.get(:ns_query_timeout_ms)

    # Query for KEY type — but we only care about the response code
    name_len = byte_size(name)
    query = <<0x01, name_len::16, name::binary, 0x01::8>>

    :gen_udp.send(socket, host, port, query)

    case :gen_udp.recv(socket, 0, timeout) do
      {:ok, {_ip, _port, <<0x04, _rest::binary>>}} -> true
      _ -> false
    end
  end

  defp revocation_cache_lookup(name) do
    case :ets.lookup(@revocation_cache, name) do
      [{^name, {result, expires_at}}] ->
        if System.system_time(:second) < expires_at do
          {:ok, result}
        else
          :ets.delete(@revocation_cache, name)
          :miss
        end

      [] ->
        :miss
    end
  rescue
    ArgumentError -> :miss
  end

  # Direct name query without caching (used internally for device owner lookups)
  defp do_name_query_direct(name, type_byte) do
    GenServer.call(__MODULE__, {:query_name_direct, name, type_byte}, 10_000)
  rescue
    _ -> {:error, :unavailable}
  catch
    :exit, _ -> {:error, :unavailable}
  end

  # ── Private: Name-based Query (0x01) ────────────────────────────────

  defp do_name_query(nil, _name, _type_byte, _trust_anchors) do
    {:error, :no_socket}
  end

  defp do_name_query(socket, name, type_byte, trust_anchors) do
    host = Config.get(:ns_server_host)
    port = Config.get(:ns_server_port)
    timeout = Config.get(:ns_query_timeout_ms)

    # Build a 0x01 query: <<0x01, name_len::16, name::binary, type_byte::8>>
    name_len = byte_size(name)
    query = <<0x01, name_len::16, name::binary, type_byte::8>>

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

  # ── Private: Pubkey Query Execution (0x05) ─────────────────────────

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

  @type_map %{1 => :key, 2 => :svc, 3 => :relay, 4 => :policy, 5 => :revoke, 6 => :bootstrap, 7 => :operator, 0x10 => :device, 0x11 => :user, 0x12 => :group}

  defp decode_record(data) when is_binary(data) do
    <<type_byte::8, name_len::16, rest::binary>> = data
    <<name::binary-size(name_len), rest2::binary>> = rest
    <<data_len::32, rest3::binary>> = rest2
    <<data_bin::binary-size(data_len), rest4::binary>> = rest3

    <<created_at::unsigned-big-64, ttl::unsigned-big-32, serial::unsigned-big-64, rest5::binary>> =
      rest4

    <<sig_len::16, sig::binary-size(sig_len), pub_len::16, pub::binary-size(pub_len)>> = rest5

    type = Map.get(@type_map, type_byte, :unknown)
    record_data = case ZtlpGateway.Cbor.decode(data_bin) do {:ok, d} -> d; _ -> %{} end

    # Reconstruct the canonical bytes (everything before the signature)
    canonical =
      <<type_byte::8, name_len::16, name::binary, data_len::32, data_bin::binary,
        created_at::unsigned-big-64, ttl::unsigned-big-32, serial::unsigned-big-64>>

    {:ok,
     %{
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

  defp verify_trust(%{signer_public_key: _pub}, trust_anchors)
       when map_size(trust_anchors) == 0 do
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

  defp group_cache_lookup(group_name) do
    case :ets.lookup(@group_cache, group_name) do
      [{^group_name, {record_map, expires_at}}] ->
        if System.system_time(:second) < expires_at do
          {:ok, record_map}
        else
          :ets.delete(@group_cache, group_name)
          :miss
        end

      [] ->
        :miss
    end
  rescue
    ArgumentError -> :miss
  end

  defp user_cache_lookup(user_name) do
    case :ets.lookup(@user_cache, user_name) do
      [{^user_name, {record_map, expires_at}}] ->
        if System.system_time(:second) < expires_at do
          {:ok, record_map}
        else
          :ets.delete(@user_cache, user_name)
          :miss
        end

      [] ->
        :miss
    end
  rescue
    ArgumentError -> :miss
  end
end
