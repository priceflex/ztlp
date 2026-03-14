defmodule ZtlpNs.Server do
  @moduledoc """
  UDP query server for ZTLP-NS with security hardening.

  Listens on a UDP port and responds to namespace queries. This is the
  network-facing interface to the record store.

  ## Security Features

  - **Rate limiting** — Per-IP token bucket via `ZtlpNs.RateLimiter`
  - **Packet size limits** — Max 8KB UDP packets, silent drop for oversized
  - **Registration authentication** — Ed25519 signature verification + zone auth
  - **Name validation** — DNS-compatible name format enforcement
  - **Amplification prevention** — Response size capped to request size for
    unauthenticated queries
  - **Worker pool** — `Task.Supervisor` with bounded concurrency
  - **Audit logging** — Structured logs for all security-relevant events
  - **Revocation checks** — NodeID checked against revocation table on registration

  ## Wire Protocol

  All messages are binary. The first byte is the message type:

  ### Query (client → server)
  ```
  <<0x01, name_len::16, name::binary-size(name_len), type_byte::8>>
  ```

  ### Response: Record Found (server → client)
  ```
  <<0x02, record_wire_format::binary>>
  ```

  ### Response: Not Found (server → client)
  ```
  <<0x03, name_len::16, name::binary-size(name_len), type_byte::8>>
  ```

  ### Response: Revoked (server → client)
  ```
  <<0x04, name_len::16, name::binary-size(name_len)>>
  ```

  ### Response: Invalid Query (server → client)
  ```
  <<0xFF>>
  ```

  ### Registration (client → server) — v2 with pubkey
  ```
  <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data::binary,
    sig_len::16, sig::binary, pubkey_len::16, pubkey::binary>>
  ```

  ## Type Bytes
  - 1 = KEY, 2 = SVC, 3 = RELAY, 4 = POLICY, 5 = REVOKE, 6 = BOOTSTRAP, 7 = OPERATOR
  """

  use GenServer

  alias ZtlpNs.{Crypto, EndpointStore, Enrollment, NameValidator, Query, Record, RegistrationAuth, Store, StructuredLog}

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(_args) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @doc "Get the port this server is listening on (useful when port is 0)."
  @spec port() :: non_neg_integer()
  def port do
    GenServer.call(__MODULE__, :get_port)
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(:ok) do
    # Persist or load the registration signing key on startup
    ensure_registration_key()

    # Read port at runtime (not compile time) so config changes take effect
    listen_port = ZtlpNs.Config.port()

    # Open UDP socket in binary mode with active message delivery.
    {:ok, socket} = :gen_udp.open(listen_port, [:binary, {:active, true}])

    # Get the actual port (important when configured port is 0)
    {:ok, actual_port} = :inet.port(socket)

    {:ok, %{socket: socket, port: actual_port}}
  end

  @impl true
  def handle_call(:get_port, _from, state) do
    {:reply, state.port, state}
  end

  @impl true
  def handle_info({:udp, _socket, ip, port, data}, state) do
    max_packet = ZtlpNs.Config.max_packet_size()

    cond do
      # Packet size limit — silent drop for oversized packets
      byte_size(data) > max_packet ->
        StructuredLog.warn(:oversized_packet,
          source_ip: format_ip(ip),
          packet_size: byte_size(data),
          max_size: max_packet
        )

      true ->
        # Rate limit check
        case ZtlpNs.RateLimiter.check(ip) do
          :ok ->
            # Dispatch to worker pool for concurrent processing
            socket = state.socket
            request_size = byte_size(data)

            worker_fn = fn ->
              reply = process_query(data, {ip, port, socket})
              # Amplification prevention: for unauthenticated name queries (0x01),
              # cap response size to request size. Pubkey queries (0x05) are
              # exempt — they require knowledge of a valid 32-byte key and are
              # not viable amplification vectors.
              reply = maybe_truncate_reply(data, reply, request_size)
              :gen_udp.send(socket, ip, port, reply)
            end

            # Use Task.Supervisor if started, otherwise run inline.
            # This handles test environments where the full supervision
            # tree isn't started (e.g., relay/gateway integration tests).
            case Process.whereis(ZtlpNs.QuerySupervisor) do
              nil -> worker_fn.()
              _pid -> Task.Supervisor.start_child(ZtlpNs.QuerySupervisor, worker_fn)
            end

          :rate_limited ->
            # Silent drop — don't send error response (would aid enumeration)
            StructuredLog.debug(:rate_limited, source_ip: format_ip(ip))
        end
    end

    {:noreply, state}
  end

  # ── Query Processing ───────────────────────────────────────────────

  # Standard query (0x01) — look up a record by name and type
  # Trailing bytes after the query are ignored (allows client padding for
  # amplification prevention compliance).
  defp process_query(<<0x01, name_len::16, name::binary-size(name_len), type_byte::8, _rest::binary>>, _source) do
    type =
      try do
        Record.byte_to_type(type_byte)
      rescue
        _ -> :unknown
      end

    if type == :unknown do
      <<0xFF>>
    else
      case Query.lookup(name, type) do
        {:ok, record} ->
          record_bin = Record.encode(record)
          <<0x02, record_bin::binary>>

        :not_found ->
          <<0x03, name_len::16, name::binary, type_byte::8>>

        {:error, :revoked} ->
          <<0x04, name_len::16, name::binary>>

        {:error, _reason} ->
          <<0x03, name_len::16, name::binary, type_byte::8>>
      end
    end
  end

  # Query by public key (0x05) — uses pubkey index for O(1) lookup
  # Trailing bytes after the query are ignored (client padding).
  defp process_query(<<0x05, pk_hex_len::16, pk_hex::binary-size(pk_hex_len), _rest::binary>>, _source) do
    pk_hex_lower = String.downcase(pk_hex)

    # Use the pubkey index for O(1) lookup instead of O(n) scan
    case Store.lookup_by_pubkey(pk_hex_lower) do
      {:ok, record} ->
        if Record.verify(record) do
          record_bin = Record.encode(record)
          <<0x02, record_bin::binary>>
        else
          <<0x03, pk_hex_len::16, pk_hex::binary, 0x00::8>>
        end

      :not_found ->
        # Fallback: scan the store (handles records inserted before index existed)
        fallback_pubkey_scan(pk_hex_lower, pk_hex_len, pk_hex)

      {:error, :revoked} ->
        # Look up the name from the index to include in response
        case :mnesia.dirty_read(:ztlp_ns_pubkey_index, pk_hex_lower) do
          [{_, _, name}] ->
            name_len = byte_size(name)
            <<0x04, name_len::16, name::binary>>

          [] ->
            <<0x04, pk_hex_len::16, pk_hex::binary>>
        end
    end
  end

  # PEER_ENDPOINTS query (0x0A) — return known endpoints for a NodeID
  #
  # Wire format (request):
  #   <<0x0A, requester_node_id::binary-16, target_node_id::binary-16,
  #     reported_count::8, [<<addr_family::8, addr::binary, port::16>>]*>>
  #
  # Wire format (response):
  #   <<0x0A, endpoint_count::8, [<<addr_family::8, addr::binary-4or16, port::16>>]*>>
  #
  # Side effect: records requester's reported endpoints + learned (source) endpoint,
  # and sends PUNCH_NOTIFY to the target node if we know their address.
  defp process_query(<<0x0A, requester_node_id::binary-size(16),
                       target_node_id::binary-size(16), rest::binary>>, source) do
    # Track the requester's source address (learned endpoint)
    maybe_track_learned(requester_node_id, source)

    # Parse reported endpoints from the request
    parse_and_track_reported(requester_node_id, rest)

    # Look up target's known endpoints
    endpoints = EndpointStore.get_endpoints(target_node_id)

    # Send PUNCH_NOTIFY to target if we know where they are
    maybe_send_punch_notify(target_node_id, requester_node_id, source)

    # Encode response
    encode_peer_endpoints_response(endpoints)
  end

  # PUNCH_REPORT (0x0C) — client reports its own endpoints (for refreshing)
  #
  # Wire format:
  #   <<0x0C, node_id::binary-16, reported_count::8,
  #     [<<addr_family::8, addr::binary, port::16>>]*>>
  defp process_query(<<0x0C, node_id::binary-size(16), rest::binary>>, source) do
    maybe_track_learned(node_id, source)
    parse_and_track_reported(node_id, rest)
    <<0x06>>  # ACK
  end

  # Registration v2 (0x09) with pubkey — verify signature + zone auth
  defp process_query(
         <<0x09, name_len::16, name::binary-size(name_len), type_byte::8, data_len::16,
           data_bin::binary-size(data_len), sig_len::16, sig::binary-size(sig_len),
           pubkey_len::16, pubkey::binary-size(pubkey_len)>>,
         source
       ) do
    # Track the registrant's source address
    maybe_track_learned_from_registration(name, source)
    type =
      try do
        Record.byte_to_type(type_byte)
      rescue
        _ -> :unknown
      end

    if type == :unknown do
      StructuredLog.warn(:registration_rejected,
        name: name, reason: :unknown_type)
      <<0xFF>>
    else
      handle_authenticated_registration(name, type, type_byte, data_bin, data_len, sig, pubkey)
    end
  end

  # Registration v1 (0x09) without pubkey — legacy format
  # Accepted in dev/demo mode (require_registration_auth=false),
  # rejected in production (default).
  defp process_query(
         <<0x09, name_len::16, name::binary-size(name_len), type_byte::8, data_len::16,
           data_bin::binary-size(data_len), sig_len::16, _sig::binary-size(sig_len)>>,
         _source
       ) do
    if ZtlpNs.Config.require_registration_auth?() do
      StructuredLog.warn(:registration_rejected,
        name: name, reason: :missing_pubkey)
      <<0xFF>>
    else
      # Dev/demo mode: accept unsigned registrations
      type =
        try do
          Record.byte_to_type(type_byte)
        rescue
          _ -> :unknown
        end

      if type == :unknown do
        StructuredLog.warn(:registration_rejected,
          name: name, reason: :unknown_type)
        <<0xFF>>
      else
        handle_unsigned_registration(name, type, data_bin)
      end
    end
  end

  # Enrollment (0x07) — device enrollment with token
  defp process_query(<<0x07, rest::binary>>, _source) do
    Enrollment.process_enroll(rest)
  end

  # Malformed query → invalid response
  defp process_query(_, _source), do: <<0xFF>>

  # ── Authenticated Registration ─────────────────────────────────────

  defp handle_authenticated_registration(name, type, _type_byte, data_bin, _data_len, sig, pubkey) do
    # 1. Validate name format
    suffix = ZtlpNs.Config.name_suffix()

    with :ok <- NameValidator.validate_with_suffix(name, suffix),
         # 2. Decode CBOR data
         {:ok, data} <- decode_data(data_bin),
         # 2b. Validate record type-specific fields
         :ok <- validate_record_data(type, data),
         # 3. Verify Ed25519 signature over canonical form
         canonical <- RegistrationAuth.build_canonical(name, type, data_bin),
         :ok <- RegistrationAuth.verify_signature(canonical, sig, pubkey),
         # 4. Check zone authorization
         :ok <- RegistrationAuth.authorize(pubkey, name, type, data),
         # 5. Check key overwrite protection (DEVICE/USER records)
         :ok <- RegistrationAuth.check_key_overwrite(pubkey, name, type, data),
         # 6. Check NodeID revocation
         :ok <- RegistrationAuth.check_revocation(data) do
      # Build the record and sign with the NS registration key.
      # The registrant's identity was verified above (Ed25519 sig + zone auth).
      # The stored record needs a signature that matches Record.serialize()
      # for the Store's invariant (Record.verify must pass).
      # We store the registrant's pubkey as metadata in the data map.
      server_priv = get_registration_key()

      record = %Record{
        name: name,
        type: type,
        data: Map.put(data, "registered_by", Base.encode16(pubkey, case: :lower)),
        created_at: System.system_time(:second),
        ttl: default_ttl(type),
        serial: System.system_time(:second),
        signature: nil,
        signer_public_key: nil
      }

      signed_record = Record.sign(record, server_priv)

      case Store.insert(signed_record) do
        :ok ->
          StructuredLog.info(:registration_accepted,
            name: name,
            type: type,
            signer: Base.encode16(pubkey, case: :lower)
          )

          <<0x06>>

        {:error, :stale_serial} ->
          # Bump serial and retry
          bumped = %{record | serial: record.serial + 1}
          bumped_signed = Record.sign(bumped, server_priv)

          case Store.insert(bumped_signed) do
            :ok ->
              StructuredLog.info(:registration_accepted,
                name: name, type: type,
                signer: Base.encode16(pubkey, case: :lower)
              )
              <<0x06>>

            {:error, reason} ->
              StructuredLog.warn(:registration_rejected,
                name: name, reason: reason)
              <<0xFF>>
          end

        {:error, reason} ->
          StructuredLog.warn(:registration_rejected,
            name: name, reason: reason)
          <<0xFF>>
      end
    else
      {:error, reason} ->
        StructuredLog.warn(:registration_rejected,
          name: name, reason: reason)
        <<0xFF>>
    end
  end

  # ── Unsigned Registration (dev/demo mode) ───────────────────────────

  defp handle_unsigned_registration(name, type, data_bin) do
    suffix = ZtlpNs.Config.name_suffix()

    with :ok <- NameValidator.validate_with_suffix(name, suffix),
         {:ok, data} <- decode_data(data_bin) do
      server_priv = get_registration_key()

      record = %Record{
        name: name,
        type: type,
        data: Map.put(data, "registered_unsigned", true),
        created_at: System.system_time(:second),
        ttl: default_ttl(type),
        serial: System.system_time(:second),
        signature: nil,
        signer_public_key: nil
      }

      signed_record = Record.sign(record, server_priv)

      case Store.insert(signed_record) do
        :ok ->
          StructuredLog.info(:registration_accepted,
            name: name, type: type, mode: :unsigned)
          <<0x06>>

        {:error, :stale_serial} ->
          bumped = %{record | serial: record.serial + 1}
          bumped_signed = Record.sign(bumped, server_priv)

          case Store.insert(bumped_signed) do
            :ok ->
              StructuredLog.info(:registration_accepted,
                name: name, type: type, mode: :unsigned)
              <<0x06>>

            {:error, reason} ->
              StructuredLog.warn(:registration_rejected,
                name: name, reason: reason, mode: :unsigned)
              <<0xFF>>
          end

        {:error, reason} ->
          StructuredLog.warn(:registration_rejected,
            name: name, reason: reason, mode: :unsigned)
          <<0xFF>>
      end
    else
      {:error, reason} ->
        StructuredLog.warn(:registration_rejected,
          name: name, reason: reason, mode: :unsigned)
        <<0xFF>>
    end
  end

  # ── Amplification Prevention ───────────────────────────────────────

  # Amplification prevention for unauthenticated queries.
  #
  # ZTLP-NS is NOT an open resolver — it's a private namespace server that
  # should be firewalled. Unlike DNS, names are long (32+ byte hex NodeIDs),
  # so the typical amplification factor is modest (~5x, vs DNS's 50x+).
  #
  # We apply truncation only when the amplification factor exceeds a
  # reasonable threshold (8x), which catches abuse while allowing normal
  # record responses through. Rate limiting (applied before this) is the
  # primary defense against reflection attacks.
  #
  # 0x05 pubkey queries are fully exempt — they require knowledge of a
  # valid 32-byte key and cannot be used for reflection by random scanners.

  @amplification_threshold 8

  defp maybe_truncate_reply(<<0x01, _::binary>>, reply, request_size) do
    if byte_size(reply) > request_size * @amplification_threshold do
      truncate_reply(reply, request_size * @amplification_threshold)
    else
      reply
    end
  end

  defp maybe_truncate_reply(<<0x05, _::binary>>, reply, _request_size), do: reply
  defp maybe_truncate_reply(_request, reply, _request_size), do: reply

  defp truncate_reply(<<0x02, _rest::binary>> = reply, max_size) do
    # Only truncate "found" (0x02) responses — not-found/revoked/error are already small.
    # Response format: <<0x02, 0x01, truncated_data::binary>>
    # 0x01 in second byte = truncated flag (client should retry over TCP)
    available = max(max_size - 2, 0)
    truncated_data = binary_part(reply, 1, min(available, byte_size(reply) - 1))
    <<0x02, 0x01, truncated_data::binary>>
  end

  defp truncate_reply(reply, _max_size), do: reply

  # ── Helpers ────────────────────────────────────────────────────────

  # Fallback pubkey scan for records not yet in the index
  defp fallback_pubkey_scan(pk_hex_lower, pk_hex_len, pk_hex) do
    result =
      Store.list()
      |> Enum.find(fn {_name, type, record} ->
        type == :key and
          (Map.get(record.data, :public_key) == pk_hex_lower or
             Map.get(record.data, "public_key") == pk_hex_lower)
      end)

    case result do
      {name, _type, record} ->
        if Store.revoked?(name) do
          name_len = byte_size(name)
          <<0x04, name_len::16, name::binary>>
        else
          if Record.verify(record) do
            record_bin = Record.encode(record)
            <<0x02, record_bin::binary>>
          else
            <<0x03, pk_hex_len::16, pk_hex::binary, 0x00::8>>
          end
        end

      nil ->
        <<0x03, pk_hex_len::16, pk_hex::binary, 0x00::8>>
    end
  end

  # Validate type-specific record data fields
  defp validate_record_data(:device, data), do: Record.validate_device(data)
  defp validate_record_data(:user, data), do: Record.validate_user(data)
  defp validate_record_data(:group, data), do: Record.validate_group(data)
  defp validate_record_data(_type, _data), do: :ok

  defp decode_data(data_bin) do
    case ZtlpNs.Cbor.decode(data_bin) do
      {:ok, data} -> {:ok, data}
      {:error, _} -> {:error, :invalid_data}
    end
  end

  # Correct default TTLs per record type (ZTLP spec)
  defp default_ttl(:key), do: 86_400       # 24 hours
  defp default_ttl(:svc), do: 86_400       # 24 hours
  defp default_ttl(:relay), do: 3_600      # 1 hour
  defp default_ttl(:policy), do: 3_600     # 1 hour
  defp default_ttl(:revoke), do: 0         # Never expires
  defp default_ttl(:bootstrap), do: 86_400 # 24 hours
  defp default_ttl(:device), do: 86_400    # 24 hours
  defp default_ttl(:user), do: 86_400      # 24 hours
  defp default_ttl(:group), do: 86_400     # 24 hours
  defp default_ttl(_), do: 3_600           # Default fallback

  # Persist registration signing key on startup.
  # Loads from file if configured, generates and saves if not found.
  defp ensure_registration_key do
    case Application.get_env(:ztlp_ns, :registration_private_key) do
      nil ->
        case ZtlpNs.Config.identity_key_file() do
          nil ->
            # No file configured — generate ephemeral key
            {_pub, priv} = ZtlpNs.Crypto.generate_keypair()
            Application.put_env(:ztlp_ns, :registration_private_key, priv)

          path ->
            case ZtlpNs.ComponentAuth.load_identity_from_file(path) do
              {:ok, {_pub, priv}} ->
                Application.put_env(:ztlp_ns, :registration_private_key, priv)

              {:error, :not_found} ->
                # Generate and persist
                keypair = {_pub, priv} = ZtlpNs.Crypto.generate_keypair()
                ZtlpNs.ComponentAuth.save_identity_to_file(path, keypair)
                Application.put_env(:ztlp_ns, :registration_private_key, priv)

              {:error, _reason} ->
                {_pub, priv} = ZtlpNs.Crypto.generate_keypair()
                Application.put_env(:ztlp_ns, :registration_private_key, priv)
            end
        end

      _priv ->
        :ok
    end
  end

  defp get_registration_key do
    case Application.get_env(:ztlp_ns, :registration_private_key) do
      nil ->
        {_pub, priv} = Crypto.generate_keypair()
        Application.put_env(:ztlp_ns, :registration_private_key, priv)
        priv

      priv ->
        priv
    end
  end

  defp format_ip(ip) when is_tuple(ip), do: :inet.ntoa(ip) |> to_string()
  defp format_ip(ip), do: inspect(ip)

  # ── Endpoint Tracking Helpers ──────────────────────────────────────

  # Track the observed source address (learned endpoint) if EndpointStore is running
  defp maybe_track_learned(node_id, {ip, port, _socket}) do
    if Process.whereis(ZtlpNs.EndpointStore) do
      EndpointStore.record_endpoint(node_id, ip, port, :learned)
    end
  end

  defp maybe_track_learned(_node_id, nil), do: :ok

  # Track source address during registration (extract NodeID from the record name)
  defp maybe_track_learned_from_registration(_name, nil), do: :ok
  defp maybe_track_learned_from_registration(_name, _source), do: :ok

  # Parse reported endpoints from a PEER_ENDPOINTS or PUNCH_REPORT request
  # and store them in the EndpointStore.
  #
  # Wire format for reported addrs:
  #   <<count::8, [<<family::8, addr::binary-4or16, port::16>>]*>>
  defp parse_and_track_reported(node_id, <<count::8, rest::binary>>) do
    parse_reported_addrs(node_id, rest, count)
  end

  defp parse_and_track_reported(_node_id, _rest), do: :ok

  defp parse_reported_addrs(_node_id, _data, 0), do: :ok

  # IPv4
  defp parse_reported_addrs(node_id, <<4::8, a::8, b::8, c::8, d::8, port::16, rest::binary>>, count) when count > 0 do
    if Process.whereis(ZtlpNs.EndpointStore) do
      EndpointStore.record_endpoint(node_id, {a, b, c, d}, port, :reported)
    end

    parse_reported_addrs(node_id, rest, count - 1)
  end

  # IPv6
  defp parse_reported_addrs(node_id, <<6::8, addr::binary-size(16), port::16, rest::binary>>, count) when count > 0 do
    if Process.whereis(ZtlpNs.EndpointStore) do
      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = addr
      EndpointStore.record_endpoint(node_id, {a, b, c, d, e, f, g, h}, port, :reported)
    end

    parse_reported_addrs(node_id, rest, count - 1)
  end

  defp parse_reported_addrs(_node_id, _data, _count), do: :ok

  # Send PUNCH_NOTIFY (0x0B) to the target node with the requester's endpoints.
  #
  # This tells the target: "hey, this peer wants to connect to you,
  # here are their endpoints — start punching!"
  #
  # Wire format:
  #   <<0x0B, requester_node_id::binary-16, endpoint_count::8,
  #     [<<addr_family::8, addr::binary-4or16, port::16>>]*>>
  defp maybe_send_punch_notify(target_node_id, requester_node_id, {_requester_ip, _requester_port, socket}) do
    # Find target's most recent learned address to send the notification to
    case EndpointStore.get_endpoints(target_node_id) do
      [] ->
        :ok

      endpoints ->
        # Prefer learned addresses over reported for sending notifications
        target_addr = pick_best_notify_addr(endpoints)

        if target_addr do
          # Get requester's endpoints to include in the notification
          requester_endpoints = EndpointStore.get_endpoints(requester_node_id)
          pkt = encode_punch_notify(requester_node_id, requester_endpoints)

          {ip, port} = target_addr
          :gen_udp.send(socket, ip, port, pkt)
        end
    end
  end

  defp maybe_send_punch_notify(_target, _requester, nil), do: :ok

  defp pick_best_notify_addr(endpoints) do
    # Prefer learned addresses (more likely to reach through NAT)
    learned = Enum.filter(endpoints, fn {type, _ip, _port} -> type == :learned end)

    case learned do
      [{_type, ip, port} | _] -> {ip, port}
      [] ->
        case endpoints do
          [{_type, ip, port} | _] -> {ip, port}
          [] -> nil
        end
    end
  end

  # Encode PUNCH_NOTIFY packet
  defp encode_punch_notify(requester_node_id, endpoints) do
    # Deduplicate by {ip, port}
    unique = endpoints
    |> Enum.map(fn {_type, ip, port} -> {ip, port} end)
    |> Enum.uniq()

    count = min(length(unique), 255)
    addrs_bin = encode_addr_list(Enum.take(unique, count))

    <<0x0B, requester_node_id::binary-size(16), count::8, addrs_bin::binary>>
  end

  # Encode PEER_ENDPOINTS response
  defp encode_peer_endpoints_response(endpoints) do
    unique = endpoints
    |> Enum.map(fn {_type, ip, port} -> {ip, port} end)
    |> Enum.uniq()

    count = min(length(unique), 255)
    addrs_bin = encode_addr_list(Enum.take(unique, count))

    <<0x0A, count::8, addrs_bin::binary>>
  end

  defp encode_addr_list(addrs) do
    Enum.reduce(addrs, <<>>, fn {ip, port}, acc ->
      acc <> encode_addr(ip, port)
    end)
  end

  defp encode_addr({a, b, c, d}, port) do
    <<4::8, a::8, b::8, c::8, d::8, port::16>>
  end

  defp encode_addr({a, b, c, d, e, f, g, h}, port) do
    <<6::8, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, port::16>>
  end
end
