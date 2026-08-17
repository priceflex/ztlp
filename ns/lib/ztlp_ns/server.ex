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
  require Logger

  alias ZtlpNs.{Audit, Crypto, EndpointAuth, EndpointStore, Enrollment, NameValidator, Query, Record, RegistrationAuth, RegistrationError, Store, StructuredLog}

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
              # A malformed/adversarial UDP packet must never crash the NS
              # Server. process_query/2 runs inline (when the QuerySupervisor
              # isn't started) or in a worker Task — either way an unhandled
              # exception here would either kill the Task or, worse, crash the
              # Server process itself (inline path). Wrap the whole handler in
              # a rescue so any bad packet is dropped silently (consistent with
              # the rate-limit / oversized-packet silent-drop policy).
              try do
                reply = process_query(data, {ip, port, socket})
                # Amplification prevention: for unauthenticated name queries
                # (0x01), cap response size to request size. Pubkey queries
                # (0x05) are exempt — they require knowledge of a valid
                # 32-byte key and are not viable amplification vectors.
                reply = maybe_truncate_reply(data, reply, request_size)
                :gen_udp.send(socket, ip, port, reply)
              rescue
                e ->
                  StructuredLog.debug(
                    :dropped_malformed_packet,
                    source_ip: format_ip(ip),
                    packet_size: byte_size(data),
                    error: Exception.message(e)
                  )
              end
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
  # Wire format (request, v2 — signed, see EndpointAuth / irt-rwzo):
  #   <<0x0A, requester_node_id::binary-16, target_node_id::binary-16,
  #     timestamp::64, sig::binary-64, pubkey::binary-32,
  #     reported_count::8, [<<addr_family::8, addr::binary, port::16>>]*>>
  #
  # Wire format (request, v1 — legacy unsigned, no endpoint tracking):
  #   <<0x0A, requester_node_id::binary-16, target_node_id::binary-16,
  #     reported_count::8, [<<addr_family::8, addr::binary, port::16>>]*>>
  #
  # Wire format (response):
  #   <<0x0A, endpoint_count::8, [<<addr_family::8, addr::binary-4or16, port::16>>]*>>
  #
  # Side effect: records requester's reported endpoints + learned (source) endpoint,
  # and sends PUNCH_NOTIFY to the target node if we know their address.
  #
  # [CWE-284 irt-rwzo] The v2 clause is tried first. It verifies an
  # Ed25519 signature over requester_node_id||timestamp before ANY
  # EndpointStore write happens, per ZtlpNs.EndpointAuth's
  # strict-if-registered / TOFU-otherwise policy (or unconditionally
  # when require_endpoint_auth? is disabled for dev/demo). A v1
  # (unsigned) request still gets a normal PEER_ENDPOINTS *response* —
  # reading endpoints was never the vulnerability, you already need to
  # know the target's node_id to ask — it just never gets tracked.
  defp process_query(<<0x0A, requester_node_id::binary-size(16),
                       target_node_id::binary-size(16),
                       timestamp::unsigned-big-64, sig::binary-size(64),
                       pubkey::binary-size(32), rest::binary>>, source) do
    case authorize_endpoint_claim(requester_node_id, timestamp, sig, pubkey) do
      :ok ->
        maybe_track_learned(requester_node_id, source)
        parse_and_track_reported(requester_node_id, rest)

      {:error, reason} ->
        StructuredLog.warn(:endpoint_claim_rejected,
          node_id: Base.encode16(requester_node_id, case: :lower),
          reason: reason
        )
    end

    endpoints = EndpointStore.get_endpoints(target_node_id)
    maybe_send_punch_notify(target_node_id, requester_node_id, source)
    encode_peer_endpoints_response(response_endpoints(endpoints))
  end

  defp process_query(<<0x0A, requester_node_id::binary-size(16),
                       target_node_id::binary-size(16), rest::binary>>, source) do
    # v1 (unsigned) request: answer normally, but do NOT track — see
    # module doc above and ZtlpNs.EndpointAuth for rationale. Silently
    # discard any reported-endpoints payload in `rest` (v1 senders may
    # still include it; a legacy build predates the auth requirement,
    # it isn't malicious, but we don't trust unauthenticated writes).
    _ = rest

    if ZtlpNs.Config.require_endpoint_auth?() do
      StructuredLog.warn(:endpoint_claim_rejected,
        node_id: Base.encode16(requester_node_id, case: :lower),
        reason: :unsigned_request
      )
    else
      maybe_track_learned(requester_node_id, source)
      parse_and_track_reported(requester_node_id, rest)
    end

    endpoints = EndpointStore.get_endpoints(target_node_id)
    maybe_send_punch_notify(target_node_id, requester_node_id, source)
    encode_peer_endpoints_response(response_endpoints(endpoints))
  end

  # PUNCH_REPORT (0x0C) — client reports its own endpoints (for refreshing)
  #
  # Wire format (v2 — signed, see EndpointAuth / irt-rwzo):
  #   <<0x0C, node_id::binary-16, timestamp::64, sig::binary-64,
  #     pubkey::binary-32, reported_count::8,
  #     [<<addr_family::8, addr::binary, port::16>>]*>>
  #
  # Wire format (v1 — legacy unsigned):
  #   <<0x0C, node_id::binary-16, reported_count::8,
  #     [<<addr_family::8, addr::binary, port::16>>]*>>
  #
  # [CWE-284 irt-rwzo] Unlike PEER_ENDPOINTS, PUNCH_REPORT has no useful
  # "answer without tracking" fallback — the entire point of this
  # message is the write. A v1 (unsigned) or auth-failed v2 request
  # still gets ACKed (backward-compat / don't leak auth-failure via
  # protocol-level silence an attacker could probe), but the endpoint
  # write is skipped.
  defp process_query(<<0x0C, node_id::binary-size(16), timestamp::unsigned-big-64,
                       sig::binary-size(64), pubkey::binary-size(32), rest::binary>>, source) do
    case authorize_endpoint_claim(node_id, timestamp, sig, pubkey) do
      :ok ->
        maybe_track_learned(node_id, source)
        parse_and_track_reported(node_id, rest)

      {:error, reason} ->
        StructuredLog.warn(:endpoint_claim_rejected,
          node_id: Base.encode16(node_id, case: :lower),
          reason: reason
        )
    end

    <<0x06>>  # ACK
  end

  defp process_query(<<0x0C, node_id::binary-size(16), rest::binary>>, source) do
    if ZtlpNs.Config.require_endpoint_auth?() do
      StructuredLog.warn(:endpoint_claim_rejected,
        node_id: Base.encode16(node_id, case: :lower),
        reason: :unsigned_request
      )
    else
      maybe_track_learned(node_id, source)
      parse_and_track_reported(node_id, rest)
    end

    <<0x06>>  # ACK
  end

  # LIST_RELAYS query (0x0D) — return registered relays, optionally scoped by zone.
  #
  # Wire format (request):
  #   <<0x0D, requester_node_id::binary-16, zone_len::8, zone::binary-zone_len>>
  #   - zone_len may be 0 to request relays across all zones (NS-policy capped)
  #
  # Wire format (response):
  #   <<0x0D, count::8, [<<addr_family::8, addr::binary-4or16, port::16,
  #                          region_len::8, region::binary-region_len>>]*>>
  #   - count is u8, max 32 relays per response
  #
  # R1: returns an empty list — the relay registration source will be wired in
  # R2 once the bench validates the wire format end-to-end.
  defp process_query(<<0x0D, _requester_node_id::binary-size(16), zone_len::8,
                       _zone::binary-size(zone_len)>>, _source) do
    relays = []
    encode_list_relays_response(relays)
  end

  # Admin query (0x13) — REMOVED in v0.35.1
  #
  # The legacy UDP admin path (list records / dump audit log) was
  # unauthenticated and publicly reachable on the same UDP socket that
  # serves name resolution (0.0.0.0:23096). It allowed anyone with
  # line-of-sight to the NS port to dump every record in the Store and
  # stream the audit log via 5–13 byte packets. PR #98 (NS admin tenant
  # isolation) added a gated HTTP replacement at /admin/records on port
  # 9103 with per-tenant HMAC + CIDR + zone-glob scoping, but did not
  # touch this UDP path. v0.35.1 removes the UDP path entirely.
  #
  # Migration: callers must move to the HTTP admin API.
  # - ztlp-cli admin {devices,ls,groups,audit} retargeted in proto/
  # - Bootstrap reconciliation uses ns_admin_client.rb (HTTP)
  #
  # 0x13 packets now fall through to the unknown-opcode catchall below
  # and receive <<0xff>>. The audit module records the dropped attempts.
  #
  # Refs: docs/operations/ns-admin-tenant-isolation.md
  # Refs: ns/test/ztlp_ns/admin_test.exs (regression pins)

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
      RegistrationError.encode(:unknown_type)
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
      RegistrationError.encode(:missing_pubkey)
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
        RegistrationError.encode(:unknown_type)
      else
        handle_unsigned_registration(name, type, data_bin)
      end
    end
  end

  # Enrollment (0x07) — device enrollment with token
  defp process_query(<<0x07, rest::binary>>, _source) do
    Enrollment.process_enroll(rest)
  end

  # ── Certificate Authority Queries (0x14) ───────────────────────────

  # 0x14 0x01 — Get CA root certificate (DER)
  # Request:  <<0x14, 0x01>>
  # Response: <<0x14, 0x01, 0x00, cert_len::32, cert_der::binary>>  (success)
  #           <<0x14, 0x01, 0x01>>                                   (CA not initialized)
  defp process_query(<<0x14, 0x01>>, _source) do
    case ZtlpNs.CertAuthority.get_root_cert_der() do
      {:ok, cert_der} ->
        Logger.info("[Server] CA root cert exported (#{byte_size(cert_der)} bytes)")
        <<0x14, 0x01, 0x00, byte_size(cert_der)::unsigned-big-32, cert_der::binary>>

      {:error, _} ->
        <<0x14, 0x01, 0x01>>
    end
  end

  # 0x14 0x02 — Get CA chain (intermediate + root) in PEM
  # Request:  <<0x14, 0x02>>
  # Response: <<0x14, 0x02, 0x00, chain_len::32, chain_pem::binary>>
  #           <<0x14, 0x02, 0x01>>
  defp process_query(<<0x14, 0x02>>, _source) do
    case ZtlpNs.CertAuthority.get_chain_pem() do
      {:ok, chain_pem} ->
        <<0x14, 0x02, 0x00, byte_size(chain_pem)::unsigned-big-32, chain_pem::binary>>

      {:error, _} ->
        <<0x14, 0x02, 0x01>>
    end
  end

  # 0x14 0x03 — Issue server certificate for a service hostname
  #
  # [SAST: oql-hvmv fix] This opcode previously took an attacker-supplied
  # hostname straight to CertIssuer.issue_server_cert/2 with ZERO auth —
  # confirmed live: one UDP packet with an arbitrary hostname returned a
  # valid CA-signed cert + private key. Now requires the request to be
  # signed by an Ed25519 key on the gateway's component-auth allowlist,
  # reusing the same ComponentAuth machinery already used for gateway<->NS
  # mutual auth elsewhere (ns/lib/ztlp_ns/component_auth.ex,
  # component_auth_enabled + component_auth_allowed_keys config). The
  # signature covers the hostname bytes directly (single UDP round trip,
  # no separate challenge needed since the caller already holds a
  # long-lived identity key).
  #
  # Request:  <<0x14, 0x03, hostname_len::16, hostname::binary,
  #                          sig_len::16, signature::binary,
  #                          pubkey_len::16, pubkey::binary>>
  # Response: <<0x14, 0x03, 0x00, cert_len::32, cert_pem::binary,
  #                                key_len::32, key_pem::binary,
  #                                chain_len::32, chain_pem::binary>>
  #           <<0x14, 0x03, 0x01>>  (CA not initialized)
  #           <<0x14, 0x03, 0x02>>  (issuance failed)
  #           <<0x14, 0x03, 0x03>>  (unauthorized — bad/missing signature, or key not allowlisted)
  defp process_query(
         <<0x14, 0x03, hostname_len::unsigned-big-16, hostname::binary-size(hostname_len),
           sig_len::unsigned-big-16, signature::binary-size(sig_len),
           pubkey_len::unsigned-big-16, pubkey::binary-size(pubkey_len)>>,
         _source
       ) do
    case verify_cert_issuance_auth(hostname, signature, pubkey) do
      :ok ->
        Logger.info("[Server] Cert issuance request for #{hostname}")

        case ZtlpNs.CertIssuer.issue_server_cert(hostname, san_dns: [hostname], key_type: :rsa2048) do
          {:ok, %{cert_pem: cert_pem, key_pem: key_pem, chain_pem: chain_pem}} ->
            Logger.info("[Server] Cert issued for #{hostname}")
            <<0x14, 0x03, 0x00,
              byte_size(cert_pem)::unsigned-big-32, cert_pem::binary,
              byte_size(key_pem)::unsigned-big-32, key_pem::binary,
              byte_size(chain_pem)::unsigned-big-32, chain_pem::binary>>

          {:error, reason} ->
            Logger.warning("[Server] Cert issuance failed for #{hostname}: #{inspect(reason)}")
            <<0x14, 0x03, 0x02>>
        end

      {:error, reason} ->
        Logger.warning("[Server] Cert issuance REJECTED for #{hostname}: unauthorized (#{inspect(reason)})")
        <<0x14, 0x03, 0x03>>
    end
  end

  # Unsigned/legacy-format cert issuance requests are always unauthorized now.
  defp process_query(<<0x14, 0x03, _rest::binary>>, _source) do
    <<0x14, 0x03, 0x03>>
  end

  # Malformed query → invalid response
  defp process_query(_, _source), do: <<0xFF>>

  # [SAST: oql-hvmv fix] Verify a cert-issuance request signature against
  # the gateway component-auth allowlist. Reuses ZtlpNs.ComponentAuth's
  # Ed25519 verify + allowlist check rather than a bespoke scheme — same
  # trust model already governing gateway<->NS mutual auth.
  defp verify_cert_issuance_auth(hostname, signature, pubkey) do
    cond do
      not ZtlpNs.ComponentAuth.auth_enabled?() ->
        # Component auth not configured for this deployment — cert
        # issuance is refused outright rather than silently allowed,
        # since there's no allowlist to check against. Operators must
        # opt in by configuring component_auth (enabled + allowed_keys)
        # before this opcode will issue anything.
        {:error, :component_auth_not_configured}

      byte_size(pubkey) != 32 ->
        {:error, :invalid_pubkey_length}

      not :crypto.verify(:eddsa, :none, hostname, signature, [pubkey, :ed25519]) ->
        {:error, :invalid_signature}

      pubkey not in ZtlpNs.ComponentAuth.allowed_keys() ->
        {:error, :unauthorized_key}

      true ->
        :ok
    end
  end

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
         :ok <- RegistrationAuth.check_revocation(data),
         # 7. Check name revocation (revoked entities cannot re-register)
         :ok <- RegistrationAuth.check_name_revocation(name),
         # 8. Check rate limiting (max 1 registration per name per hour)
         :ok <- RegistrationAuth.check_rate_limit(name, pubkey) do
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

          Audit.log(:registered, name, type, %{
            signer: Base.encode16(pubkey, case: :lower)
          })

          # If this is a revocation, log revocation events and clean up indexes
          if type == :revoke do
            handle_revocation_side_effects(data, name)
          end

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

              Audit.log(:updated, name, type, %{
                signer: Base.encode16(pubkey, case: :lower),
                note: "serial bumped"
              })

              # If this is a revocation, log revocation events and clean up indexes
              if type == :revoke do
                handle_revocation_side_effects(data, name)
              end

              <<0x06>>

            {:error, reason} ->
              StructuredLog.warn(:registration_rejected,
                name: name, reason: reason)
              RegistrationError.encode(RegistrationError.from_internal(reason))
          end

        {:error, reason} ->
          StructuredLog.warn(:registration_rejected,
            name: name, reason: reason)
          RegistrationError.encode(RegistrationError.from_internal(reason))
      end
    else
      {:error, reason} ->
        StructuredLog.warn(:registration_rejected,
          name: name, reason: reason)
        RegistrationError.encode(RegistrationError.from_internal(reason))
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

          Audit.log(:registered, name, type, %{mode: :unsigned})

          # If this is a revocation, log revocation events and clean up indexes
          if type == :revoke do
            handle_revocation_side_effects(data, name)
          end

          <<0x06>>

        {:error, :stale_serial} ->
          bumped = %{record | serial: record.serial + 1}
          bumped_signed = Record.sign(bumped, server_priv)

          case Store.insert(bumped_signed) do
            :ok ->
              StructuredLog.info(:registration_accepted,
                name: name, type: type, mode: :unsigned)

              Audit.log(:updated, name, type, %{mode: :unsigned, note: "serial bumped"})

              # If this is a revocation, log revocation events and clean up indexes
              if type == :revoke do
                handle_revocation_side_effects(data, name)
              end

              <<0x06>>

            {:error, reason} ->
              StructuredLog.warn(:registration_rejected,
                name: name, reason: reason, mode: :unsigned)
              RegistrationError.encode(RegistrationError.from_internal(reason))
          end

        {:error, reason} ->
          StructuredLog.warn(:registration_rejected,
            name: name, reason: reason, mode: :unsigned)
          RegistrationError.encode(RegistrationError.from_internal(reason))
      end
    else
      {:error, reason} ->
        StructuredLog.warn(:registration_rejected,
          name: name, reason: reason, mode: :unsigned)
        RegistrationError.encode(RegistrationError.from_internal(reason))
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

  # Amplification-truncation threshold is now sourced from
  # ZtlpNs.Config.amplification_threshold/0 (configurable via
  # ZTLP_NS_AMPLIFICATION_THRESHOLD) instead of this compile-time constant.

  defp maybe_truncate_reply(<<0x01, _::binary>>, reply, request_size) do
    threshold = ZtlpNs.Config.amplification_threshold()

    if byte_size(reply) > request_size * threshold do
      truncate_reply(reply, request_size * threshold)
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

  # ── Revocation Side Effects ──────────────────────────────────────────

  # When a revocation is registered, log individual revoked entities
  # and clean up related indexes (remove from device-owner, group membership).
  defp handle_revocation_side_effects(data, revoke_record_name) do
    revoked_ids = Map.get(data, "revoked_ids") || Map.get(data, :revoked_ids) || []
    reason = Map.get(data, "reason") || Map.get(data, :reason) || "unspecified"

    Enum.each(revoked_ids, fn id ->
      Audit.log(:revoked, id, :revoke, %{
        reason: reason,
        revocation_record: revoke_record_name
      })

      # Clean up device-owner index for revoked devices
      cleanup_device_index(id)

      # Clean up group membership index for revoked users
      cleanup_group_index(id)
    end)
  end

  # Remove a revoked device from the device-owner index
  defp cleanup_device_index(device_name) do
    try do
      existing = :mnesia.dirty_match_object({:ztlp_ns_device_index, :_, device_name})
      Enum.each(existing, fn entry -> :mnesia.dirty_delete_object(entry) end)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  # Remove a revoked user from all group membership indexes
  defp cleanup_group_index(user_name) do
    try do
      existing = :mnesia.dirty_match_object({:ztlp_ns_group_index, user_name, :_})
      Enum.each(existing, fn entry -> :mnesia.dirty_delete_object(entry) end)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
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

  # Default TTL per record type. Delegates to ZtlpNs.RecordDefaults so the
  # enrollment path (ZtlpNs.Enrollment.register_device/5) cannot drift from
  # the canonical table — see record_defaults.ex for the v0.33.0 history.
  defp default_ttl(type), do: ZtlpNs.RecordDefaults.default_ttl(type)

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

  # The registration signing key is the Ed25519 keypair NS uses to sign
  # every record it stores (see Record.sign/2 call sites above). Gateways
  # verify these signatures against a configured trust anchor
  # (ZTLP_GATEWAY_TRUST_ANCHORS) before accepting ANY NS record — so this
  # key MUST be stable across restarts, or every gateway's trust anchor
  # goes stale the moment NS restarts and picks a new random key.
  #
  # NOTE: the actual persistence logic lives in ensure_registration_key/0
  # above, called once from init/1 before any registrations can arrive.
  # It already handles the file-based persist/load cycle via
  # ZtlpNs.ComponentAuth + ZtlpNs.Config.identity_key_file/0 — see that
  # function's default-path fix in Config.identity_key_file/0 (defaults to
  # <ca_data_dir>/registration_signing.key instead of nil/ephemeral, so a
  # fresh deployment persists a stable key without any extra env var).
  #
  # This function is just a cache read — by the time any registration
  # handler calls it, ensure_registration_key/0 has already populated
  # Application.env, so the `nil` branch below should never actually run
  # in practice. It's kept only as a defensive fallback.
  defp get_registration_key do
    case Application.get_env(:ztlp_ns, :registration_private_key) do
      nil ->
        Logger.warning(
          "[NS] registration_private_key was not set by ensure_registration_key/0 " <>
            "at startup — generating an ephemeral fallback key. This should not " <>
            "happen in normal operation; check NS startup logs for errors."
        )
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

  # [CWE-284 irt-rwzo] Verify a PEER_ENDPOINTS/PUNCH_REPORT sender's
  # signed claim to own `node_id` before any EndpointStore write.
  # Delegates to ZtlpNs.EndpointAuth (Ed25519 sig check + strict
  # registered-record-match / TOFU-pin ownership policy). When
  # require_endpoint_auth? is disabled (dev/demo), skip verification
  # entirely and trust the claim -- matches require_registration_auth?'s
  # existing escape hatch pattern.
  defp authorize_endpoint_claim(node_id, timestamp, sig, pubkey) do
    if ZtlpNs.Config.require_endpoint_auth?() do
      EndpointAuth.verify_and_bind(node_id, timestamp, sig, pubkey)
    else
      :ok
    end
  end

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

  def pick_best_notify_addr(endpoints) do
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

  # Filter the EndpointStore set down to what we OFFER a requester as
  # standalone dial candidates in a PEER_ENDPOINTS response.
  #
  # == Why :learned must not be offered as a dial candidate (v0.35.2)
  #
  # `:learned` is the UDP SOURCE address NS observed on a control-plane packet
  # (PEER_ENDPOINTS / PUNCH_REPORT) the node sent us. For a node behind NAT
  # that emits those packets from an EPHEMERAL socket (e.g. a relay-routed
  # gateway whose listener binds 0.0.0.0 and whose NS keepalive uses a throwaway
  # 0.0.0.0:0 socket), that source is a transient outbound NAT mapping — NOT an
  # inbound listener. Offered as a dial target it is a phantom: it only ever
  # times out, and worse, it crowds the genuinely reachable candidates (the
  # node's :reported listener address and the relay backstop) out of the
  # operator's bounded parallel-dial race. This is the KELLYMANCINO-PC failure
  # (2026-06-15): NS served [reported LAN, learned srflx]; both dead; connect
  # only recovered via the client's post-race relay fallback.
  #
  # The fix: prefer :reported (addresses the node DELIBERATELY advertised as
  # reachable). Only fall back to :learned when there is NO reported endpoint —
  # i.e. a symmetric-NAT peer for which the observed source is the only hint we
  # have, and coordinated simultaneous-open (PUNCH_NOTIFY, which still sees the
  # full set) is the intended path. This keeps hole punching working for the
  # cases that need srflx while ending the phantom-candidate poisoning for
  # relay-routed gateways.
  #
  # Gated by ZtlpNs.Config.peer_endpoints_prefer_reported?/0 (default true) so
  # the legacy "return everything" behavior can be restored at runtime if a
  # deployment depends on it.
  @spec response_endpoints([{EndpointStore.endpoint_type(), :inet.ip_address(), :inet.port_number()}]) ::
          [{EndpointStore.endpoint_type(), :inet.ip_address(), :inet.port_number()}]
  def response_endpoints(endpoints) do
    if ZtlpNs.Config.peer_endpoints_prefer_reported?() do
      reported = Enum.filter(endpoints, fn {type, _ip, _port} -> type == :reported end)

      case reported do
        [] -> endpoints
        _ -> reported
      end
    else
      endpoints
    end
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

  # Encode LIST_RELAYS (0x0D) response.
  #
  # Accepts a list of relay maps shaped like:
  #   %{addr: {ip_tuple, port}, region: binary}
  # where ip_tuple is either a 4-tuple (IPv4) or 8-tuple (IPv6).
  #
  # Caps the list at 32 entries (MAX_LIST_RELAYS_COUNT) per response.
  defp encode_list_relays_response(relays) when is_list(relays) do
    capped = Enum.take(relays, 32)
    count = length(capped)

    body =
      Enum.reduce(capped, <<>>, fn %{addr: {ip, port}, region: region}, acc ->
        addr_bin = encode_addr(ip, port)
        region_bin = if is_binary(region), do: region, else: to_string(region)
        region_len = byte_size(region_bin)
        acc <> addr_bin <> <<region_len::8, region_bin::binary>>
      end)

    <<0x0D, count::8, body::binary>>
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
