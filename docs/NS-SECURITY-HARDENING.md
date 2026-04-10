# ZTLP-NS Security Hardening — Implementation Plan

**Date:** 2026-03-13
**Status:** ✅ Complete (v0.6.0, commit `5ef8954`)
**Scope:** Fix all security gaps in `ns/lib/ztlp_ns/server.ex` and related modules

> All security modules (RateLimiter, ComponentAuth, TlsConfig, ZoneAuthority,
> TrustAnchor) already exist. The primary task is **wiring them into the
> server's query handler** and adding missing validation logic.

---

## Table of Contents

1. [Critical Fixes](#1-critical-fixes)
2. [High Priority Fixes](#2-high-priority-fixes)
3. [Medium Priority Fixes](#3-medium-priority-fixes)
4. [Low Priority Fixes](#4-low-priority-fixes)
5. [Certificate Renewal Implementation](#5-certificate-renewal-implementation)
6. [Testing Checklist](#6-testing-checklist)
7. [Files to Modify](#7-files-to-modify)

---

## 1. Critical Fixes

### 1.1 🔴 Wire Rate Limiter into Server (~30 min)

**Problem:** `ZtlpNs.RateLimiter` exists (200 lines, ETS token bucket, cleanup, metrics)
but `Server.handle_info/2` never calls `RateLimiter.check(ip)`. Any host can send
unlimited queries.

**Fix:** Add rate limit check at the top of the UDP handler before any processing.

**File:** `ns/lib/ztlp_ns/server.ex`

```elixir
# In handle_info({:udp, ...}):
@impl true
def handle_info({:udp, _socket, ip, port, data}, state) do
  case ZtlpNs.RateLimiter.check(ip) do
    :ok ->
      reply = process_query(data)
      :gen_udp.send(state.socket, ip, port, reply)

    :rate_limited ->
      # Silent drop — don't send error response (would aid enumeration)
      :ok
  end
  {:noreply, state}
end
```

**Tests to add:**
- Query succeeds under rate limit
- Query rejected when bucket exhausted
- Rate limit resets after cooldown
- Metrics increment correctly

---

### 1.2 🔴 Registration Authentication — Verify Signatures & Zone Auth (~2 hours)

**Problem:** The registration handler (0x09) has THREE critical issues:
1. **Discards the incoming signature** — pattern matches `_sig`, never verifies it
2. **Re-signs with server's auto-generated key** — anyone can register anything
3. **No zone authorization** — any name in any zone accepted

**Current broken code:**
```elixir
# server.ex line ~173 — signature is IGNORED
defp process_query(
       <<0x09, name_len::16, name::binary-size(name_len), type_byte::8, data_len::16,
         data_bin::binary-size(data_len), sig_len::16, _sig::binary-size(sig_len)>>
       ) do
  # ... creates a new record, signs it with server key, inserts it
```

**Fix — three layers of validation:**

```elixir
defp process_query(
       <<0x09, name_len::16, name::binary-size(name_len), type_byte::8, data_len::16,
         data_bin::binary-size(data_len), sig_len::16, sig::binary-size(sig_len),
         pubkey_len::16, pubkey::binary-size(pubkey_len)>>
     ) do
  # 1. Parse type
  type = Record.byte_to_type(type_byte)

  # 2. Decode CBOR data
  {:ok, data} = ZtlpNs.Cbor.decode(data_bin)

  # 3. Validate name format
  :ok = validate_name(name)

  # 4. Verify the signature against the provided public key
  #    (prove the registrant holds the private key)
  canonical = Record.canonical_form(name, type, data)
  true = :crypto.verify(:eddsa, :none, canonical, sig, [pubkey, :ed25519])

  # 5. Zone authorization — verify the signer's pubkey is authorized
  #    for this zone (either the zone authority key or a delegated key)
  zone = extract_zone(name)
  :ok = authorize_for_zone(pubkey, zone)

  # 6. Build and store the record (keeping the original signature)
  record = %Record{
    name: name,
    type: type,
    data: data,
    created_at: System.system_time(:second),
    ttl: default_ttl(type),
    serial: System.system_time(:second),
    signature: sig,
    signer_public_key: pubkey
  }

  case Store.insert(record) do
    :ok -> <<0x06>>
    {:error, _} -> <<0xFF>>
  end
end
```

**Zone authorization logic:**
```elixir
defp authorize_for_zone(pubkey, zone_name) do
  # Option 1: pubkey IS the zone authority key
  case ZoneAuthority.get(zone_name) do
    %{public_key: ^pubkey} -> :ok
    _ ->
      # Option 2: pubkey is a delegated key (signed by zone authority)
      case Query.lookup_verified(zone_name, :key) do
        {:ok, delegation} when delegation.data.public_key == pubkey -> :ok
        _ ->
          # Option 3: self-registration (node registering its own KEY record)
          #   Allowed if the pubkey matches the record's public_key field
          #   AND the name was assigned during enrollment
          :ok = verify_self_registration(pubkey, zone_name)
      end
  end
end
```

**Self-registration rule:** A node CAN register/update its own KEY and SVC
records (this is how `ztlp listen` and `ztlp connect` work). The validation is:
- The registering pubkey must match the `public_key` field in the record data
- The name must already exist (initial record created during enrollment)
  OR the zone has open registration enabled (for dev/test)

**Tests to add:**
- Registration with valid zone authority signature → accepted
- Registration with wrong zone key → rejected
- Registration with forged signature → rejected
- Registration with unsigned data → rejected
- Self-registration (node updating own KEY) → accepted
- Self-registration for someone else's name → rejected
- Zone authority can register any name in zone → accepted
- Cross-zone registration → rejected

---

### 1.3 🔴 Wire Component Auth for Registrations (~1 hour)

**Problem:** `ComponentAuth` (Ed25519 challenge-response, nonce replay protection)
exists but is never used. The server treats all UDP clients identically.

**Fix:** Add an authentication layer for write operations (registrations).
Read-only queries (0x01, 0x05) can remain unauthenticated (they return
signed records that clients verify independently). Write operations (0x09,
0x07 enrollment) require proof of identity.

**Two approaches (choose one):**

**Option A — Inline signature (recommended for UDP):**
Registration messages already carry a signature and public key.
The fix from §1.2 above handles this — verify the signature proves
key possession, then check the key is authorized for the zone.
No separate challenge-response needed for registration.

**Option B — Challenge-response for sensitive operations:**
For admin-level operations (revocation, zone delegation, config changes),
require the Ed25519 challenge-response protocol that ComponentAuth
already implements. This is a TCP-based flow:

```
Admin tool                    NS Server
    │                              │
    │── TCP connect ─────────────► │
    │                              │
    │◄─ CHALLENGE (nonce) ──────── │
    │                              │
    │── RESPONSE (sig + pubkey) ──►│
    │   (sign nonce with admin key)│
    │                              │
    │  Verify sig + check pubkey   │
    │  is in allowed_keys list     │
    │                              │
    │── ADMIN COMMAND ───────────► │
    │  (revoke / delegate / etc)   │
    │                              │
```

**Recommendation:** Use Option A (inline signature) for all UDP operations.
Reserve Option B (challenge-response over TCP) for a future admin API.

---

## 2. High Priority Fixes

### 2.1 🟠 Packet & Record Size Limits (~30 min)

**Problem:** No limits on incoming UDP packet size or record size.
Spec says records MUST NOT exceed 4,096 bytes.

**Fix in `server.ex`:**
```elixir
@max_packet_size 8192  # UDP max practical size
@max_record_size 4096  # Spec §9.6

def handle_info({:udp, _socket, ip, port, data}, state) when byte_size(data) > @max_packet_size do
  # Drop oversized packets silently
  {:noreply, state}
end
```

**Fix in `store.ex`:**
```elixir
def insert(%Record{} = record, opts) do
  wire_size = byte_size(Record.encode(record))
  if wire_size > 4096 do
    {:error, :record_too_large}
  else
    # ... existing logic
  end
end
```

**Tests:**
- Packet >8KB → silently dropped
- Record encoding >4096 bytes → rejected
- Normal-sized records → accepted

---

### 2.2 🟠 Name Validation (~30 min)

**Problem:** Names are arbitrary binary strings. No character set, format,
or length validation.

**Fix — add `validate_name/1`:**
```elixir
@max_name_length 253  # Same as DNS
@name_pattern ~r/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$/

defp validate_name(name) when byte_size(name) > @max_name_length do
  {:error, :name_too_long}
end

defp validate_name(name) do
  if Regex.match?(@name_pattern, name) do
    :ok
  else
    {:error, :invalid_name}
  end
end
```

**Rules:**
- Max 253 bytes (DNS compatible)
- Lowercase alphanumeric + hyphens + dots only
- Labels separated by dots
- No leading/trailing hyphens per label
- Must end with `.ztlp` (configurable zone suffix)

**Tests:**
- Valid names → accepted
- Names with special chars → rejected
- Names >253 bytes → rejected
- Names with null bytes → rejected
- Names not ending in `.ztlp` → rejected (configurable)

---

### 2.3 🟠 Pubkey Lookup Performance — Index (~1 hour)

**Problem:** Public key lookup (0x05) does `Store.list() |> Enum.find(...)` —
O(n) scan of all records. With 100K records, this is a CPU exhaustion vector.

**Fix:** Add a reverse index (pubkey → name) in a separate ETS/Mnesia table.

```elixir
# In store.ex — maintain a pubkey index
@pubkey_index :ztlp_ns_pubkey_index

# On insert of KEY records:
defp index_pubkey(%Record{type: :key, name: name, data: data}) do
  pubkey = Map.get(data, :public_key) || Map.get(data, "public_key")
  if pubkey do
    :mnesia.dirty_write({@pubkey_index, String.downcase(pubkey), name})
  end
end

# On lookup by pubkey:
def lookup_by_pubkey(pubkey_hex) do
  case :mnesia.dirty_read(@pubkey_index, String.downcase(pubkey_hex)) do
    [{_, _, name}] -> lookup(name, :key)
    [] -> :not_found
  end
end
```

**Tests:**
- Pubkey lookup O(1) after indexing
- Index updated on insert
- Index cleaned on record expiry/deletion

---

### 2.4 🟠 Amplification Prevention (~1 hour)

**Problem:** Spec §18.2 requires `response_bytes ≤ request_bytes` for
unauthenticated responses. NS doesn't check this.

**Fix:** For unauthenticated query responses, truncate or pad:

```elixir
defp send_reply(socket, ip, port, request_data, reply) do
  if byte_size(reply) > byte_size(request_data) do
    # Truncate response to request size
    # Include a "truncated" flag so client knows to retry over TCP
    truncated = binary_part(reply, 0, byte_size(request_data) - 1)
    :gen_udp.send(socket, ip, port, <<0x02, 0x01>> <> truncated)  # 0x01 = truncated flag
  else
    :gen_udp.send(socket, ip, port, reply)
  end
end
```

**Alternative:** Require queries to include padding (like the spec says for HELLO).
Clients that want full records must send padded queries.

**Tests:**
- Small query → response truncated to query size
- Large query → full response returned
- Truncated flag set correctly

---

## 3. Medium Priority Fixes

### 3.1 🟡 Worker Pool for Query Processing (~2 hours)

**Problem:** Single GenServer handles all queries sequentially.
One slow query blocks everything.

**Fix:** Use `Task.Supervisor` for concurrent query processing:

```elixir
def handle_info({:udp, _socket, ip, port, data}, state) do
  case ZtlpNs.RateLimiter.check(ip) do
    :ok ->
      Task.Supervisor.start_child(ZtlpNs.QuerySupervisor, fn ->
        reply = process_query(data)
        :gen_udp.send(state.socket, ip, port, reply)
      end)

    :rate_limited ->
      :ok
  end
  {:noreply, state}
end
```

Add to the supervision tree:
```elixir
# In application.ex
{Task.Supervisor, name: ZtlpNs.QuerySupervisor, max_children: 100}
```

The `max_children: 100` cap prevents unbounded task spawning under load.

---

### 3.2 🟡 Persist Registration Signing Key (~30 min)

**Problem:** `get_registration_key()` generates a random key and stores it in
application env. On restart, a new key is generated — all previous records
become unverifiable.

**Fix:** Load from config file, or derive from zone authority key:

```elixir
defp get_registration_key do
  case Application.get_env(:ztlp_ns, :registration_private_key) do
    nil ->
      # Try loading from file
      case ZtlpNs.ComponentAuth.load_identity_from_file(identity_key_path()) do
        {:ok, {_pub, priv}} -> 
          Application.put_env(:ztlp_ns, :registration_private_key, priv)
          priv
        {:error, _} ->
          # Generate and persist
          {pub, priv} = ZtlpNs.Crypto.generate_keypair()
          ZtlpNs.ComponentAuth.save_identity_to_file(identity_key_path(), {pub, priv})
          Application.put_env(:ztlp_ns, :registration_private_key, priv)
          priv
      end
    priv -> priv
  end
end
```

---

### 3.3 🟡 Enrollment Nonce Persistence (~1 hour)

**Problem:** Token usage counts tracked in ETS only. On restart, multi-use
tokens can be replayed.

**Fix:** Move enrollment token tracking to Mnesia (like the main store).

---

### 3.4 🟡 Trust Chain Verification in Server (~1 hour)

**Problem:** Server uses `Query.lookup/2` (simple mode, signature only)
for all responses. Never calls `Query.lookup_verified/2` (full chain).

**Fix:** Add a config option to enable verified lookups. When enabled,
responses include chain verification:

```elixir
defp do_lookup(name, type) do
  if ZtlpNs.Config.verify_trust_chain?() do
    Query.lookup_verified(name, type)
  else
    Query.lookup(name, type)
  end
end
```

Default: `false` for backward compatibility. Recommend `true` for production.

---

### 3.5 🟡 Audit Logging (~30 min)

**Problem:** No logging for security-relevant events in the server.

**Fix:** Use the existing `StructuredLog` module:

```elixir
# After successful registration:
StructuredLog.info("registration_accepted",
  %{name: name, type: type, signer: Base.encode16(pubkey, case: :lower)})

# After failed registration:
StructuredLog.warn("registration_rejected",
  %{name: name, reason: reason, source_ip: :inet.ntoa(ip)})

# After rate limit:
StructuredLog.debug("rate_limited", %{source_ip: :inet.ntoa(ip)})
```

---

## 4. Low Priority Fixes

### 4.1 🟢 Correct Default TTLs Per Record Type

**Problem:** Registration hardcodes `ttl: 3600` for all record types.

**Fix:**
```elixir
defp default_ttl(:key), do: 86_400      # 24 hours
defp default_ttl(:svc), do: 86_400      # 24 hours
defp default_ttl(:relay), do: 3_600     # 1 hour
defp default_ttl(:policy), do: 3_600    # 1 hour
defp default_ttl(:revoke), do: 0        # Never expires
defp default_ttl(:bootstrap), do: 86_400 # 24 hours
defp default_ttl(_), do: 3_600          # Default fallback
```

### 4.2 🟢 Revocation Check by NodeID, Not Just Name

**Problem:** `Store.revoked?` checks name only. A revoked node could
register under a different name.

**Fix:** On registration, also check if the NodeID in the record data
appears in the revocation table:

```elixir
defp check_node_revocation(data) do
  node_id = Map.get(data, "node_id") || Map.get(data, :node_id)
  if node_id && Store.revoked?(node_id) do
    {:error, :revoked}
  else
    :ok
  end
end
```

---

## 5. Certificate Renewal Implementation

This is the **new feature** from `docs/CREDENTIAL-RENEWAL.md`. The spec
additions are already committed (README.md §16.2.1). What remains is
implementation.

### 5.1 Wire Protocol Summary

**RENEW request (0x09 — node → NS):**
```
  Offset  Field
  0       MsgType (0x09)
  1       Version (0x01)
  2       NodeID (16 bytes)
  18      Zone name length (uint16) + zone name
  20+Z    Current cert serial (uint16)
  22+Z    New X25519 pubkey (32 bytes, or copy of current)
  54+Z    Timestamp (uint64, Unix epoch seconds)
  62+Z    Ed25519 signature over bytes [0..62+Z)
```

**RENEW response (0x0A — NS → node):**
```
  Offset  Field
  0       MsgType (0x0A)
  1       Result code (0x00=SUCCESS, 0x01=NOT_ELIGIBLE, 0x02=REVOKED,
          0x03=EXPIRED, 0x04=BAD_SIGNATURE, 0x05=CLOCK_SKEW, 0x06=RATE_LIMITED)
  2       Payload (new signed certificate on SUCCESS, or error data)
```

### 5.2 NS Server Handler

**File:** `ns/lib/ztlp_ns/renewal.ex` (new)

Implementation steps:
1. Parse RENEW request (0x09)
2. Verify timestamp within ±300s of server clock
3. Rate limit: max 3 renewals per hour per NodeID
4. Look up current certificate by NodeID
5. Verify Ed25519 signature over request using current cert's pubkey
6. Check renewal window: at least 1/3 of cert lifetime elapsed
7. Check NodeID not revoked
8. Issue new certificate:
   - Increment serial
   - Fresh `issued_at`, `not_before`, `not_after`
   - Same TTL as original (or zone policy override)
   - New X25519 key if provided, otherwise keep current
9. Sign new cert with zone authority key
10. Update KEY record in store
11. Return 0x0A SUCCESS + new signed cert

**File:** `ns/lib/ztlp_ns/server.ex`

Add handler for 0x09:
```elixir
# Certificate renewal (0x09)
defp process_query(<<0x09, rest::binary>>) do
  ZtlpNs.Renewal.process_renewal(rest)
end
```

### 5.3 Rust Client — `ztlp renew`

**File:** `proto/src/renewal.rs` (new)

Implementation steps:
1. Load current identity from `~/.ztlp/identity.json`
2. Extract current cert serial, NodeID, zone
3. Build RENEW request:
   - Include NodeID, zone, serial, X25519 pubkey, timestamp
   - Sign with Ed25519 private key
4. Send to NS server via UDP
5. Parse RENEW_RESPONSE
6. On SUCCESS: save new certificate to identity file
7. On error: log and retry with backoff

**File:** `proto/src/bin/ztlp-cli.rs`

Add subcommand:
```
ztlp renew --ns-server <addr> --zone <zone> [--rotate-x25519] [--daemon]
```

### 5.4 Rust Client — `ztlp agent` (Daemon Mode)

**File:** `proto/src/agent.rs` (new)

Daemon that runs continuously:
- Certificate renewal (check every hour, renew at 2/3 lifetime)
- NS record refresh (re-register KEY/SVC at 75% TTL with jitter)
- Health metrics (optional Prometheus endpoint)

Config file: `~/.ztlp/agent.toml`

### 5.5 NS Record Auto-Refresh in `ztlp listen`

**File:** `proto/src/bin/ztlp-cli.rs` (modify `listen` subcommand)

After initial NS registration, spawn a background tokio task that
re-registers KEY and SVC records at 75% of TTL with ±10% jitter.

---

## 6. Testing Checklist

### Security Hardening Tests (ns/test/)

```
[x] test/ztlp_ns/rate_limiter_integration_test.exs
    - Queries rate limited at server level
    - Rate limited queries get no response (silent drop)
    - Legitimate queries still work after rate limit expires

[x] test/ztlp_ns/registration_auth_test.exs
    - Valid zone authority signature → accepted
    - Wrong zone key → rejected
    - Forged signature → rejected
    - Unsigned registration → rejected
    - Self-registration (own KEY record) → accepted
    - Cross-zone registration → rejected
    - Revoked NodeID registration → rejected

[x] test/ztlp_ns/packet_limits_test.exs
    - Oversized packet → dropped
    - Record >4096 bytes → rejected
    - Name >253 bytes → rejected
    - Invalid name chars → rejected

[x] test/ztlp_ns/amplification_test.exs
    - Response ≤ request for unauthenticated queries
    - Truncation flag set when response truncated

[x] test/ztlp_ns/pubkey_index_test.exs
    - O(1) pubkey lookup
    - Index maintained on insert/delete

[x] test/ztlp_ns/audit_log_test.exs
    - Registration events logged
    - Rate limit events logged
    - Auth failure events logged
```

### Certificate Renewal Tests

```
[x] test/ztlp_ns/renewal_test.exs
    - Renewal within window → new cert issued
    - Renewal before window → NOT_ELIGIBLE
    - Renewal after expiry → EXPIRED
    - Bad signature → BAD_SIGNATURE
    - Revoked NodeID → REVOKED
    - Clock skew >300s → CLOCK_SKEW with server timestamp
    - Rate limited (>3/hour) → RATE_LIMITED with retry-after
    - Serial incremented on renewal
    - X25519 key rotation during renewal
    - New cert TTL matches original

[x] proto/tests/renewal_test.rs
    - Build and parse RENEW message
    - Build and parse RENEW_RESPONSE
    - Signature verification
    - Interop with Elixir NS server
```

---

## 7. Files to Modify

### Existing files to modify:
| File | Changes |
|------|---------|
| `ns/lib/ztlp_ns/server.ex` | Wire rate limiter, fix registration auth, add size limits, name validation, amplification check, worker pool, audit logging, renewal handler |
| `ns/lib/ztlp_ns/store.ex` | Record size validation, pubkey index, enrollment nonce persistence |
| `ns/lib/ztlp_ns/config.ex` | New config options (verify_trust_chain, name_suffix, worker_pool_size) |
| `ns/lib/ztlp_ns/application.ex` | Add Task.Supervisor to supervision tree |
| `proto/src/bin/ztlp-cli.rs` | Add `renew` and `agent` subcommands, NS refresh in `listen` |

### New files to create:
| File | Purpose |
|------|---------|
| `ns/lib/ztlp_ns/renewal.ex` | RENEW (0x09) handler — cert renewal protocol |
| `ns/lib/ztlp_ns/name_validator.ex` | Name format validation |
| `ns/lib/ztlp_ns/registration_auth.ex` | Zone authorization for registrations |
| `proto/src/renewal.rs` | Rust RENEW client — build/parse/send messages |
| `proto/src/agent.rs` | Credential renewal daemon |
| `ns/test/ztlp_ns/renewal_test.exs` | Renewal tests |
| `ns/test/ztlp_ns/registration_auth_test.exs` | Registration auth tests |
| `ns/test/ztlp_ns/rate_limiter_integration_test.exs` | Rate limiter integration tests |
| `proto/tests/renewal_test.rs` | Rust renewal tests |

---

## Implementation Order

**Phase 1 — Critical security fixes (server.ex wiring):**
1. Wire rate limiter → server
2. Fix registration: verify signatures, reject unsigned
3. Add zone authorization to registration
4. Packet/record size limits
5. Name validation
6. Audit logging

**Phase 2 — High priority improvements:**
7. Pubkey lookup index (O(1) instead of O(n))
8. Amplification prevention
9. Worker pool (Task.Supervisor)
10. Persist registration signing key

**Phase 3 — Certificate renewal (new feature):**
11. `ns/lib/ztlp_ns/renewal.ex` — NS server handler
12. `proto/src/renewal.rs` — Rust client
13. `ztlp renew` CLI subcommand
14. NS record auto-refresh in `ztlp listen`

**Phase 4 — Agent daemon:**
15. `proto/src/agent.rs` — background renewal + refresh daemon
16. `ztlp agent` CLI subcommand
17. Systemd service file
18. Agent metrics

**Estimated total effort:** 2–3 focused sessions
