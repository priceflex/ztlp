# ZTLP Assurance Level — Step 1 Specification

> Schema and policy plumbing only. No crypto changes, no hardware-token
> enrollment, no attestation verifier. Lands the whitepaper's
> "assurance level requirements" feature on top of today's L1 (software-key)
> identities.

**Status:** Draft for review
**Author:** Steven Price
**Last updated:** 2026-05-23
**Targets:** proto (Rust), ns (Elixir), gateway (Elixir), CLI

---

## 1. Scope and Non-Goals

### In scope (this step)

- Define `AssuranceLevel` as a first-class enum in the Rust proto crate
  and as an atom/byte mapping in the Elixir NS crate.
- Add `assurance_level` as a signed field on the NS DEVICE record's
  CBOR data map.
- Require the enrollment authority (bootstrap Rails app, or any future
  enrollment authority) to set `assurance_level` when registering a
  device. The client cannot self-assert it.
- Add `min_assurance` to gateway policy YAML rules.
- Extend the gateway admission path to compare the resolved peer's
  device assurance level against the service's `min_assurance` and
  reject mismatches.
- Extend the audit log format to include `assurance` and
  `required_assurance` fields for every admission decision.
- Default every existing device (any DEVICE record without an
  `assurance_level` field) to `software`.
- Default every existing policy rule (any rule without a
  `min_assurance` field) to `software`.

### Out of scope (later steps)

- L2 PKCS#11 / hardware-token enrollment (Step 2).
- L3 platform attestation verifiers — DCAppAttest, TPM AIK chains,
  Android KeyAttestation (Step 3+).
- Noise cipher-suite changes; Noise stays `Noise_XX_25519_ChaChaPoly_BLAKE2s`.
- Algorithm-agnostic identity keys; Ed25519 + X25519 remain the only
  curves today. The `AssuranceLevel` enum is forward-compatible with
  Option A (per the long-term plan), but no algorithm tag ships here.
- Per-user `min_assurance` (USER records). Step 1 binds assurance to
  the device only.
- Runtime promotion/demotion APIs. Assurance level is set at
  enrollment and changed only by re-enrollment.

---

## 2. The `AssuranceLevel` Enum

### 2.1 Definition

Three levels, ordered from weakest to strongest:

| Level | Wire byte | Meaning |
|-------|-----------|---------|
| `software` | `0x01` | Private key stored in a filesystem file. The default for existing identities. Compromised by any local code execution on the device. |
| `hardware_token` | `0x02` | Private key stored in a removable hardware token (YubiKey, Nitrokey, smart card via PKCS#11). Not implemented in Step 1; the enum value is reserved so policy can be written today and start working the moment Step 2 lands. |
| `attested` | `0x03` | Private key stored in a platform secure element (TPM 2.0, Apple Secure Enclave, Android StrongBox) AND the enrollment carries a manufacturer-signed attestation chain proving the key is non-extractable. Not implemented in Step 1; reserved for the same forward-compatibility reason. |

Wire bytes `0x00` and `0x04..0xFF` are reserved. A receiver that sees an
unknown wire byte MUST treat the record as if the field were absent
(i.e., fall back to `software`) and log a warning. This keeps a future
`0x04 = attested_with_user_presence` rollout from bricking older
gateways.

### 2.2 Ordering and comparison

The levels form a strict total order:

```
software < hardware_token < attested
```

The policy comparison is "does the device's level meet or exceed the
service's required level". A device at `attested` satisfies a rule
requiring `software`. A device at `software` does NOT satisfy a rule
requiring `hardware_token`.

This is the only comparison the gateway makes. There is no notion of
"approximately equal" or "different but acceptable" levels.

### 2.3 Rust definition (proto crate)

`proto/src/identity.rs` gains:

```rust
/// Assurance level of an identity's long-term key material.
///
/// Set by the enrollment authority at enrollment time and carried in
/// the device's NS record. Clients MUST NOT self-assert this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    Software,
    HardwareToken,
    Attested,
}

impl AssuranceLevel {
    pub fn to_wire_byte(self) -> u8 {
        match self {
            AssuranceLevel::Software => 0x01,
            AssuranceLevel::HardwareToken => 0x02,
            AssuranceLevel::Attested => 0x03,
        }
    }

    pub fn from_wire_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(AssuranceLevel::Software),
            0x02 => Some(AssuranceLevel::HardwareToken),
            0x03 => Some(AssuranceLevel::Attested),
            _ => None,
        }
    }
}

impl Default for AssuranceLevel {
    fn default() -> Self {
        AssuranceLevel::Software
    }
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssuranceLevel::Software => write!(f, "software"),
            AssuranceLevel::HardwareToken => write!(f, "hardware_token"),
            AssuranceLevel::Attested => write!(f, "attested"),
        }
    }
}

impl std::str::FromStr for AssuranceLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "software" => Ok(AssuranceLevel::Software),
            "hardware_token" | "hardware-token" | "hardware" => Ok(AssuranceLevel::HardwareToken),
            "attested" => Ok(AssuranceLevel::Attested),
            other => Err(format!("unknown assurance level: {other}")),
        }
    }
}
```

The derives `PartialOrd, Ord` give us the comparison semantics from §2.2
for free, in the declared variant order.

### 2.4 Elixir mirror (ns and gateway crates)

`ns/lib/ztlp_ns/assurance.ex` (new file):

```elixir
defmodule ZtlpNs.Assurance do
  @moduledoc """
  Assurance level of an identity's long-term key material.

  See docs/ASSURANCE-LEVEL-SPEC.md for the protocol-level definition.
  Mirrors `AssuranceLevel` in proto/src/identity.rs.
  """

  @type t :: :software | :hardware_token | :attested

  @atom_to_byte %{software: 0x01, hardware_token: 0x02, attested: 0x03}
  @byte_to_atom %{0x01 => :software, 0x02 => :hardware_token, 0x03 => :attested}

  @ordering %{software: 0, hardware_token: 1, attested: 2}

  @spec to_byte(t()) :: byte()
  def to_byte(level), do: Map.fetch!(@atom_to_byte, level)

  @spec from_byte(byte()) :: {:ok, t()} | :error
  def from_byte(b), do: Map.fetch(@byte_to_atom, b) |> wrap()

  @spec from_string(String.t()) :: {:ok, t()} | :error
  def from_string(s) do
    case String.downcase(String.trim(s)) do
      "software" -> {:ok, :software}
      "hardware_token" -> {:ok, :hardware_token}
      "hardware-token" -> {:ok, :hardware_token}
      "hardware" -> {:ok, :hardware_token}
      "attested" -> {:ok, :attested}
      _ -> :error
    end
  end

  @spec to_string(t()) :: String.t()
  def to_string(:software), do: "software"
  def to_string(:hardware_token), do: "hardware_token"
  def to_string(:attested), do: "attested"

  @doc """
  `true` if the device's level meets or exceeds the required level.
  See spec §2.2 for ordering.
  """
  @spec meets?(t(), t()) :: boolean()
  def meets?(device_level, required_level) do
    Map.fetch!(@ordering, device_level) >= Map.fetch!(@ordering, required_level)
  end

  @spec default() :: t()
  def default(), do: :software

  defp wrap({:ok, _} = v), do: v
  defp wrap(:error), do: :error
end
```

The gateway crate does NOT duplicate this module — it depends on
`:ztlp_ns` (it already does, via `ZtlpGateway.NsClient`) and calls
`ZtlpNs.Assurance` directly. One canonical implementation.

---

## 3. NS DEVICE Record Field

### 3.1 New field

The DEVICE record's CBOR `data` map gains one optional field:

| Field | Type | Required? | Default | Notes |
|-------|------|-----------|---------|-------|
| `assurance_level` | string | optional | `"software"` | One of `"software"`, `"hardware_token"`, `"attested"`. Hex strings or integer wire bytes are NOT accepted in the CBOR data map — the string form is the canonical wire shape inside the data field. The wire byte from §2.1 is reserved for future binary protocol extensions but is NOT used in the NS record itself. |

### 3.2 Why string-in-CBOR, not byte-in-CBOR

The DEVICE record's data map already uses string-valued fields for
everything that's a small enum (`role: "admin" | "tech" | "user"` in
USER records). Following that convention keeps the records readable in
the existing NS CLI dump tools, lets operators eyeball NS dumps for
"is this device hardware-backed?", and avoids inventing a new
encoding for one field.

The wire-byte form from §2.1 exists for any future binary protocol
(e.g., a future identity header in the handshake), not for the NS
record's data map.

### 3.3 Updated `ZtlpNs.Record.new_device/4`

In `ns/lib/ztlp_ns/record.ex` around line 395:

```elixir
@spec new_device(String.t(), binary(), binary(), keyword()) :: t()
def new_device(name, node_id, pubkey, opts \\ []) do
  assurance =
    case opts[:assurance_level] do
      nil -> :software
      atom when is_atom(atom) -> atom
      str when is_binary(str) ->
        case ZtlpNs.Assurance.from_string(str) do
          {:ok, lvl} -> lvl
          :error -> raise ArgumentError, "invalid assurance_level: #{inspect(str)}"
        end
    end

  %__MODULE__{
    name: name,
    type: :device,
    data: %{
      node_id: Base.encode16(node_id, case: :lower),
      public_key: Base.encode16(pubkey, case: :lower),
      owner: opts[:owner] || "",
      hardware_id: opts[:hardware_id] || "",
      assurance_level: ZtlpNs.Assurance.to_string(assurance)
    },
    created_at: opts[:created_at] || System.system_time(:second),
    ttl: opts[:ttl] || 86400,
    serial: opts[:serial] || 1
  }
end
```

Note: `assurance_level` is ALWAYS written into the data map (never
omitted), even when it's `"software"`. This matters for the canonical
signing form — the signature covers the CBOR-encoded data map, and we
want the signed bytes to be stable across calls that pass the default
explicitly vs. relying on it.

### 3.4 Updated `ZtlpNs.Record.validate_device/1`

Around line 444:

```elixir
@spec validate_device(map()) :: :ok | {:error, atom()}
def validate_device(data) do
  node_id = Map.get(data, :node_id) || Map.get(data, "node_id")
  pubkey = Map.get(data, :public_key) || Map.get(data, "public_key")
  assurance_str = Map.get(data, :assurance_level) || Map.get(data, "assurance_level") || "software"

  cond do
    is_nil(node_id) or node_id == "" ->
      {:error, :missing_node_id}

    is_nil(pubkey) or pubkey == "" ->
      {:error, :missing_public_key}

    match?(:error, ZtlpNs.Assurance.from_string(assurance_str)) ->
      {:error, :invalid_assurance_level}

    true ->
      :ok
  end
end
```

A DEVICE record with a malformed `assurance_level` string is rejected
at registration time. Existing records without the field are accepted
(default applied at read time).

### 3.5 Reading helper

Add to `ZtlpNs.Record`:

```elixir
@doc """
Read a DEVICE record's assurance level. Defaults to `:software` if the
field is absent or malformed (with a warning logged). This is the only
place where a malformed value is tolerated — registration rejects it
(see `validate_device/1`), but read paths must remain forward-compatible
with records written by future versions of NS that may use unknown
string values.
"""
@spec device_assurance(t()) :: ZtlpNs.Assurance.t()
def device_assurance(%__MODULE__{type: :device, data: data}) do
  raw = Map.get(data, :assurance_level) || Map.get(data, "assurance_level") || "software"

  case ZtlpNs.Assurance.from_string(raw) do
    {:ok, lvl} ->
      lvl

    :error ->
      require Logger
      Logger.warning("ZtlpNs.Record: unknown assurance_level #{inspect(raw)}, treating as :software")
      :software
  end
end
```

---

## 4. Enrollment Authority Signs `assurance_level`

### 4.1 Invariant

The `assurance_level` field is part of the DEVICE record's CBOR data
map, which is part of the canonical serialization, which is what the
signature covers. Therefore the existing record-signature mechanism
(`ZtlpNs.Record.serialize/1` + Ed25519 over the signer's key) already
binds the assurance level to the enrolling authority's signature.

No new cryptographic mechanism is required. The work is purely:

- The enrollment authority must SET the field at the value it has
  evidence for.
- Verification logic must REJECT a DEVICE record whose signer is not
  the enrollment authority for the zone.

The second point is already enforced by `ZtlpNs.RegistrationAuth` —
this spec does not change that path; it only ensures the field travels
through it.

### 4.2 What the bootstrap server emits

Today the bootstrap server (Rails app at `bootstrap/`) issues
enrollment tokens that let a CLI register itself. Step 1 changes the
emitted DEVICE record:

- If the enrollment flow used was the standard `ztlp setup --token …`
  path (a software keygen in the CLI), the bootstrap server sets
  `assurance_level: "software"`.
- The bootstrap server MUST NOT honor a client-supplied
  `assurance_level` in the registration request. Any field the client
  sends with that name is dropped before signing.
- Step 2 will introduce a hardware-token enrollment flow that proves
  to the bootstrap server (via PKCS#11 attestation or equivalent) that
  the key lives on a token; only then will the bootstrap server set
  `"hardware_token"`. Until that flow exists, the only valid value the
  authority emits is `"software"`.

### 4.3 What the CLI sends in a registration request

For Step 1, the registration request payload from the CLI to the
bootstrap server does NOT include an `assurance_level` field. The
authority decides based on the enrollment flow it serves. Adding the
field on the client side would be a self-assertion vector — explicitly
disallowed.

### 4.4 Manual `ztlp ns register` path

`ztlp ns register` (the operator path that writes records directly
into a zone with the zone authority key) DOES accept an
`--assurance-level` CLI flag. This is the escape hatch for operators
who run their own enrollment authority — they can issue records with
any level, signed by their own zone key. The flag exists in the CLI
for symmetry but the trust comes from the zone-authority signature,
not from the flag.

`ztlp ns register --assurance-level software` is the only invocation
shipped in Step 1; the other values are accepted by the parser but
documented as "Step 2+ only" because there is no way to PRODUCE a
hardware-backed key yet.

---

## 5. Gateway Policy: `min_assurance`

### 5.1 YAML schema extension

`gateway/config/gateway.yaml` (and the equivalent
`gateway/config/runtime.exs` policy form) gain an optional
`min_assurance` key on each rule:

```yaml
policies:
  - service: payroll
    allow: ["group:finance@acme.ztlp"]
    min_assurance: attested

  - service: wiki
    allow: :all
    min_assurance: hardware_token

  - service: public-status
    allow: :all
    # min_assurance omitted → default "software" → no extra gate

  - service: default
    allow: ["*.engineering.acme.ztlp"]
    min_assurance: software
```

Defaults:

- A rule without `min_assurance` is treated as `min_assurance: software`.
- A service with no rule at all falls through to the `default` rule
  (existing behavior, unchanged) — `default`'s `min_assurance` applies.
- A `min_assurance` value the gateway doesn't recognize causes
  gateway startup to FAIL with a clear error message. We do NOT
  silently downgrade on startup — that would be a deploy-time
  security regression.

### 5.2 Updated rule storage

`ZtlpGateway.PolicyEngine`'s ETS table currently stores
`{service, allow}`. Step 1 changes this to
`{service, %{allow: allow, min_assurance: level}}`:

```elixir
@type rule :: %{
        allow: :all | [String.t()],
        min_assurance: ZtlpNs.Assurance.t()
      }

# init/1 changes:
Enum.each(policies, fn rule ->
  svc = rule[:service] || rule["service"]
  allow = rule[:allow] || rule["allow"]

  min_assurance =
    case rule[:min_assurance] || rule["min_assurance"] do
      nil ->
        :software

      str when is_binary(str) ->
        case ZtlpNs.Assurance.from_string(str) do
          {:ok, lvl} ->
            lvl

          :error ->
            raise "invalid min_assurance #{inspect(str)} for service #{inspect(svc)}"
        end

      atom when is_atom(atom) ->
        atom
    end

  :ets.insert(@table, {svc, %{allow: allow, min_assurance: min_assurance}})
end)
```

### 5.3 Updated `authorize?`

`authorize?/2,3` keeps its signature but the body fetches the
structured rule and lets the admission caller see the
`min_assurance` separately. A new function
`evaluate/3` returns the full decision:

```elixir
@type decision :: %{
        result: :allow | :deny,
        reason: atom(),
        matched_pattern: String.t() | nil,
        required_assurance: ZtlpNs.Assurance.t(),
        device_assurance: ZtlpNs.Assurance.t() | nil
      }

@spec evaluate(String.t(), String.t(), ZtlpNs.Assurance.t() | nil, keyword()) :: decision()
def evaluate(identity, service, device_assurance, opts \\ []) do
  rule = lookup_rule(service)
  required = rule.min_assurance

  cond do
    not pattern_allows?(identity, rule.allow, opts) ->
      %{result: :deny, reason: :pattern_mismatch,
        matched_pattern: nil,
        required_assurance: required,
        device_assurance: device_assurance}

    is_nil(device_assurance) ->
      # No NS record for this device — treat as software (safest for
      # backward compat with the existing prototype, where many test
      # paths don't register devices). Only denies if min > software.
      effective = :software
      if ZtlpNs.Assurance.meets?(effective, required) do
        %{result: :allow, reason: :ok, matched_pattern: nil,
          required_assurance: required, device_assurance: effective}
      else
        %{result: :deny, reason: :assurance_too_low,
          matched_pattern: nil,
          required_assurance: required, device_assurance: effective}
      end

    ZtlpNs.Assurance.meets?(device_assurance, required) ->
      %{result: :allow, reason: :ok, matched_pattern: nil,
        required_assurance: required, device_assurance: device_assurance}

    true ->
      %{result: :deny, reason: :assurance_too_low,
        matched_pattern: nil,
        required_assurance: required,
        device_assurance: device_assurance}
  end
end
```

`authorize?/2,3` remains as a convenience wrapper that returns just the
boolean. Existing callers keep working; new admission code uses
`evaluate/3` so it can log the assurance-related fields.

### 5.4 Resolving the peer's assurance level

After the Noise_XX handshake completes, the gateway has the peer's
X25519 static public key. It already does an NS lookup to find the
zone name of that key. In Step 1 we extend that lookup to ALSO return
the assurance level from the DEVICE record:

`ZtlpGateway.NsClient` gains:

```elixir
@spec resolve_device(binary()) :: {:ok, %{name: String.t(), assurance: ZtlpNs.Assurance.t()}} | :not_found
def resolve_device(static_pubkey_bytes) do
  case lookup_device_by_pubkey(static_pubkey_bytes) do
    {:ok, record} ->
      {:ok, %{
        name: record.name,
        assurance: ZtlpNs.Record.device_assurance(record)
      }}

    :not_found ->
      :not_found
  end
end
```

The session-establishment code in `ZtlpGateway.Session` then calls
`resolve_device/1`, passes the assurance to `PolicyEngine.evaluate/3`,
and acts on the result.

For peers with no NS record (e.g., test fixtures, ad-hoc bench runs),
`resolve_device/1` returns `:not_found`, the session code passes `nil`
as `device_assurance`, and `evaluate/3` applies the "treat as software"
rule from §5.3.

---

## 6. Gateway Admission Decision Logic

### 6.1 Decision flow

The order of checks during admission, post-handshake:

1. Handshake validates (Noise_XX completes). If not, admission fails
   before this spec applies.
2. Resolve service name from the HELLO header. (Unchanged.)
3. Resolve peer device via `NsClient.resolve_device/1`. Get
   `{name, assurance}` or `:not_found`.
4. Call `PolicyEngine.evaluate(name_or_pubkey, service, assurance)`.
5. If `result: :allow`, proceed with backend connection.
6. If `result: :deny`, close the QUIC connection with a reason code
   and emit the audit log line (§7).

### 6.2 Deny reason codes

| `reason` atom | Meaning | Operator-visible message |
|---------------|---------|--------------------------|
| `:pattern_mismatch` | Existing pattern/group/role check failed. Unchanged from today. | `not authorized` |
| `:assurance_too_low` | Pattern matched but the device's assurance level is below the service's `min_assurance`. | `assurance level insufficient: device=<lvl> required=<lvl>` |

The QUIC close frame carries a numeric application error code. Step 1
reserves:

- `0x2001` — `pattern_mismatch` (same value the existing pattern denial
  uses; unchanged).
- `0x2002` — `assurance_too_low` (new).

Clients that see `0x2002` SHOULD surface a message guiding the user to
re-enroll on a higher-assurance flow once those flows exist.

### 6.3 What changes for existing test fixtures

Every existing gateway test passes a software-keyed peer to a policy
that omits `min_assurance` (default `software`). The new decision
logic produces `:allow` for every such test, so the test surface is
unchanged unless a test deliberately sets `min_assurance` to a higher
value.

The one new behavior to assert in tests:

- A device with no NS record and a service requiring
  `hardware_token` is DENIED with `:assurance_too_low`.
- A device with `software` and a service requiring `hardware_token`
  is DENIED with `:assurance_too_low`.
- A device with `attested` and a service requiring `hardware_token`
  is ALLOWED.

---

## 7. Audit Logging Format

### 7.1 Today's line shape

The gateway currently emits admission decisions via
`ZtlpGateway.Session` using Elixir's `Logger`. The line format is
informal and varies by code path.

Step 1 introduces a canonical structured form for admission decisions.

### 7.2 New canonical line

```
admission_decision device=<name_or_pubkey_hex> service=<svc> assurance=<lvl> required_assurance=<lvl> decision=<allow|deny> reason=<atom> session_id=<hex16>
```

Examples:

```
admission_decision device=laptop-01.acme.ztlp service=payroll assurance=software required_assurance=attested decision=deny reason=assurance_too_low session_id=3f9c1e8a7b2d4f56

admission_decision device=laptop-01.acme.ztlp service=wiki assurance=software required_assurance=software decision=allow reason=ok session_id=3f9c1e8a7b2d4f56

admission_decision device=unknown(pub=a1b2c3...) service=public-status assurance=software required_assurance=software decision=allow reason=ok session_id=3f9c1e8a7b2d4f56
```

### 7.3 Field semantics

- `device` — Either the zone-qualified name resolved from NS, or
  `unknown(pub=<first 8 bytes hex>)` if no NS record was found.
- `service` — The backend service name from the HELLO header.
- `assurance` — The device's resolved assurance level, or `software`
  if the device wasn't found in NS (per §5.3 fallback).
- `required_assurance` — The `min_assurance` from the matched policy
  rule (or `software` if the rule omits it).
- `decision` — `allow` or `deny`.
- `reason` — One of the atoms from §6.2 (`ok`, `pattern_mismatch`,
  `assurance_too_low`). `ok` is used for the allow case to keep the
  field present and greppable.
- `session_id` — The 12-byte ZTLP session ID, hex-encoded. Already
  present in other gateway log lines; included here so audit lines
  can be correlated with handshake lines.

### 7.4 Logger level and emission point

- Level: `:info` for both allow and deny. Deny is operationally
  routine and should not be `:warning` (an attacker probing services
  would otherwise be a denial-of-logging vector).
- Emitted exactly once per admission decision, from
  `ZtlpGateway.Session` immediately after `PolicyEngine.evaluate/3`
  returns.
- Emitted BEFORE the QUIC close (for denies) so the audit record
  exists even if the close fails.

### 7.5 Forward compatibility

The line is plain `key=value` space-separated to keep it greppable
without a parser. Future fields are appended after `session_id` to
preserve compatibility with existing log scrapers.

A future structured-logging mode (JSON) is a separate decision and not
part of Step 1. Today's text format is the audit format.

---

## 8. Default Behavior for Existing Deployments

### 8.1 Existing DEVICE records

Records written before Step 1 don't have an `assurance_level` field in
their CBOR data map. They are NOT migrated. The read helper
(`device_assurance/1`, §3.5) returns `:software` when the field is
absent. The next time the record is re-signed by the enrollment
authority (TTL refresh, owner change, etc.), the new code path
writes `"software"` explicitly.

### 8.2 Existing policy rules

Rules without `min_assurance` default to `:software`. No deployment
needs to update its YAML to keep working.

### 8.3 Existing handshakes

A device with no NS record at all (test fixtures, bench runs,
unenrolled CLI sessions) is treated as `software` (§5.3 fallback).
This preserves today's behavior — those flows already work today.

### 8.4 No-flag-day guarantee

A gateway running the Step 1 code MUST be deployable into a fleet
where some peers and some NS records still run Step 0 code. The
fallback rules in §3.5, §5.3, and §8.1 together guarantee this.

A Step 0 gateway reading a Step 1 NS record sees an unknown field in
the CBOR data map. CBOR decoders that follow RFC 8949 ignore unknown
map keys, so the Step 0 gateway loses the assurance information but
keeps working. (CONFIRM during implementation that
`ZtlpNs.Cbor.decode/1` round-trips unknown keys without erroring; if
it errors, that's a bug to fix in Step 1.)

---

## 9. Test Surface

### 9.1 Rust (proto)

- Unit tests for `AssuranceLevel`:
  - Round-trip via `to_wire_byte` / `from_wire_byte`.
  - Round-trip via `Display` / `FromStr`.
  - `PartialOrd` matches the §2.2 ordering.
  - `Default` returns `Software`.
  - Serde round-trip through JSON yields the snake_case form.

### 9.2 Elixir (ns)

- `ZtlpNs.Assurance`: byte round-trip, string parse (all aliases),
  `meets?/2` ordering, `default/0`.
- `ZtlpNs.Record.new_device/4` includes `assurance_level: "software"`
  in the data map when no opt is passed.
- `ZtlpNs.Record.new_device/4` raises on invalid string.
- `ZtlpNs.Record.validate_device/1` accepts records without the field
  (for backward compat) and rejects records with a malformed field.
- `ZtlpNs.Record.device_assurance/1` returns `:software` for legacy
  records, the correct value for new records, and `:software` plus a
  warning for unknown future values.
- Canonical-serialization regression: a DEVICE record with
  `assurance_level: "software"` serializes to a stable byte string
  that the test pins as a hex constant. This guards against
  accidental signature breaks.

### 9.3 Elixir (gateway)

- `ZtlpGateway.PolicyEngine.evaluate/3` for the four matrix cells:
  pattern-pass + assurance-pass, pattern-pass + assurance-fail,
  pattern-fail (assurance irrelevant), missing NS record
  (treated as software).
- `ZtlpGateway.PolicyEngine` startup fails on a malformed
  `min_assurance` in YAML.
- Audit log line matches the §7.2 regex for each of the matrix cells.
- A backward-compat test: a YAML rule without `min_assurance` loads
  and behaves identically to one with `min_assurance: software`.

### 9.4 Integration

- E2E: a device enrolled via today's bootstrap (which emits
  `"software"`) connects to a service whose rule is
  `min_assurance: hardware_token`, gets denied with QUIC error
  `0x2002`, and the gateway audit log contains the expected line.
- E2E: same device, same service, but the rule is
  `min_assurance: software` — connection succeeds.

---

## 10. Open Questions for Review

These are deliberately left for Steve to decide before the
implementation plan is finalized.

1. **NS record CBOR encoding of the field.** The spec uses the
   string form (`"software"`) in the CBOR data map. Alternative: use
   the wire byte from §2.1 as a CBOR small-int. String is more
   readable; byte is one byte shorter on the wire and matches the
   binary protocol byte. **Recommendation: string.** Locking in.

2. **Where the bootstrap server stamps `"software"`.** Today the
   bootstrap server hands the CLI an enrollment certificate and the
   CLI publishes its own DEVICE record signed by the zone authority
   (or signed by the bootstrap-issued sub-key, depending on flow).
   The spec assumes the bootstrap-signed flow. If your deployment
   uses a different signing path (the operator signs records out-of-
   band), §4.2 needs to call that flow out specifically.

3. **Deny error code `0x2002`.** Is `0x20xx` the right namespace for
   policy-class errors, or do you want `0x21xx` so future assurance
   errors stay clustered? **Default: keep `0x2002` adjacent to
   `0x2001` so all policy errors are 0x20xx.**

4. **Audit log destination.** Step 1 emits to Logger. Do you want a
   separate audit sink (file, syslog facility, structured pipeline)?
   **Default: ride Logger for Step 1, evaluate sink in Step 2+ when
   real customers want it.**

5. **Should `evaluate/3` be the primary API and `authorize?/2,3` be
   deprecated?** Keeping `authorize?/2,3` around forever costs us
   nothing today. **Default: keep both; document `evaluate/3` as
   the preferred new API.**

---

## 11. Forward Compatibility Notes

The schema in this spec is designed to host Steps 2 and 3 without a
breaking change:

- Wire bytes for new levels (`0x04` etc.) are reserved.
- The enrollment authority is already the sole writer of
  `assurance_level`; Step 2/3 just adds new flows the authority can
  use to justify `"hardware_token"` or `"attested"`.
- `min_assurance` already accepts the future levels; policies written
  today as `min_assurance: hardware_token` will START WORKING the
  moment Step 2 ships, with no policy edit required.
- The audit log format is field-additive; Step 2 will add an
  `attestation_chain_id=…` field at the end of the line.
- The `AssuranceLevel` enum stays open to algorithm-agnostic identity
  keys (Option A from the long-term plan). When that change lands,
  it adds a sibling enum (`IdentityAlgorithm` or similar) — not a
  variant on `AssuranceLevel`.

---

## 12. Summary

Step 1 adds one enum, one optional CBOR field, one YAML key, one new
gateway function, and one canonical audit-log line. It changes no
crypto, requires no fleet migration, ships with the whitepaper's
policy feature working end-to-end, and leaves the door open for
hardware-token and attested-device enrollment in Steps 2 and 3.
