# Assurance Level Step 1 Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Land the `AssuranceLevel` schema and policy plumbing across proto, ns, and gateway so the whitepaper's "assurance level requirements" policy feature works end-to-end on top of today's software-key identities, without any crypto, attestation, or hardware-token work.

**Architecture:** Three changes, in this order: (1) define the enum in proto and Elixir, (2) add the field to the NS DEVICE record and require the enrollment authority to set it, (3) extend gateway policy YAML with `min_assurance` and wire the admission path to consult it. Defaults are chosen so existing deployments behave identically until an operator opts in.

**Tech Stack:** Rust (proto, snow, serde, CBOR), Elixir/OTP (ns, gateway, ETS, Logger), CBOR (RFC 8949), YAML (gateway config).

**Spec:** `docs/ASSURANCE-LEVEL-SPEC.md` (companion document — read first).

**Branch:** `feat/assurance-level-step1` off `main`.

**Commit identity:** "Steven Price" <steve@techrockstars.com>.

**Commit format:** What/Why/Details/Tests/Validation/Follow-up bullets per Steve's convention.

---

## Pre-Flight

### Task 0a: Read the spec and confirm scope

**Objective:** Subagent loads docs/ASSURANCE-LEVEL-SPEC.md, confirms it covers what this plan implements, surfaces any spec ambiguity before code is written.

**Files:**
- Read: `docs/ASSURANCE-LEVEL-SPEC.md`
- Read: `proto/src/identity.rs`
- Read: `ns/lib/ztlp_ns/record.ex`
- Read: `gateway/lib/ztlp_gateway/policy_engine.ex`
- Read: `gateway/lib/ztlp_gateway/session.ex`
- Read: `gateway/lib/ztlp_gateway/ns_client.ex`

**Step 1:** Subagent reports a 1-paragraph summary of which spec sections each Elixir/Rust file maps to. If anything is ambiguous, halt and ask.

**No commit.**

### Task 0b: Create feature branch

**Objective:** Branch off main with a clean working tree.

```bash
cd /home/trs/ztlp
git status --short                  # expect clean modulo known untracked files
git checkout -b feat/assurance-level-step1
git push -u origin feat/assurance-level-step1
```

**Expected:** Branch exists locally and on origin. `git status` clean apart from the pre-existing untracked items (.ssh/, docker_build/, etc. — leave alone).

**No commit yet.**

---

## Phase A — `AssuranceLevel` enum in proto (Rust)

### Task A1: Failing tests for `AssuranceLevel`

**Objective:** Pin the enum's public surface before writing it.

**Files:**
- Create: `proto/tests/assurance_level_test.rs`

**Step 1: Write failing test**

```rust
use ztlp_proto::identity::AssuranceLevel;
use std::str::FromStr;

#[test]
fn wire_byte_roundtrip() {
    for lvl in [
        AssuranceLevel::Software,
        AssuranceLevel::HardwareToken,
        AssuranceLevel::Attested,
    ] {
        let b = lvl.to_wire_byte();
        assert_eq!(AssuranceLevel::from_wire_byte(b), Some(lvl));
    }
    assert_eq!(AssuranceLevel::from_wire_byte(0x00), None);
    assert_eq!(AssuranceLevel::from_wire_byte(0xFF), None);
}

#[test]
fn wire_byte_values_are_stable() {
    assert_eq!(AssuranceLevel::Software.to_wire_byte(), 0x01);
    assert_eq!(AssuranceLevel::HardwareToken.to_wire_byte(), 0x02);
    assert_eq!(AssuranceLevel::Attested.to_wire_byte(), 0x03);
}

#[test]
fn string_parse_all_aliases() {
    assert_eq!(AssuranceLevel::from_str("software").unwrap(), AssuranceLevel::Software);
    assert_eq!(AssuranceLevel::from_str("SOFTWARE").unwrap(), AssuranceLevel::Software);
    assert_eq!(AssuranceLevel::from_str("hardware_token").unwrap(), AssuranceLevel::HardwareToken);
    assert_eq!(AssuranceLevel::from_str("hardware-token").unwrap(), AssuranceLevel::HardwareToken);
    assert_eq!(AssuranceLevel::from_str("hardware").unwrap(), AssuranceLevel::HardwareToken);
    assert_eq!(AssuranceLevel::from_str("attested").unwrap(), AssuranceLevel::Attested);
    assert!(AssuranceLevel::from_str("bogus").is_err());
}

#[test]
fn display_is_snake_case() {
    assert_eq!(format!("{}", AssuranceLevel::Software), "software");
    assert_eq!(format!("{}", AssuranceLevel::HardwareToken), "hardware_token");
    assert_eq!(format!("{}", AssuranceLevel::Attested), "attested");
}

#[test]
fn ordering_matches_spec_section_2_2() {
    assert!(AssuranceLevel::Software < AssuranceLevel::HardwareToken);
    assert!(AssuranceLevel::HardwareToken < AssuranceLevel::Attested);
    assert!(AssuranceLevel::Software < AssuranceLevel::Attested);
}

#[test]
fn default_is_software() {
    assert_eq!(AssuranceLevel::default(), AssuranceLevel::Software);
}

#[test]
fn serde_json_roundtrip_snake_case() {
    let lvl = AssuranceLevel::HardwareToken;
    let json = serde_json::to_string(&lvl).unwrap();
    assert_eq!(json, "\"hardware_token\"");
    let back: AssuranceLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lvl);
}
```

**Step 2: Run — expect failures**

```bash
cd /home/trs/ztlp/proto
cargo test --test assurance_level_test 2>&1 | tail -20
```

Expected: compile error, `AssuranceLevel` not found in `ztlp_proto::identity`.

**Step 3: Commit the failing test**

```bash
git add proto/tests/assurance_level_test.rs
git commit -m "test(proto): pin AssuranceLevel enum public surface (failing)

What: Adds integration test ./proto/tests/assurance_level_test.rs that
exercises the AssuranceLevel enum the spec calls for.
Why: TDD — pin the contract before the implementation.
Details: Covers wire-byte roundtrip, stable byte values, string parse
including aliases, Display, total ordering, Default, and serde JSON.
Tests: Currently FAIL — type does not yet exist.
Validation: \`cargo test --test assurance_level_test\` shows compile error.
Follow-up: Task A2 implements the enum to turn this green."
```

### Task A2: Implement `AssuranceLevel` in `proto/src/identity.rs`

**Objective:** Add the enum, derives, and helper impls per spec §2.3.

**Files:**
- Modify: `proto/src/identity.rs`
- Modify: `proto/src/lib.rs` (if `identity` is not already in `pub mod`)

**Step 1:** Read current file to find a good insertion point (just below `NodeId` impls, above `NodeIdentity`).

```bash
read_file proto/src/identity.rs
```

**Step 2: Insert exactly the block from spec §2.3** into `proto/src/identity.rs` immediately after the `impl fmt::Display for NodeId` block. Do not modify any other code in the file. The block is reproduced verbatim from the spec.

**Step 3: Verify it builds**

```bash
cd /home/trs/ztlp/proto
cargo build --release 2>&1 | tail -10
```

Expected: clean build, no warnings about `AssuranceLevel`.

**Step 4: Run the Task A1 tests**

```bash
cargo test --test assurance_level_test 2>&1 | tail -20
```

Expected: all 7 tests pass.

**Step 5: Run cargo fmt and the full lib unit-test suite**

```bash
cargo fmt
cargo test --release --lib 2>&1 | tail -20
```

Expected: zero changes from fmt, all lib tests pass.

**Step 6: Commit**

```bash
git add proto/src/identity.rs
git commit -m "feat(proto): add AssuranceLevel enum to identity module

What: Introduces AssuranceLevel { Software, HardwareToken, Attested }
with wire-byte mapping, Display/FromStr, total ordering, Default, and
serde snake_case serialization.
Why: Step 1 of assurance-level rollout — pure schema, no behavior change
in the Noise handshake or anywhere else yet.
Details: Wire bytes 0x01/0x02/0x03; PartialOrd derived from variant order
matches the spec's Software < HardwareToken < Attested rule; serde uses
rename_all=snake_case to match the NS CBOR string form.
Tests: \`cargo test --test assurance_level_test\` (7 tests) all PASS.
Validation: \`cargo build --release\`, \`cargo fmt --check\`, \`cargo test
--release --lib\` all clean.
Follow-up: NS DEVICE record gains an assurance_level field in Phase B."
```

---

## Phase B — `ZtlpNs.Assurance` and DEVICE record field (Elixir/NS)

### Task B1: Failing tests for `ZtlpNs.Assurance`

**Objective:** Pin the Elixir mirror's public surface.

**Files:**
- Create: `ns/test/ztlp_ns/assurance_test.exs`

**Step 1: Write failing test**

```elixir
defmodule ZtlpNs.AssuranceTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.Assurance

  test "wire byte roundtrip" do
    for lvl <- [:software, :hardware_token, :attested] do
      b = Assurance.to_byte(lvl)
      assert {:ok, ^lvl} = Assurance.from_byte(b)
    end
  end

  test "stable wire byte values" do
    assert Assurance.to_byte(:software) == 0x01
    assert Assurance.to_byte(:hardware_token) == 0x02
    assert Assurance.to_byte(:attested) == 0x03
  end

  test "from_byte rejects unknown" do
    assert :error = Assurance.from_byte(0x00)
    assert :error = Assurance.from_byte(0xFF)
  end

  test "from_string parses all aliases" do
    assert {:ok, :software} = Assurance.from_string("software")
    assert {:ok, :software} = Assurance.from_string("SOFTWARE")
    assert {:ok, :hardware_token} = Assurance.from_string("hardware_token")
    assert {:ok, :hardware_token} = Assurance.from_string("hardware-token")
    assert {:ok, :hardware_token} = Assurance.from_string("hardware")
    assert {:ok, :attested} = Assurance.from_string("attested")
    assert :error = Assurance.from_string("bogus")
  end

  test "to_string is snake_case" do
    assert Assurance.to_string(:software) == "software"
    assert Assurance.to_string(:hardware_token) == "hardware_token"
    assert Assurance.to_string(:attested) == "attested"
  end

  test "meets? matches spec ordering" do
    assert Assurance.meets?(:software, :software)
    refute Assurance.meets?(:software, :hardware_token)
    refute Assurance.meets?(:software, :attested)
    assert Assurance.meets?(:hardware_token, :software)
    assert Assurance.meets?(:hardware_token, :hardware_token)
    refute Assurance.meets?(:hardware_token, :attested)
    assert Assurance.meets?(:attested, :software)
    assert Assurance.meets?(:attested, :hardware_token)
    assert Assurance.meets?(:attested, :attested)
  end

  test "default is software" do
    assert Assurance.default() == :software
  end
end
```

**Step 2: Run — expect failure**

```bash
cd /home/trs/ztlp/ns
mix test test/ztlp_ns/assurance_test.exs 2>&1 | tail -15
```

Expected: `(UndefinedFunctionError) function ZtlpNs.Assurance.to_byte/1 is undefined (module ZtlpNs.Assurance is not available)`.

**Step 3: Commit failing test**

```bash
git add ns/test/ztlp_ns/assurance_test.exs
git commit -m "test(ns): pin ZtlpNs.Assurance public surface (failing)

What: New test module pins to_byte/1, from_byte/1, from_string/1,
to_string/1, meets?/2, default/0.
Why: TDD pin before implementation; mirrors proto Rust enum.
Tests: FAILS — module does not exist yet.
Validation: \`mix test test/ztlp_ns/assurance_test.exs\` shows
UndefinedFunctionError.
Follow-up: Task B2 implements ZtlpNs.Assurance."
```

### Task B2: Implement `ZtlpNs.Assurance`

**Objective:** Land the module verbatim from spec §2.4.

**Files:**
- Create: `ns/lib/ztlp_ns/assurance.ex`

**Step 1: Write the module exactly as spec §2.4 specifies.** Do not improvise: the function signatures and ordering map are what other modules will depend on.

**Step 2: Run tests**

```bash
cd /home/trs/ztlp/ns
mix test test/ztlp_ns/assurance_test.exs 2>&1 | tail -10
```

Expected: 7 tests, 0 failures.

**Step 3: Run full ns suite to confirm no regression**

```bash
mix test 2>&1 | tail -10
```

Expected: existing tests still pass.

**Step 4: Commit**

```bash
git add ns/lib/ztlp_ns/assurance.ex
git commit -m "feat(ns): add ZtlpNs.Assurance module

What: New module ZtlpNs.Assurance mirroring AssuranceLevel from proto.
Why: Step 1 schema — both ns and gateway will read/write this in the
DEVICE record and policy engine respectively.
Details: byte mapping 0x01/0x02/0x03, atom set
:software|:hardware_token|:attested, meets?/2 implements the strict
total order, from_string/1 accepts the three documented aliases.
Tests: 7/7 pass; full \`mix test\` suite unaffected.
Validation: No callers yet — pure schema.
Follow-up: Task B3 extends ZtlpNs.Record.new_device/4 to write the field."
```

### Task B3: Failing tests for DEVICE record changes

**Objective:** Pin the DEVICE-record behavior changes from spec §3.

**Files:**
- Modify: `ns/test/ztlp_ns/record_test.exs` (add a new describe block, do not touch existing tests)

**Step 1: Append the following describe block** (preserve all existing tests):

```elixir
describe "DEVICE record assurance_level (Step 1 spec §3)" do
  test "new_device defaults assurance_level to software string" do
    rec = ZtlpNs.Record.new_device("laptop-01.acme.ztlp", <<0::128>>, <<1::256>>)
    assert rec.data.assurance_level == "software"
  end

  test "new_device accepts atom" do
    rec =
      ZtlpNs.Record.new_device("laptop-01.acme.ztlp", <<0::128>>, <<1::256>>,
        assurance_level: :hardware_token
      )

    assert rec.data.assurance_level == "hardware_token"
  end

  test "new_device accepts string" do
    rec =
      ZtlpNs.Record.new_device("laptop-01.acme.ztlp", <<0::128>>, <<1::256>>,
        assurance_level: "attested"
      )

    assert rec.data.assurance_level == "attested"
  end

  test "new_device raises on invalid string" do
    assert_raise ArgumentError, fn ->
      ZtlpNs.Record.new_device("laptop-01.acme.ztlp", <<0::128>>, <<1::256>>,
        assurance_level: "bogus"
      )
    end
  end

  test "validate_device accepts records without the field (backward compat)" do
    data = %{node_id: "abcd", public_key: "ef01"}
    assert :ok = ZtlpNs.Record.validate_device(data)
  end

  test "validate_device accepts records with valid field" do
    data = %{node_id: "abcd", public_key: "ef01", assurance_level: "hardware_token"}
    assert :ok = ZtlpNs.Record.validate_device(data)
  end

  test "validate_device rejects records with malformed field" do
    data = %{node_id: "abcd", public_key: "ef01", assurance_level: "L9000"}
    assert {:error, :invalid_assurance_level} = ZtlpNs.Record.validate_device(data)
  end

  test "device_assurance returns software for legacy records" do
    rec = %ZtlpNs.Record{
      name: "x.acme.ztlp",
      type: :device,
      data: %{node_id: "abcd", public_key: "ef01"},
      created_at: 0,
      ttl: 60,
      serial: 1
    }

    assert :software = ZtlpNs.Record.device_assurance(rec)
  end

  test "device_assurance returns the field for new records" do
    rec =
      ZtlpNs.Record.new_device("x.acme.ztlp", <<0::128>>, <<1::256>>,
        assurance_level: :attested
      )

    assert :attested = ZtlpNs.Record.device_assurance(rec)
  end

  test "device_assurance tolerates unknown future values" do
    rec = %ZtlpNs.Record{
      name: "x.acme.ztlp",
      type: :device,
      data: %{node_id: "abcd", public_key: "ef01", assurance_level: "future_l4"},
      created_at: 0,
      ttl: 60,
      serial: 1
    }

    assert :software = ZtlpNs.Record.device_assurance(rec)
  end
end

describe "DEVICE record canonical serialization regression" do
  test "DEVICE record with software assurance produces stable signed bytes" do
    rec =
      ZtlpNs.Record.new_device("device.acme.ztlp", <<0::128>>, <<0::256>>,
        created_at: 1_700_000_000,
        ttl: 86400,
        serial: 1
      )

    bytes = ZtlpNs.Record.serialize(rec)
    hex = Base.encode16(bytes, case: :lower)

    # This pin guards against accidental CBOR encoding changes that
    # would break signature verification on existing records. Update
    # ONLY when a deliberate wire-format bump is made.
    assert byte_size(bytes) > 0
    assert String.length(hex) > 0
    # The actual value goes in once the test is first run; subagent
    # captures it from the green run and pastes it back as a literal:
    # assert hex == "<paste from first green run>"
  end
end
```

**Step 2: Run — expect failures**

```bash
mix test test/ztlp_ns/record_test.exs 2>&1 | tail -25
```

Expected: ~7 failures in the new describe block.

**Step 3: Commit**

```bash
git add ns/test/ztlp_ns/record_test.exs
git commit -m "test(ns): pin DEVICE-record assurance_level behavior (failing)

What: Adds two describe blocks to record_test.exs — one for
new_device/4 + validate_device/1 + device_assurance/1, one regression
pin for canonical serialization stability.
Why: TDD for spec §3 (DEVICE record field).
Tests: ~10 new tests FAIL — new_device/4 doesn't write the field yet,
validate_device/1 doesn't check it, device_assurance/1 doesn't exist.
Validation: \`mix test test/ztlp_ns/record_test.exs\` shows the
expected failures.
Follow-up: Task B4 implements the record changes."
```

### Task B4: Implement DEVICE record changes

**Objective:** Apply spec §3.3, §3.4, §3.5 to `ns/lib/ztlp_ns/record.ex`.

**Files:**
- Modify: `ns/lib/ztlp_ns/record.ex`

**Step 1: Replace `new_device/4` body** with the version from spec §3.3.

**Step 2: Replace `validate_device/1` body** with the version from spec §3.4.

**Step 3: Add `device_assurance/1`** at the end of the module per spec §3.5.

**Step 4: Run the new tests**

```bash
cd /home/trs/ztlp/ns
mix test test/ztlp_ns/record_test.exs 2>&1 | tail -15
```

Expected: all new describe tests pass; existing tests still pass.

**Step 5: Capture the canonical hex** — the regression test has a placeholder. Run the regression test alone, inspect output, then paste the actual hex into the assert.

```bash
mix test test/ztlp_ns/record_test.exs --only describe:"DEVICE record canonical serialization regression" -v 2>&1 | tail -20
```

Then patch the test file to replace the commented placeholder with the literal assertion. Re-run to confirm green.

**Step 6: Full ns suite**

```bash
mix test 2>&1 | tail -10
```

Expected: zero failures.

**Step 7: Commit**

```bash
git add ns/lib/ztlp_ns/record.ex ns/test/ztlp_ns/record_test.exs
git commit -m "feat(ns): DEVICE records carry assurance_level field

What: new_device/4 now writes assurance_level (default \"software\")
into the CBOR data map; validate_device/1 rejects malformed values;
new device_assurance/1 helper returns the atom form with backward-
compat fallback to :software for legacy records.
Why: Spec §3 — Step 1 schema for assurance-level policy. Field is
covered by the existing record signature because it lives inside the
signed CBOR data blob.
Details: Default is always written explicitly so canonical
serialization is stable. Regression test pins the hex of a fully-
default DEVICE record's signed bytes.
Tests: 10 new tests in record_test.exs PASS; full \`mix test\` clean.
Validation: Canonical-serialization regression hex captured and pinned.
Follow-up: Task B5 wires the registration path to surface the field."
```

### Task B5: Registration path tolerance check

**Objective:** Confirm `ZtlpNs.RegistrationAuth` and `ZtlpNs.Server` accept DEVICE records with and without the field, and that the field cannot be forged by an unsigned/unauthorized registration.

**Files:**
- Modify (if needed): `ns/test/ztlp_ns/registration_auth_test.exs`

**Step 1:** Subagent reads `registration_auth.ex` and confirms the path is signature-based — a client cannot send an `assurance_level` field that bypasses the zone-authority signature. Document the finding in the commit body.

**Step 2: Add a positive and negative test** to `registration_auth_test.exs`:
- A signed DEVICE record with `assurance_level: "hardware_token"` from the correct authority is accepted.
- A signed DEVICE record from the WRONG authority is rejected as today (existing test pattern), and the assurance field is irrelevant — the rejection happens on the signature path first.

**Step 3:** Run tests.

```bash
cd /home/trs/ztlp/ns
mix test test/ztlp_ns/registration_auth_test.exs 2>&1 | tail -10
```

Expected: all tests pass.

**Step 4: Commit**

```bash
git add ns/test/ztlp_ns/registration_auth_test.exs
git commit -m "test(ns): confirm assurance_level cannot be forged

What: Two new tests in registration_auth_test.exs — a correctly
signed DEVICE record carrying assurance_level=hardware_token is
accepted; an incorrectly signed record is rejected on the signature
path regardless of assurance value.
Why: Spec §4.1 — the field is bound to the enrolling authority's
signature via the existing record-signature mechanism, no new crypto
needed. This test pins that invariant.
Tests: 2 new tests PASS.
Validation: \`mix test test/ztlp_ns/registration_auth_test.exs\` clean.
Follow-up: Phase C wires the gateway to read this field."
```

---

## Phase C — Gateway policy and admission

### Task C1: Failing tests for `PolicyEngine.evaluate/3`

**Objective:** Pin spec §5.3, §5.4, §6.

**Files:**
- Modify: `gateway/test/ztlp_gateway/policy_engine_test.exs` (add a new describe block)

**Step 1: Append the describe block**

```elixir
describe "evaluate/3 with min_assurance (Step 1 spec §5.3)" do
  setup do
    # Ensure the policy table exists. The PolicyEngine GenServer is
    # already started by the test app; we just put_rule directly.
    ZtlpGateway.PolicyEngine.delete_rule("payroll")
    ZtlpGateway.PolicyEngine.delete_rule("wiki")
    ZtlpGateway.PolicyEngine.delete_rule("public")
    :ok
  end

  test "pattern pass + assurance pass → allow" do
    ZtlpGateway.PolicyEngine.put_rule("wiki", %{allow: :all, min_assurance: :software})

    decision = ZtlpGateway.PolicyEngine.evaluate("anyone.acme.ztlp", "wiki", :software)
    assert decision.result == :allow
    assert decision.reason == :ok
    assert decision.required_assurance == :software
    assert decision.device_assurance == :software
  end

  test "pattern pass + assurance fail → deny assurance_too_low" do
    ZtlpGateway.PolicyEngine.put_rule("payroll", %{allow: :all, min_assurance: :attested})

    decision = ZtlpGateway.PolicyEngine.evaluate("user.acme.ztlp", "payroll", :software)
    assert decision.result == :deny
    assert decision.reason == :assurance_too_low
    assert decision.required_assurance == :attested
    assert decision.device_assurance == :software
  end

  test "pattern fail → deny pattern_mismatch (assurance irrelevant)" do
    ZtlpGateway.PolicyEngine.put_rule("payroll", %{
      allow: ["specific.acme.ztlp"],
      min_assurance: :attested
    })

    decision = ZtlpGateway.PolicyEngine.evaluate("other.acme.ztlp", "payroll", :attested)
    assert decision.result == :deny
    assert decision.reason == :pattern_mismatch
  end

  test "missing device assurance falls back to :software" do
    ZtlpGateway.PolicyEngine.put_rule("public", %{allow: :all, min_assurance: :software})

    decision = ZtlpGateway.PolicyEngine.evaluate("nobody", "public", nil)
    assert decision.result == :allow
    assert decision.device_assurance == :software
  end

  test "missing device assurance + min hardware_token → deny" do
    ZtlpGateway.PolicyEngine.put_rule("secure", %{allow: :all, min_assurance: :hardware_token})

    decision = ZtlpGateway.PolicyEngine.evaluate("nobody", "secure", nil)
    assert decision.result == :deny
    assert decision.reason == :assurance_too_low
  end

  test "rule without min_assurance defaults to :software" do
    # put_rule passing a legacy bare value should still work via
    # backward-compat shim, but the new internal representation
    # carries :software.
    ZtlpGateway.PolicyEngine.put_rule("legacy", :all)

    decision = ZtlpGateway.PolicyEngine.evaluate("anyone", "legacy", :software)
    assert decision.result == :allow
    assert decision.required_assurance == :software
  end

  test "ordering: attested device satisfies hardware_token requirement" do
    ZtlpGateway.PolicyEngine.put_rule("secure", %{allow: :all, min_assurance: :hardware_token})

    decision = ZtlpGateway.PolicyEngine.evaluate("anyone", "secure", :attested)
    assert decision.result == :allow
  end
end

describe "PolicyEngine startup validation" do
  test "init/1 raises on malformed min_assurance" do
    # Use a fresh policy list; this test exercises the validation in
    # the init path, not the live GenServer.
    bad = [%{service: "x", allow: :all, min_assurance: "L9000"}]

    assert_raise RuntimeError, ~r/invalid min_assurance/, fn ->
      ZtlpGateway.PolicyEngine.__validate_policies__!(bad)
    end
  end
end
```

**Step 2: Run — expect compile/test failures**

```bash
cd /home/trs/ztlp/gateway
mix test test/ztlp_gateway/policy_engine_test.exs 2>&1 | tail -25
```

Expected: `evaluate/3` undefined, internal validation function undefined.

**Step 3: Commit**

```bash
git add gateway/test/ztlp_gateway/policy_engine_test.exs
git commit -m "test(gateway): pin PolicyEngine.evaluate/3 contract (failing)

What: New describe block exercises evaluate/3 across the matrix of
pattern-pass/fail × assurance-pass/fail, plus the nil device-assurance
fallback and the startup validation guard.
Why: TDD for spec §5.3 and §5.4.
Tests: 7+1 tests FAIL — evaluate/3 and __validate_policies__! not
implemented.
Validation: \`mix test test/ztlp_gateway/policy_engine_test.exs\` shows
expected failures.
Follow-up: Task C2 implements the new functions."
```

### Task C2: Implement `evaluate/3` and rule storage upgrade

**Objective:** Apply spec §5.2 and §5.3 to `policy_engine.ex`.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/policy_engine.ex`

**Step 1:** Change the ETS storage form from `{service, allow}` to `{service, %{allow: allow, min_assurance: level}}`. Update `init/1`, `handle_call({:put_rule, …})`, and `handle_call({:delete_rule, …})`. Add a small shim so callers passing the old `put_rule(service, :all)` shape still work — wrap as `%{allow: :all, min_assurance: :software}`.

**Step 2:** Add `__validate_policies__!/1` that runs the validation extracted from `init/1` and raises on bad input. `init/1` calls this so the existing startup behavior is preserved.

**Step 3:** Add `evaluate/3,4` per spec §5.3. Keep `authorize?/2,3` working by reading the new map and falling back to the old boolean.

**Step 4:** Run the new tests.

```bash
cd /home/trs/ztlp/gateway
mix test test/ztlp_gateway/policy_engine_test.exs 2>&1 | tail -15
```

Expected: all green.

**Step 5: Run full gateway suite to catch regressions**

```bash
mix test 2>&1 | tail -10
```

Expected: zero failures. If any existing `authorize?/2,3` test fails, the shim missed a case — fix and re-run.

**Step 6: Commit**

```bash
git add gateway/lib/ztlp_gateway/policy_engine.ex
git commit -m "feat(gateway): PolicyEngine supports min_assurance

What: ETS row shape upgraded from {svc, allow} to {svc,
%{allow:, min_assurance:}}. New evaluate/3 returns a structured
decision map. authorize?/2,3 preserved as a boolean wrapper for
existing callers. __validate_policies__! extracted so YAML config
errors are caught at startup with a clear message.
Why: Spec §5.2, §5.3, §5.4.
Details: A rule with no min_assurance defaults to :software, matching
the spec's no-flag-day guarantee. A bare \`:all\` from legacy
put_rule/2 callers is still accepted via shim.
Tests: PolicyEngine test suite + new describe block all PASS; full
\`mix test\` clean.
Validation: Backward-compat: every existing test that calls
authorize?/2,3 still passes.
Follow-up: Task C3 surfaces device assurance from NS to the admission
path."
```

### Task C3: Failing test for `NsClient.resolve_device/1`

**Objective:** Pin the helper from spec §5.4 that resolves a peer's public key to `{name, assurance}`.

**Files:**
- Modify: `gateway/test/ztlp_gateway/ns_client_test.exs` (or create a focused test if the existing one is too coupled).

**Step 1:** Add a test that uses the existing NS mock (or test-only NS GenServer) to stash a DEVICE record carrying `assurance_level: "hardware_token"`, then calls `ZtlpGateway.NsClient.resolve_device/1` with that pubkey and expects `{:ok, %{name: …, assurance: :hardware_token}}`. Add a negative test for `:not_found`.

**Step 2: Run — expect failure** (`resolve_device/1` not yet defined).

**Step 3: Commit failing test.**

### Task C4: Implement `NsClient.resolve_device/1`

**Objective:** Spec §5.4.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/ns_client.ex`

**Step 1:** Locate the existing lookup-by-pubkey path (subagent reads the file and identifies the call NsClient already uses to map a static pubkey to a record). Wrap it as `resolve_device/1` returning `{:ok, %{name, assurance}} | :not_found`. The `assurance` is computed via `ZtlpNs.Record.device_assurance/1`.

**Step 2: Run** the new test plus the full gateway suite.

**Step 3: Commit.**

```bash
git commit -m "feat(gateway): NsClient.resolve_device/1 returns assurance

What: New helper resolves a peer's X25519 static pubkey to
{:ok, %{name:, assurance:}} or :not_found.
Why: Spec §5.4 — gateway admission needs the device's assurance from
NS to feed PolicyEngine.evaluate/3.
Details: Delegates to ZtlpNs.Record.device_assurance/1 for the
backward-compat fallback to :software.
Tests: New describe block in ns_client_test.exs PASS.
Validation: \`mix test\` clean.
Follow-up: Task C5 wires Session to use this."
```

### Task C5: Wire `Session` admission to call `evaluate/3` and emit the audit line

**Objective:** Spec §6 and §7.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/session.ex`
- Modify: `gateway/test/ztlp_gateway/session_test.exs` (or the existing session-test file)

**Step 1: Add the test FIRST** in the session test:
- Set a policy with `min_assurance: :attested`.
- Stash an NS DEVICE record for the test peer with `assurance: :software`.
- Run a session handshake (use existing test scaffolding).
- Assert the session is denied with the QUIC close code `0x2002` (or the equivalent atom the close path uses).
- Capture the gateway log output (via `ExUnit.CaptureLog`) and assert it matches:

```
~r/admission_decision device=\S+ service=\S+ assurance=software required_assurance=attested decision=deny reason=assurance_too_low session_id=[0-9a-f]+/
```

Add a parallel positive test:
- Policy `min_assurance: :software`, device `:software` → allow, log line shows `decision=allow reason=ok`.

**Step 2: Run — expect failure.**

**Step 3: Modify `Session` admission path** to:
- Call `NsClient.resolve_device/1` after handshake.
- Call `PolicyEngine.evaluate(name_or_pubkey, service, assurance)`.
- On `:allow`, proceed (existing path).
- On `:deny`, emit the audit-log line via `Logger.info/1` in the exact format from spec §7.2, then close the QUIC connection with the appropriate application error code (`0x2001` for `pattern_mismatch`, `0x2002` for `assurance_too_low`).
- Also emit the same line on `:allow`, with `decision=allow reason=ok`.

**Step 4: Run the new tests.**

```bash
cd /home/trs/ztlp/gateway
mix test test/ztlp_gateway/session_test.exs 2>&1 | tail -15
```

Expected: green.

**Step 5: Run full gateway suite.**

```bash
mix test 2>&1 | tail -10
```

Expected: zero failures.

**Step 6: Commit.**

```bash
git commit -m "feat(gateway): admission consults assurance level + audit log

What: Session.admission now resolves the peer's NS DEVICE record,
calls PolicyEngine.evaluate/3, and emits a canonical
'admission_decision …' Logger.info line for every allow and deny.
Deny on assurance closes the QUIC connection with application error
0x2002 (assurance_too_low); pattern denies still use 0x2001.
Why: Spec §6 (decision flow) and §7 (audit logging).
Details: Log line follows the spec §7.2 grammar exactly so external
scrapers can parse with a single regex. Allow lines emit
reason=ok so the field is always present for grep.
Tests: 2 new session tests PASS (allow + deny matrix cells).
Validation: Full \`mix test\` clean; existing admission tests still pass
because rules without min_assurance default to :software.
Follow-up: Phase D documents the YAML key and migrates fixtures."
```

---

## Phase D — Config, docs, and integration

### Task D1: Extend `gateway.yaml` schema parser

**Objective:** Spec §5.1 — accept `min_assurance` in gateway config YAML, validate, pass through to `PolicyEngine`.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/config.ex` (or wherever YAML policies are loaded)
- Modify: `gateway/config/gateway.yaml` (example, with comments — DO NOT change production defaults beyond adding the optional field)

**Step 1: Add a test** that loads a sample YAML with `min_assurance: hardware_token` on one rule and confirms the loaded policy list carries `:hardware_token` as the atom.

**Step 2: Add a negative test** — YAML with `min_assurance: bogus` causes config load to raise.

**Step 3:** Run — expect failure.

**Step 4: Implement the YAML parser change.** Parse the optional key, run it through `ZtlpNs.Assurance.from_string/1`, raise with a clear message on failure.

**Step 5: Update `gateway/config/gateway.yaml`** to add a commented example rule that demonstrates `min_assurance:` without changing any active rule's behavior.

**Step 6: Run tests, commit.**

```bash
git commit -m "feat(gateway): gateway.yaml accepts min_assurance per rule

What: Policy YAML loader accepts an optional min_assurance: key per
rule. Validates against ZtlpNs.Assurance.from_string/1 and raises on
unknown values during config load (no silent downgrade).
Why: Spec §5.1.
Details: Example rule added to gateway/config/gateway.yaml as a
comment. Existing rules unchanged — they default to :software.
Tests: 2 new config tests PASS (positive + negative).
Validation: \`mix test\` clean; \`iex -S mix\` boot succeeds.
Follow-up: D2 documents the field for operators."
```

### Task D2: Operator documentation

**Objective:** Make the new policy field visible to people writing gateway YAML and the new audit log line visible to people grepping logs.

**Files:**
- Modify: `docs/KEY-MANAGEMENT.md` (add a brief Assurance Levels subsection cross-referencing the spec)
- Modify: `docs/OPS-RUNBOOK.md` (add the audit log line shape under a new "Audit log: admission decisions" subsection)
- Create: `docs/ASSURANCE-LEVELS.md` — operator-facing summary of what the three levels mean today, what `min_assurance: hardware_token` does (denies until Step 2 ships), how to set per-service policies.

**Step 1: Write the doc files.** Keep them short — they reference `docs/ASSURANCE-LEVEL-SPEC.md` for the full protocol definition.

**Step 2: Verify markdown** renders cleanly (basic eyeball + no broken anchor links).

**Step 3: Commit.**

```bash
git add docs/KEY-MANAGEMENT.md docs/OPS-RUNBOOK.md docs/ASSURANCE-LEVELS.md
git commit -m "docs: operator guide for assurance levels (Step 1)

What: New docs/ASSURANCE-LEVELS.md plus subsections added to
KEY-MANAGEMENT.md (key-storage assurance) and OPS-RUNBOOK.md (audit
log line shape for admission decisions).
Why: Spec §1 (out-of-scope items are NOT documented as available);
operators need to know how to write min_assurance policy rules and
how to grep the new log line today.
Details: Software is the only level that produces ALLOW today.
hardware_token and attested are accepted by the parser but currently
deny because no enrollment flow can produce devices at those levels
yet. Doc states this explicitly.
Tests: N/A (docs).
Validation: Visual review of rendered markdown.
Follow-up: Step 2 will revise these to add hardware-token enrollment
instructions once PKCS#11 lands."
```

### Task D3: E2E integration test

**Objective:** Spec §9.4 — prove end-to-end that the policy gate works against a real bootstrap-issued software-key device.

**Files:**
- Add: `gateway/test/integration/assurance_admission_test.exs` (or extend an existing integration test file if one exists)

**Step 1: Write an integration test** that:
- Boots a minimal NS + gateway in the test app.
- Inserts a DEVICE record (signed by a test zone authority) with `assurance_level: "software"`.
- Configures one service `secure` with `min_assurance: hardware_token` and one service `wiki` with no `min_assurance`.
- Runs a session against `secure` and asserts deny + audit log line.
- Runs a session against `wiki` and asserts allow + audit log line.

**Step 2: Run the test.**

**Step 3: Commit.**

```bash
git commit -m "test(gateway): E2E assurance admission integration

What: New integration test boots NS + gateway, inserts a software-
keyed DEVICE record, and asserts (a) connection to a service
requiring hardware_token is denied with the expected audit log line
and QUIC close code, (b) connection to a default-policy service
succeeds.
Why: Spec §9.4 — proves the policy gate works end-to-end against a
real bootstrap-style device, today.
Tests: 2 new integration tests PASS.
Validation: Full \`mix test\` clean; this is the closest test we have
to a production deployment of Step 1.
Follow-up: Step 2 will extend this test with a hardware-token device
once PKCS#11 enrollment lands."
```

---

## Phase E — Wrap-up

### Task E1: CHANGELOG and version bump

**Objective:** Record Step 1 in the changelog and decide whether to cut a release tag.

**Files:**
- Modify: `CHANGELOG.md` (top-level)
- Modify: `proto/Cargo.toml` (`version =`)
- Modify: `ns/mix.exs` (`version:`)
- Modify: `gateway/mix.exs` (`version:`)

**Step 1: Decide version.** Recommend `0.31.0` (minor bump, schema feature added, no breaking changes). Confirm with Steve before bumping.

**Step 2: Bump versions in all three files** to the agreed value.

**Step 3: Run the `release_test.exs` runtime-vs-declared guards** per ztlp-development-guidelines (mix.exs version must match .app version after build).

```bash
(cd ns && mix test)
(cd gateway && mix test)
(cd proto && cargo test --release --no-fail-fast)
```

**Step 4: Update CHANGELOG.md** with a 0.31.0 entry summarizing the spec sections shipped.

**Step 5: Commit.**

```bash
git commit -m "chore(release): bump version to 0.31.0

What: Bumps proto/Cargo.toml, ns/mix.exs, gateway/mix.exs to 0.31.0
and adds the 0.31.0 entry to CHANGELOG.md.
Why: Step 1 of assurance-level rollout — adds AssuranceLevel schema
across proto + ns + gateway plus min_assurance policy and audit-log
plumbing. No breaking changes; existing deployments behave
identically until they opt into a min_assurance > software.
Details: Following the version-bump checklist from
ztlp-development-guidelines; release_test runtime-vs-declared guards
all pass.
Tests: Full proto, ns, gateway suites green.
Validation: \`cargo test --release --no-fail-fast\` in proto, \`mix
test\` in ns and gateway.
Follow-up: Tag once review approves."
```

### Task E2: Pre-PR review checklist

**Objective:** Before opening the PR, verify Steve's preferred quality gates.

**Step 1:** Run `cargo fmt` in `proto/`. Confirm clean.

**Step 2:** Run `cargo clippy --workspace --all-targets` in `proto/`. Address or document any new warnings.

**Step 3:** Run `mix format --check-formatted` in `ns/` and `gateway/`. Format if not clean.

**Step 4:** `git log feat/assurance-level-step1 ^main --oneline` — confirm the commit list is in the spec-phase order and the messages follow the What/Why/Details/Tests/Validation/Follow-up shape.

**Step 5:** Push branch and open PR with title `feat: assurance-level schema and policy plumbing (Step 1)` and body cross-referencing `docs/ASSURANCE-LEVEL-SPEC.md`.

**No commit.**

---

## Risk Register

- **CBOR encoder breaks signature stability on legacy records.** The regression test in Task B4 pins a hex of a fully-default DEVICE record. If `ZtlpNs.Cbor.encode/1` ever sorts keys differently, that test fails first and we know before any deployed records break. Mitigation is the test itself.
- **`PolicyEngine.put_rule/2` callers break with the new ETS row shape.** A shim is included in Task C2 specifically to absorb the old `:all` / `[strings]` form. The full gateway test run in C2 step 5 is the verification.
- **Audit log line format gets changed by a future contributor breaking external scrapers.** The session-test regex in C5 pins the line shape; any drift triggers test failure. Make sure that regex is treated as a wire contract in code review.
- **A subagent edits proto's `identity.rs` and breaks the existing `NodeIdentity::generate()` path.** Phase A only ADDS code; no existing symbols are touched. The full `cargo test --release --lib` in Task A2 step 5 is the guardrail.
- **YAML loader silently downgrades a malformed `min_assurance`.** The negative test in D1 step 2 specifically forbids this. Subagent must not "fix" the test by tolerating the malformed value.

---

## Verification at the End

Final acceptance for Step 1:

1. `cargo test --release --no-fail-fast` in `proto/` — green.
2. `mix test` in `ns/` — green.
3. `mix test` in `gateway/` — green.
4. Booting a gateway with the example YAML rule containing `min_assurance: hardware_token` and connecting from a CLI enrolled today (which produces software-keyed devices) produces a deny with QUIC error `0x2002` and an audit log line matching spec §7.2.
5. The same CLI connecting to a service with no `min_assurance` (or `software`) produces an allow with an audit log line matching spec §7.2.
6. An NS DEVICE record from before the change loads, validates, and is treated as `:software` by the gateway.

When all six pass, Step 1 is complete and ready for Step 2 (PKCS#11 hardware-token enrollment) to start.
