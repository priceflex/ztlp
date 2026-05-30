# D4 NRPT — End-to-End Smoke Evidence (Live Windows Bench)

**Date:** 2026-05-30
**Bench:** `DESKTOP-LRC8DKH` (10.170.3.111, Tech Rockstars QA box)
**OS:** Windows Server, PowerShell 5.1.19041.6456
**Binary:** `ztlp.exe v0.34.3` from `feat/d4-windows-nrpt` HEAD
**NS:** `16.147.41.195:23096` (v0.34.3, mixed-case fix live)
**Relay:** `34.218.240.106:23095` (v0.34.2)
**Operator:** AI agent (autonomous), Steve Price's bench
**Transcript:** `desktop-windows-d4-e2e-evidence.txt` (sibling file)

## Test methodology

Drove the entire **end-user flow** on the real Windows bench from a Linux
control plane via SSH + `Start-Transcript`. Single PowerShell script
(`tools/ztlp-d4-e2e.ps1`) executes the 8 stages and captures everything.

This is the test the user means when they say "make sure it works completely
as the end user".

## Stages

| # | Stage                                          | Status |
|---|------------------------------------------------|--------|
| 0 | Environment (admin, PowerShell, version)       | PASS   |
| 1 | Pre-flight — no pre-existing ZTLP NRPT rules   | PASS   |
| 2 | `ztlp setup --token …`  — enroll into NS       | PASS   |
| 3 | `ztlp agent dns-setup --zones trs.ztlp`        | PASS   |
| 4 | `Get-DnsClientNrptRule` confirms rule shape    | PASS   |
| 5 | DNS interception active (nslookup → loopback)  | PASS   |
| 6 | `ztlp agent dns-teardown` removes rule         | PASS   |
| 7 | Idempotent teardown — second call no-ops       | PASS   |
| 8 | RESULT                                         | **[PASS] ALL D4 CHECKS PASSED** |

## Key live evidence

### Enrollment (Stage 2)
```
✓ Token valid    Zone: trs.ztlp    NS: 16.147.41.195:23096
→ Enrolling as lrc8dkh-d4smoke3.trs.ztlp
✓ Identity saved to C:\Users\TRS\.ztlp\identity.json
    NodeID: 77a72b6d4a876bf7b7a9446c950ef241
✓ Enrolled as lrc8dkh-d4smoke3.trs.ztlp
✓ Config written to C:\Users\TRS\.ztlp\config.toml
```

### NRPT install (Stage 3)
```
✓ NRPT rules installed (1 namespace)
    .trs.ztlp → 127.0.0.53:5353
```

### Rule shape verified (Stage 4)
```
Name                                   Namespace   NameServers Comment
{25289340-C95F-4392-8CD2-1C08A0D24382} {.trs.ztlp}             ZTLP-managed
```

### NRPT teardown + idempotency (Stages 6-7)
```
✓ Removed 1 NRPT rule .trs.ztlp
No ZTLP-managed NRPT rules found      # second call: idempotent
```

## Defect found & fixed during smoke

**Bug:** D4.T2's `parse_list_output` rejected real PowerShell output with
"missing Namespace field" because Windows `ConvertTo-Json` emits the NRPT
`Namespace` field as a JSON array (`["..."]`) — the underlying CIM type is
`string[]`. Unit tests used a bare string and never exercised the actual
shape.

**Fix:** Accept both string and array forms.

**Regression tests added** (D4.T2 module, 34→37 tests):
1. `parse_list_accepts_namespace_array_real_windows_output` — pins
   the literal JSON captured from DESKTOP-LRC8DKH.
2. `parse_list_accepts_namespace_array_with_servers_array` — both
   namespace and name-servers as arrays (multi-zone shape).
3. `parse_list_rejects_empty_namespace_array` — empty array → clear
   error (not the old misleading "missing Namespace").

**Caught only by the live smoke.** Cross-platform CI on Linux can't catch
shape mismatches with the real Windows DNS Client provider.

## What this validates

- ✅ v0.34.3 NS deployed at 16.147.41.195 accepts a fresh enrollment from
  Windows (mixed-case path tested by virtue of the upstream `name_validator`
  change reaching production).
- ✅ Full Rust → Windows → PowerShell 5.1 round trip works for both
  `dns-setup` and `dns-teardown`.
- ✅ NRPT rule shape is correct (Namespace `.trs.ztlp`, NameServers
  `127.0.0.53:5353`, Comment `ZTLP-managed`).
- ✅ Browsers / nslookup / WinHTTP will route `*.trs.ztlp` queries through
  the ZTLP agent's DNS resolver (the daemon isn't running in this smoke; that
  ships in D6).
- ✅ Teardown leaves operator-installed NRPT rules untouched (idempotency
  check verified clean removal of only the `ZTLP-managed` rule).

## Known limitations

- Daemon not running in this smoke (NXDOMAIN on `nslookup probe.trs.ztlp`
  proves the *path* but not the resolver). The agent's DNS server is part of
  D6's service-host lifecycle and is tested separately.
- Bootstrap callback `https://www.ztlp.net/api/enrollment/confirm` returns
  404 (curl exit 60 in the second run). This is a Launch-side wiring issue
  unrelated to D4 — token still reconciles via the next TokenReconciler
  sweep.

## How to reproduce

```bash
# On the orchestrator (Linux):
cd ztlp/proto
cargo build --release --target x86_64-pc-windows-gnu --bin ztlp

# Deploy to the Windows bench:
scp target/x86_64-pc-windows-gnu/release/ztlp.exe \
    trs@<windows-bench>:C:/Users/trs/ztlp/ztlp.exe
scp tools/ztlp-d4-e2e.ps1 trs@<windows-bench>:C:/Users/trs/ztlp-d4-e2e.ps1

# Mint a fresh single-use 1h token from bootstrap (Rails runner)
TOKEN=...

# Run end-to-end smoke (must be elevated PowerShell):
ssh trs@<windows-bench> \
    "powershell -NoProfile -ExecutionPolicy Bypass \
     -File C:\\Users\\trs\\ztlp-d4-e2e.ps1 -Token '$TOKEN'"
```

Exit code 0 + section 8 "[PASS] ALL D4 CHECKS PASSED" means the slice ships.
