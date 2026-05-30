# D5 CA Trust + On-Demand Cert Minting — End-to-End Smoke Evidence

**Date:** 2026-05-30
**Bench:** `DESKTOP-LRC8DKH` (10.170.3.111, Tech Rockstars QA box)
**OS:** Windows Server, PowerShell 5.1.19041.6456 (elevated)
**Binary:** `ztlp.exe v0.34.3` from `feat/d5-machine-ca-and-sni-minting` HEAD
**Operator:** AI agent (autonomous), Steve Price's bench
**Transcript:** `desktop-windows-d5-e2e-evidence.txt` (sibling file)

## What D5 ships

| Slice | Description |
|------|-------------|
| **D5.T2.0** | `ztlp admin ca-init` now generates a **real X.509 chain** (ECDSA P-256, 10-year validity, intermediate signed by root). The previous implementation wrote PEM frames containing only comments — not valid X.509 — which `certutil -addstore Root` rejected outright. |
| **D5.T2.b** | New module `agent::cert_mint` (21 unit tests). Loads the intermediate CA from disk and mints leaf certificates signed by it on demand. ECDSA P-256, 90-day validity, `serverAuth` EKU, `dns:` SAN only. |
| **D5.T2.c** | `agent::local_tls::SniCertResolver` extended with `with_mint_ca()` / `set_mint_ca()`. ClientHello miss → mint a fresh leaf → persist to disk → warm the cache. 5 new fallback-path tests. |
| **D5.T1** | `ztlp agent install-ca-cert` CLI subcommand with `--machine-scope`. Plants the root CA into `LocalMachine\Root` via `certutil -addstore -enterprise -f Root`. Companion `remove-ca-cert` uses **SHA1 thumbprint** as the cert selector. |

**Test count:** library suite 1043 → 1084 tests, all green.

## Test methodology

Drove all 9 stages on the real Windows bench from a Linux control plane via
SSH + `Start-Transcript`. Single PowerShell script (`tools/ztlp-d5-e2e.ps1`).

## Stages

| # | Stage | Result |
|---|-------|--------|
| 0 | Environment (admin, PS 5.1, ztlp 0.34.3) | PASS |
| 1 | Pre-flight clean (remove any prior CA + trust store entries) | PASS |
| 2 | `ztlp admin ca-init --zone trs.ztlp` (real X.509 generation) | PASS |
| 3 | Validate `root.pem` is real X.509 via `certutil -dump` | PASS |
| 3b | Validate `intermediate.pem` is real X.509, **issued by** ZTLP Root | PASS |
| 4 | `ztlp agent install-ca-cert --machine-scope` | PASS |
| 5 | Verify cert appears in `LocalMachine\Root` | PASS |
| 6 | `CurrentUser\Root` view (Windows mirrors machine certs) | INFO |
| 7 | `ztlp agent remove-ca-cert` | PASS |
| 8 | Verify cert is gone from `LocalMachine\Root` | PASS |
| 9 | RESULT | **[PASS] ALL D5 CHECKS PASSED** |

## Key live evidence

### Real X.509 chain (Stage 3-3b)

```
Root certificate:
  Subject:    O=ZTLP, CN=ZTLP Root CA - trs.ztlp
  Public Key: ECDSA_P256 (1.2.840.10045.3.1.7), 256 bits
  Validity:   5/30/2026 → 5/27/2036 (10 years)
  Signature:  sha256ECDSA

Intermediate certificate:
  Subject:    O=ZTLP, CN=ZTLP Intermediate CA - trs.ztlp
  Issuer:     O=ZTLP, CN=ZTLP Root CA - trs.ztlp        ← real chain
  Public Key: ECDSA_P256, 256 bits
  Signature:  sha256ECDSA
```

### Machine-scope install (Stage 4-5)

```
✓ ZTLP Root CA installed (machine-wide)

Subject                            Thumbprint                               NotAfter
-------                            ----------                               --------
O=ZTLP, CN=ZTLP Root CA - trs.ztlp 70AD2A12A7939EEFC7A99B06AA7FAB94A7119751 5/27/2036 4:15:29 PM
```

### Clean removal by thumbprint (Stage 7-8)

```
✓ ZTLP Root CA removed from trust store
[OK] machine-wide trust store is clean
```

## Defects found & fixed during the live smoke

This is the second consecutive D-slice where the live smoke caught real
defects the unit tests missed:

### Defect 1 — `ca-init` was writing stub PEM, not X.509

The previous `cmd_admin_ca_init` wrote files like:

```
-----BEGIN CERTIFICATE-----
# ZTLP Root CA for zone: trs.ztlp
# Generated: ...
# Key: <hex of an Ed25519 verifying key>
-----END CERTIFICATE-----
```

Not valid X.509. `certutil -addstore Root` rejected it. Browsers couldn't
validate any chain rooted at it. **Fixed** by replacing with rcgen-based
generation (ECDSA P-256, real DN, real validity, real signature; intermediate
is `signed_by(root)` not self-signed).

### Defect 2 — `remove-ca-cert` was a silent no-op when CN was zone-suffixed

The previous removal call was `certutil -delstore Root "ZTLP Root CA"` —
a CN substring match. Once `ca-init` started suffixing the CN with the zone
(`ZTLP Root CA - trs.ztlp`), the match still nominally "succeeded" (exit 0,
"command completed successfully") but found zero certs to delete. The cert
stayed installed.

**Fixed** by switching the selector to **SHA1 thumbprint** of the actual
cert file. The thumbprint is loaded from disk via PEM → DER → `Sha1::hash` →
uppercase hex (40 chars), then passed verbatim to certutil. Works regardless
of CN naming policy. Added two regression tests in `agent::ca_trust`.

### Defect 3 (false positive) — "cert also visible in CurrentUser\Root"

Initial smoke flagged this as a warning. **Diagnosed as expected Windows
behavior**: `Cert:\CurrentUser\Root` is a *blended view* that includes all
certs from `LocalMachine\Root` plus actual per-user entries. A machine-scope
install legitimately shows up in both views. The test now treats this as
informational.

## What this validates

- ✅ Real X.509 generation works end-to-end on Windows
- ✅ Intermediate CA is genuinely signed by root (not self-signed at intermediate level)
- ✅ Machine-wide trust store install lands in `LocalMachine\Root`
- ✅ Cert can be cleanly removed by thumbprint, regardless of CN format
- ✅ Idempotency: re-running install on a clean store works; re-running remove
  on an already-clean store doesn't error

## What's NOT in this PR (deferred follow-ups)

- **D5.T1.c — service installer auto-call**: The Windows service installer
  (`ztlp-service install`) should invoke `ztlp agent install-ca-cert --machine-scope`
  during install. Trivial wiring on top of this PR.
- **Browser green-lock validation**: Requires the agent daemon to be running
  and a real ZTLP service to terminate TLS on. D6 territory.

## How to reproduce

```bash
# On the orchestrator (Linux):
cd ztlp/proto
cargo build --release --target x86_64-pc-windows-gnu --bin ztlp

# Deploy to the Windows bench:
scp target/x86_64-pc-windows-gnu/release/ztlp.exe \
    trs@<windows-bench>:C:/Users/trs/ztlp/ztlp.exe
scp tools/ztlp-d5-e2e.ps1 trs@<windows-bench>:C:/Users/trs/ztlp-d5-e2e.ps1

# Run E2E smoke (must be elevated PowerShell):
ssh trs@<windows-bench> \
    "powershell -NoProfile -ExecutionPolicy Bypass \
     -File C:\\Users\\trs\\ztlp-d5-e2e.ps1"
```

Exit code 0 + section 9 "[PASS] ALL D5 CHECKS PASSED" means the slice ships.
