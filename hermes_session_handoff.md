# Hermes Session Handoff — ZTLP End-to-End Stack Test

> **Active session:** 2026-05-19 — feature/ztlp-end-to-end-stack-test
> **Agent:** Hermes (google/gemini-3.1-pro-preview)
> **Operator:** Steve Price

---

## 1. Mission

Run a real end-to-end test of the entire ZTLP stack — public site → bootstrap →
enrollment → device-to-device communication — exactly like a human user would.

Validate the data model: **a user can have many devices; a device must be
registered before it can communicate; both device-to-device and
user-on-device communication must work over the ZTLP network.**

Bonus: clean up the bootstrap UX so next-steps are obvious.

---

## 2. Topology — Locked In

| Role | Host | Port | Notes |
|------|------|------|-------|
| **Public site (ztlp.net)** | runs on Nameserver host, behind ngrok at `www.ztlp.net` | 8080 → 443 | Python WSGI launch app |
| **Nameserver (NS)** | `35.91.88.177` | UDP 23096 | |
| **Relay** | `34.218.240.106` | UDP 23095 | |
| **Gateway** | `54.218.127.30` | UDP 23097 | gateway = "copy private key" device |
| **Windows user box** | `10.170.3.111` | — | Steve runs commands here |
| **Vaultwarden test app** | Gateway host | 8081 | ZTLP-only access |

---

## 3. Implementation Plan

### DONE Phase 1-4
- Ngrok branded at `www.ztlp.net`, Gateway repointed.

### DONE Phase 10: ztlp.net Public Security Audit
- Implemented STRICT input logic to prevent XSS payloads injected via ztlp.net.
- Refactored `app.py` request headers to rigorously enforce `https` protocols and strictly pass HSTS headers.

### DONE Phase 4c-4: Protocol-Aware Proxying, HTTP Injection
- Successfully refactored `session.ex` and `HttpHeaderInjector` to enforce Protocol Sniffing for Plain-ZTLP sessions bridging Vaultwarden over Gateway endpoints.
- Handled Identity injection mappings converting Noise primitives (`unknown:<hex>`) reliably to identity structs before header insertion. 
- Repaired `SniRouter` table crash when TLS proxies were skipped.

### PENDING Phase 8 + UX Testing
- Re-architect UI UX (Next-Step CTAs, labels, 1-click generation) - NEXT STEP!
- Ensure browser native connectivity inside Bootstrap for Vaultwarden apps uses HTTPS natively for `.ztlp`.

### PENDING Phase 11: Internal PKI
- Resolve `:ca_not_initialized` by properly configuring the internal CA.

---

## 4. Current State

| Component | Status | Note |
|-----------|---------|------|
| `ztlp-ns` | Healthy | Resolving `type 1` and `type 2` queries |
| `ztlp-relay` | Healthy | UDP tests clear |
| `ztlp-gateway` | Redeployed | Header injection and vault proxying validated |

---

## 5. Next Session Startup Plan
1. **Phase 11 (PKI):** Establish CA trust for Vaultwarden inside Nameserver PKI logic so Vaultwarden returns a local HTTPS connection.
2. Complete Phase 8 (UX checks on Bootstrap interface) by tunneling ZTLP over browser and auditing UI.
