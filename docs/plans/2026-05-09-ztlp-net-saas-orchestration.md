# ztlp.net SaaS Tenant Orchestration Plan

This document outlines the architecture, requirements, and checklist for the automated provisioning of ZTLP environments via `ztlp.net`.

## Goal
A user visits `ztlp.net`, enters their Name and Email, and a pristine, isolated ZTLP tenant environment (Namespace Server, Relay, Gateway, and Bootstrap UI) is automatically spun up behind ZTLP identity-enforced access.

---

## 1. Components of a "Tenant Stack"
Every new tenant gets an isolated Docker Compose stack. The Orchestrator creates a folder (e.g., `/opt/ztlp/tenants/acme-corp`) and templates the following:

- **ZTLP Namespace Server (NS):**
  - Mnesia DB initialized.
  - Root `Ed25519` Zone Key generated and injected.
  - Initial 1-hour `Admin Enrollment Token` injected.
- **ZTLP Relay:**
  - Bound to the NS. Provides UDP hole-punching and routing for the tenant.
- **ZTLP Gateway:**
  - Decrypts traffic meant for the internal Bootstrap UI.
  - **Crucial:** Injects `X-ZTLP-User` and `X-ZTLP-Signature` headers to provide seamless, passwordless login to the Bootstrap UI.
- **Rails Bootstrap UI:**
  - The management interface, restricted so it only accepts traffic from the Gateway's local proxy.
  - Seeded with the super-admin's initial user record.

---

## 2. The Identity Handoff Flow (Option B: URI-based)
1. **User Submits Form** (`ztlp.net`)
2. **Backend Orchestrator** generates the stack and keys.
3. User receives a magical link: `ztlp://enroll/?zone=acme.ztlp&ns=1.2.3.4:10001&token=XYZ_123`
4. User clicks link → Windows/macOS Desktop App opens.
5. **Client-Side Keygen:** The App generates strong hardware-bound keys *locally*.
6. **Enrollment (0x07):** The App connects to the new NS (`1.2.3.4:10001`), presents `token=XYZ_123`, and deposits its public key.
7. The NS validates the token, accepts the key, and marks the token as used. The user is now the sole Admin.

---

## 3. Implementation Checklist

### Phase 1: Orchestrator Scaffolding (Bash / Docker templating)
- [x] Create the `tenant_template/` directory structure containing the base `docker-compose.yml` for a tenant.
- [x] Write `provision_tenant.sh` script to allocate host UDP/TCP ports for the tenant (e.g., NS = 23001, Gateway = 23002).
- [x] Automatically spawn the stack via `docker compose up -d` after scaffolding keys.

### Phase 2: Gateway Identity Header Injection
- [x] Ensure the ZTLP Gateway has `ZTLP_HEADER_HMAC_SECRET` configured for the tenant.
- [x] Verify that `ZtlpGateway.HttpHeaderInjector` is active and passing the authenticated user's email inside the `X-ZTLP-User` HTTP header.

### Phase 3: Bootstrap Passwordless Auth 
- [x] Modify the Rails Bootstrap App `ApplicationController`.
- [x] Read the `X-ZTLP-User` and `X-ZTLP-Signature` headers.
- [x] If present and signature is valid (matching `BOOTSTRAP_HMAC_SECRET`), automatically find or create the `ZtlpUser` and log them in as Super Admin.
- [x] Bypass the standard OmniAuth/Username login screens entirely when these headers hit.

### Phase 4: Desktop App Polish (Windows)
- [x] Ensure the Desktop app cleanly intercepts OS-level `ztlp://...` URI clicks.
- [x] Verify the UI correctly triggers the `process_enrollment` Rust FFI to spend the token against the NS.
