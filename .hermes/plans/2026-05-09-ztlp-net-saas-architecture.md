# ZTLP.net SaaS Onboarding Architecture

## Objective
Create a true Zero-Trust SaaS onboarding flow. Users register on `ztlp.net`, a dedicated tenant infrastructure is spun up, and the user accesses their management panel strictly via a passwordless ZTLP tunnel.

## The UX Flow
1. **Registration:** User visits public `ztlp.net`, enters Name and Email. No password required.
2. **Provisioning:** The orchestrator spins up a dedicated Docker Compose stack (NS, Gateway, Relay, Bootstrap UX) for this tenant.
3. **Delivery:** The user is provided the Desktop App and a one-time onboarding link/file.
4. **Ingestion:** The Desktop App ingests the identity, encrypts it locally (e.g., DPAPI on Windows / Keychain on macOS), and deletes the downloaded file.
5. **Passwordless Access:** The user opens the management UI (`http://manage.internal.ztlp`). The Gateway authenticates the ZTLP session and injects identity headers into the Rails app.
6. **Auto-Login:** The Rails Bootstrap app reads the headers and logs the user in as Super Admin automatically.

## Cryptographic Handoff (The Pre-shared Identity)
There are two ways to achieve the initial administrator bootstrap:

**Method A: Server-Generated Identity (The "VPN Profile" approach)**
- The `ztlp.net` server generates the X25519 and Ed25519 keypairs.
- It bakes them into a `setup.ztlp` JSON file alongside the NS/Relay IPs.
- The user downloads this file and drops it into the Desktop App.
- **Pros:** Instant, exact match to Steve's vision.
- **Cons:** Private keys touch the TLS wire.

**Method B: Client-Generated Identity (The "Secure Token" approach)**
- The `ztlp.net` server generates a one-time `ztlp://enroll/?...` URI or short text token.
- The user pastes this into the Desktop App.
- The App generates hardware-bound keys *locally* and simply uses the token to authorize the registration of its public key with the new NS.
- **Pros:** Private keys never leave the endpoint (purist zero-trust).
- **Cons:** Requires the NS to accept a one-time registration token.

*Recommendation:* Go with **Method B**, but wrap it in a seamless UX (e.g., clicking the link automatically opens the ZTLP Desktop app and does the exchange in the background).

## Required Engineering Steps

### 1. ZtlpGateway Header Injection
The Gateway must be configured to inject cryptographic identity headers into the proxied TCP stream.
- Enable `ZTLP_HEADER_HMAC_SECRET`.
- Gateway injects `X-ZTLP-User: email@domain.com` and `X-ZTLP-Signature: <HMAC>` on every HTTP request sent to the Bootstrap backend.

### 2. Passwordless Rails Bootstrap
The `Bootstrap` Rails app must be modified to trust these headers.
- Deprecate standard password login for the owner.
- Add `ApplicationController` logic: If `X-ZTLP-User` and a valid `X-ZTLP-Signature` are present, automatically find or create the `ZtlpUser` and establish the Rails session.

### 3. ZTLP.net Orchestrator
A new lightweight web service (can be Rails or Elixir) whose sole job is orchestration:
- Accepts Name/Email.
- Uses Docker API / Kubernetes to spawn the tenant's isolated network.
- Generates the root Zone keys.
- Seeds the tenant's NS with the Root Key.
- Generates the initial Admin Enrollment token.
- Returns the Token / App download links to the user.