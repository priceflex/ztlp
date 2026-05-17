# ztlp.net Docker Orchestration

This folder contains the scaffolding tools for spawning independent ZTLP Tenant architectures (Namespace Server, Relay, Gateway, Bootstrap UI) on an isolated Docker network dynamically.

## Files
- `provision_tenant.sh`: Run this to instantiate a tenant stack.

## Architecture
Each spawned stack acts as its own autonomous ZTLP overlay zone:
1. **Namespace Server (NS)**: Retains identity bindings on an isolated virtual volume.
2. **Relay**: Retains routing parameters between authenticated devices within that tenant's zone.
3. **Gateway**: Decrypts ZTLP packets arriving from verified devices and passes the HTTP connections onto the internal Bootstrap container using `X-ZTLP-*` cryptographic identity headers.
4. **Bootstrap**: The Management UI framework, accessible *only* via the authenticated Gateway.
