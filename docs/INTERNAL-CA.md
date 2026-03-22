# Internal Certificate Authority

ZTLP includes a built-in Certificate Authority (CA) for issuing TLS
certificates within your network. This eliminates the need for external
CAs and enables automatic certificate management for all ZTLP services.

## Architecture

```
┌─────────────────────────────────────────┐
│           Root CA (offline ideal)        │
│  Key: Ed25519  |  Self-signed           │
│  Lifetime: 10 years  |  Rotate: manual  │
└──────────────┬──────────────────────────┘
               │ signs
┌──────────────▼──────────────────────────┐
│       Intermediate CA (online)           │
│  Key: Ed25519  |  Signed by Root        │
│  Lifetime: 1 year  |  Rotate: automatic │
└──────────────┬──────────────────────────┘
               │ signs
┌──────────────▼──────────────────────────┐
│        Leaf Certificates                 │
│  Server certs, client certs, node certs │
│  Lifetime: 90 days  |  Auto-renew       │
└─────────────────────────────────────────┘
```

## Key Management

### Root CA Key

- Generated during `ztlp admin ca-init`
- Stored in `~/.ztlp/ca/root.key`
- Should be backed up securely and ideally kept offline
- Only used to sign intermediate CA certificates
- Rotation: manual, rare (only if compromised)

### Intermediate CA Key

- Generated during `ztlp admin ca-init`
- Stored in `~/.ztlp/ca/intermediate.key`
- Used for day-to-day certificate issuance
- Rotation: `ztlp admin ca-rotate-intermediate`
- Old intermediate certs remain valid until expiry

### Leaf Certificate Keys

- Generated per-device during enrollment
- Stored according to assurance level:
  - **Software:** `~/.ztlp/key` (file)
  - **Device-bound:** OS keychain / TPM
  - **Hardware:** YubiKey / SmartCard (never exported)

## Trust Model

1. Devices trust the root CA certificate (installed during enrollment)
2. The gateway trusts the root CA for verifying client certificates
3. Backends trust the gateway's identity headers (via HMAC)
4. The NS signs certificates with the intermediate CA key
5. The intermediate CA is signed by the root CA

## Certificate Lifecycle

### Issuance

```bash
# Via CLI
ztlp admin cert-issue --hostname webapp.corp.ztlp --days 90

# Via Bootstrap UI
Navigate to Network → Certificates → Issue Certificate

# Automatic (during enrollment)
ztlp setup  # generates key, requests cert from NS
```

### Renewal

Certificates are automatically renewed by the ZTLP agent before expiry:
- Renewal starts 30 days before expiry
- The agent generates a new key pair
- The NS issues a new certificate
- The old certificate is kept until the new one is confirmed

### Revocation

```bash
# Via CLI
ztlp admin cert-revoke --serial ABC123 --reason key-compromise

# Via Bootstrap UI
Navigate to Network → Certificates → [cert] → Revoke
```

Revoked certificates are published via the gateway's CRL endpoint.
Clients and gateways check the CRL during TLS handshakes.

## File Layout

```
~/.ztlp/ca/
├── root.key              # Root CA private key
├── root.pem              # Root CA certificate (PEM)
├── intermediate.key      # Intermediate CA private key
├── intermediate.pem      # Intermediate CA certificate (PEM)
├── ca.json               # CA metadata (zone, keys, timestamps)
└── certs/
    ├── index.json        # Issued certificate registry
    ├── webapp_corp_ztlp.pem
    ├── webapp_corp_ztlp.key
    └── ...
```

## CLI Commands

```bash
# Initialize the CA
ztlp admin ca-init --zone corp.ztlp

# Show CA status
ztlp admin ca-show

# Export root cert for trust store installation
ztlp admin ca-export-root > ztlp-root.pem

# Rotate the intermediate CA
ztlp admin ca-rotate-intermediate

# Issue a certificate
ztlp admin cert-issue --hostname webapp.corp.ztlp --days 90

# List all certificates
ztlp admin cert-list

# Show certificate details
ztlp admin cert-show --serial ABC123

# Revoke a certificate
ztlp admin cert-revoke --serial ABC123 --reason key-compromise
```

## Security Considerations

1. **Protect the root key** — It's the trust anchor for everything.
   Back it up. Consider offline storage for production.
2. **Rotate intermediates regularly** — Even without compromise, periodic
   rotation limits the blast radius of a key compromise.
3. **Short-lived leaf certs** — 90-day default encourages automation
   and limits exposure from compromised leaf keys.
4. **Hardware keys for sensitive access** — Use `min_assurance: hardware`
   for admin panels and sensitive services.
5. **CRL distribution** — The gateway CRL server ensures revocations
   take effect immediately across the network.

## See Also

- [TLS Architecture](TLS.md)
- [mTLS Setup](MTLS-SETUP.md)
- [Passwordless Auth](PASSWORDLESS.md)
