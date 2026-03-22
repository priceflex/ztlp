# mTLS Client Authentication Setup

This guide walks through setting up mutual TLS (mTLS) authentication
with ZTLP, enabling passwordless access to services protected by the
gateway.

## Overview

With mTLS, both the server and client present certificates during the
TLS handshake. The ZTLP gateway verifies the client's certificate
against the internal CA and extracts identity information for
downstream services.

## Step 1: Initialize the CA

```bash
ztlp admin ca-init --zone corp.ztlp
```

This creates:
- Root CA certificate and key
- Intermediate CA certificate and key
- Certificate registry

## Step 2: Trust the Root CA

### macOS

```bash
ztlp admin ca-export-root > ztlp-root.pem
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ztlp-root.pem
```

Or use the ZTLP agent:
```bash
ztlp trust install   # auto-detects OS and installs
```

### Linux

```bash
ztlp admin ca-export-root | \
  sudo tee /usr/local/share/ca-certificates/ztlp.crt
sudo update-ca-certificates
```

### Windows

```powershell
ztlp admin ca-export-root > ztlp-root.pem
Import-Certificate -FilePath ztlp-root.pem -CertStoreLocation Cert:\LocalMachine\Root
```

### Firefox

Firefox uses its own certificate store:
```bash
ztlp trust install --firefox
```
Or manually: Settings → Privacy & Security → View Certificates → Import

## Step 3: Enroll a Device

```bash
ztlp setup
```

This:
1. Generates a key pair (based on available hardware)
2. Requests a certificate from the NS
3. Installs the certificate and CA chain
4. Reports the assurance level

### Hardware Key Enrollment

For higher assurance, enroll with a hardware security key:

```bash
# YubiKey
ztlp setup --hardware-key

# This will:
# 1. Detect the YubiKey
# 2. Generate a key pair ON the YubiKey (never exported)
# 3. Request a certificate with assurance=hardware
# 4. Install the certificate referencing the hardware key
```

## Step 4: Configure the Gateway

Add TLS and backend configuration:

```yaml
# gateway.yml
tls:
  enabled: true
  port: 8443
  cert_file: /etc/ztlp/gateway.pem
  key_file: /etc/ztlp/gateway.key
  ca_cert_file: /etc/ztlp/ca.pem
  mtls_optional: true

  header_signing:
    enabled: true
    secret_env: ZTLP_HEADER_HMAC_SECRET

backends:
  - name: webapp
    host: 127.0.0.1
    port: 8080
    auth_mode: identity
    hostnames:
      - app.corp.ztlp
```

## Step 5: Test the Connection

```bash
# With curl
curl --cert ~/.ztlp/cert.pem --key ~/.ztlp/key \
  https://app.corp.ztlp:8443/

# Check the injected headers
curl --cert ~/.ztlp/cert.pem --key ~/.ztlp/key \
  https://app.corp.ztlp:8443/debug/headers
```

You should see the `X-ZTLP-*` headers in the response.

## Browser Configuration

### Chrome / Edge (Chromium)

Client certificates are auto-selected from the OS keychain. After
enrolling with `ztlp setup`, Chrome will prompt to select the
certificate when connecting to an mTLS-enabled service.

To auto-select without prompting, use Chrome enterprise policy:
```json
{
  "AutoSelectCertificateForUrls": [
    "{\"pattern\":\"*.corp.ztlp\",\"filter\":{\"ISSUER\":{\"O\":\"ZTLP\"}}}"
  ]
}
```

### Safari

Uses the macOS Keychain automatically. The certificate installed by
`ztlp setup` will be available for client authentication.

### Firefox

Firefox has its own certificate store. Import the client certificate:
```bash
ztlp trust install --firefox
```

## Verifying mTLS

```bash
# Check what certificate the gateway sees
ztlp status

# Shows:
#   Identity: steves-macbook.corp.ztlp
#   Assurance: hardware (YubiKey 5)
#   Certificate: expires 2026-06-20
#   Zone: corp.ztlp
```

## Troubleshooting

### Browser doesn't prompt for certificate
- Verify the root CA is trusted: `ztlp trust status`
- Verify the client cert is installed: `ztlp status`
- Check the gateway is requesting client certs (`mtls_optional: true`)

### "Certificate not trusted"
- Ensure the root CA is in the OS/browser trust store
- Run `ztlp trust install` to reinstall

### "Assurance level insufficient"
- The service requires a higher assurance level
- Re-enroll with: `ztlp setup --hardware-key`

### Certificate expired
- Run `ztlp renew` to request a new certificate
- Or re-enroll: `ztlp setup`

## See Also

- [TLS Architecture](TLS.md)
- [Internal CA](INTERNAL-CA.md)
- [Identity Headers](IDENTITY-HEADERS.md)
- [Passwordless Auth](PASSWORDLESS.md)
