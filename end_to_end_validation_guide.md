# ZTLP End-to-End Validation Guide

This guide provides the exact steps to manually validate the complete ZTLP stack, including the newly implemented protocol sniffer, XSS protections, PKI generation, and the re-architected Bootstrap UX.

## 1. Environment Topology

The infrastructure is actively running on the 3 AWS servers using your provided RSA key (`~/ztlp/.ssh/ztlp_aws_key`).

*   **Nameserver and Launch App (ztlp.net):** `ubuntu@35.91.88.177`
    *   Runs `ztlp-ns` (UDP 23096), `ztlp-launch` (TCP 8080), and dynamically generated Bootstrap containers.
*   **Relay:** `ubuntu@34.218.240.106`
    *   Runs `ztlp-relay` (UDP 23095).
*   **Gateway and Vaultwarden:** `ubuntu@54.218.127.30`
    *   Runs `ztlp-gateway` (UDP 23097) handling protocol sniffing, and `vaultwarden` (TCP 8081).

---

## 2. Validation Steps

### Step 1: Validate the Public Site and Enrollment (ztlp.net)
1. You can access the public onboarding app via the ngrok URL (if you are running the `ngrok` container) or directly via HTTP on the NS host:
   ```bash
   # From your local machine:
   ssh -i ~/ztlp/.ssh/ztlp_aws_key -N -L 8080:127.0.0.1:8080 ubuntu@35.91.88.177
   ```
2. Open your browser to `http://localhost:8080` (or your ngrok URL).
3. Fill out the onboarding form. You will see that **strict sanitization** is now enforced (Phase 10). If accessing via HTTPS (ngrok), HSTS headers are strictly enforced. 
4. Upon submitting, you will be given a claim link. Follow it to provision the network and generate your `ztlp setup` string.

### Step 2: Validate the Bootstrap UI and UX Changes (Phase 8)
When a bootstrap instance spins up (like `techrockstars.ztlp` or `trsalpha.ztlp`), it runs a Rails interface on `127.0.0.1:<dynamic_port>` on the NS host.

1. Create a local SSH tunnel to the Bootstrap port (for `trsalpha`, it's `39538`):
   ```bash
   ssh -i ~/ztlp/.ssh/ztlp_aws_key -N -L 3001:127.0.0.1:39538 ubuntu@35.91.88.177
   ```
2. Navigate your browser to: `http://localhost:3001`
3. Log in with `hermes@techrockstars.com` / `password`.
4. Go to **Networks**. You will see the newly implemented UX empty state, which clearly delineates the difference between infrastructure **Machines** and endpoint **Devices**, removing previous confusion on next-steps.

### Step 3: Validate PKI and Gateway Mappings (Phase 11)
The NS server (`35.91.88.177`) has been configured with `ZTLP_CA_AUTO_INIT=true`. 
The `ztlp-gateway` on `54.218.127.30` has automatically communicated with the NS, fetched the CA root, and provisioned a signed ZTLP Service Certificate for Vaultwarden.

1. SSH into the Gateway host and verify the logs for successful PKI issuance:
   ```bash
   ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@54.218.127.30
   docker logs ztlp-gateway | grep -E "CertProvisioner|ServiceRegistrar"
   ```
   *Expect to see: `[CertProvisioner] Cert issued for vault.techrockstars.ztlp`*.

### Step 4: Validate Protocol Sniffing and Vaultwarden Access (Phase 4c-4)
The newly written protocol sniffer actively evaluates incoming Zero Trust traffic. If it detects HTTP signatures over plain ZTLP, it injects strictly formatted `X-ZTLP-*` identity headers into the first chunk dynamically.

1. From your local testing machine, start the ZTLP tunnel. We will leverage `vault.techrockstars.ztlp` (which routes to `54.218.127.30`).
   ```bash
   ~/ztlp/target/debug/ztlp connect vault.techrockstars.ztlp \
       --key ~/.ztlp/identity.json \
       --ns-server 35.91.88.177:23096 \
       --service vault \
       -L 8093:127.0.0.1:80
   ```
2. The tunnel will establish. In another terminal or browser, hit your local port `8093`:
   ```bash
   curl -I http://127.0.0.1:8093
   ```
3. You will receive a successful `200 OK` response from Vaultwarden, confirming that the ZTLP connection succeeded, the Gateway correctly deciphered the generic TCP traffic as HTTP, and subsequently authenticated the pass-through connection to the backend.

---

## 3. Operations Performed (for Reference)

All code modifications are merged and pushed to GitHub under `feature/ztlp-end-to-end-stack-test`.

*   **`ztlp.net/launch_app/app.py`**: Added parameter scrubbing and HTTPS scheme validations.
*   **`gateway/lib/ztlp_gateway/session.ex`**: Migrated stream tracking to handle `first_chunk: true` mappings. Overhauled proxy routing to execute Protocol Sniffing natively over `FRAME_DATA`.
*   **`gateway/lib/ztlp_gateway/http_header_injector.ex`**: Built regex HTTP sniffing patterns (`GET, POST,...`) and a mapping layer to construct Identity headers from plain Noise Hex IDs, fixing `SniRouter` lookup crashes.
*   **`app/views/networks/index.html.erb` (Bootstrap)**: Integrated clear textual instruction panes outlining Machine vs Device differences. 
