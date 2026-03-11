# ZTLP Demos

## SSH Tunnel Demo (Security Showcase)

An interactive demonstration of how ZTLP hides an SSH service behind a single, encrypted port.  The demo walks through cryptographic identity creation, optional ZTLP-NS registration, establishing a ZTLP listener that forwards to a local SSH daemon, opening a client-side tunnel, and finally connecting via SSH.

In addition to the core workflow, the demo includes throughput benchmarking and simulated attacker actions:

- **Throughput Saturation** – SCP file transfers (10/50/100 MB) through the ZTLP tunnel vs direct SSH. Shows Mbps throughput and encryption overhead percentage.
- **Port Scan** – shows the SSH port is invisible while the ZTLP port is the only exposed service.
- **UDP Packet Flood** – sends thousands of random UDP packets to the ZTLP port; they are rejected in ~19 ns at L1 (magic‑byte check).
- **Malformed ZTLP Packets** – packets with a correct magic header but bogus SessionIDs are rejected at L2 (session verification).
- **tcpdump Capture** – optionally records the traffic on the ZTLP port, demonstrating that payloads are encrypted.
- **CPU Monitoring** – measures the CPU overhead during the flood, showing the cheap cost of rejection.
- **Final Summary** – compares traditional SSH exposure versus the ZTLP‑protected setup with statistics from all tests.

### Quick Start

```bash
# Download the latest ztlp binary
# https://github.com/priceflex/ztlp/releases

# Run the demo (requires an SSH server on localhost:22)
./ssh-tunnel-demo.sh

# Skip NS registration (use raw IP instead of name)
./ssh-tunnel-demo.sh --skip-ns

# Custom settings (override via env vars)
SSH_USER=steve SSH_PORT=22 LISTEN_PORT=23095 ./ssh-tunnel-demo.sh

# Cleanup demo artifacts
./ssh-tunnel-demo.sh --cleanup
```

### What It Does

```
┌─────────────┐         ┌────────────────┐         ┌────────────┐
│   ssh client │  TCP    │    ZTLP tunnel   │  TCP    │  SSH server  │
│              │───────▶│                  │───────▶│              │
│ localhost:   │         │  Noise_XX E2E    │         │ localhost:22 │
│    2222      │         │  ChaCha20-Poly   │         │              │
└─────────────┘         └────────────────┘         └────────────┘
                          Port 23095 only
                          19ns reject for unauthorized packets
```

### Environment Variables

| Variable   | Default                | Description |
|------------|------------------------|-------------|
| `ZTLP_BIN` | `ztlp`                 | Path to the `ztlp` binary |
| `NS_SERVER`| `127.0.0.1:5353`       | ZTLP-NS server address |
| `LISTEN_PORT`| `23095`               | ZTLP listener port |
| `TUNNEL_LOCAL_PORT`| `2222`          | Local port for the SSH tunnel |
| `SSH_PORT` | `22`                    | Target SSH server port |
| `SSH_USER` | `$(whoami)`            | Username for SSH connection |
| `DEMO_DIR` | `/tmp/ztlp-demo`       | Directory for demo artifacts |

The demo is safe to run on a local machine - it never makes destructive changes to the system and all traffic stays on `localhost`.
