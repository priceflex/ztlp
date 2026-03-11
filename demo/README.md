# ZTLP Demos

## SSH Tunnel Demo

Interactive demo showing SSH protected behind ZTLP — keygen, NS registration, encrypted tunnel, and live SSH session.

### Quick Start

```bash
# Download the latest ztlp binary
# https://github.com/priceflex/ztlp/releases

# Run the demo (requires SSH server on localhost:22)
./ssh-tunnel-demo.sh

# Skip NS registration (use raw IP instead of name)
./ssh-tunnel-demo.sh --skip-ns

# Custom settings
SSH_USER=steve SSH_PORT=22 LISTEN_PORT=23095 ./ssh-tunnel-demo.sh

# Cleanup
./ssh-tunnel-demo.sh --cleanup
```

### What It Does

```
┌──────────────┐         ┌─────────────────┐         ┌──────────────┐
│   ssh client │  TCP    │    ZTLP tunnel   │  TCP    │  SSH server  │
│              │────────▶│                  │────────▶│              │
│ localhost:   │         │  Noise_XX E2E    │         │ localhost:22 │
│    2222      │         │  ChaCha20-Poly   │         │              │
└──────────────┘         └─────────────────┘         └──────────────┘
                          Port 23095 only
                          19ns reject for
                          unauthorized pkts
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTLP_BIN` | `ztlp` | Path to ztlp binary |
| `NS_SERVER` | `127.0.0.1:5353` | ZTLP-NS server address |
| `LISTEN_PORT` | `23095` | ZTLP listener port |
| `TUNNEL_LOCAL_PORT` | `2222` | Local SSH tunnel port |
| `SSH_PORT` | `22` | Target SSH server port |
| `SSH_USER` | `$(whoami)` | SSH username |
| `DEMO_DIR` | `/tmp/ztlp-demo` | Directory for demo artifacts |
