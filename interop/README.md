# ZTLP Cross-Language Interop Test

Proves that Rust ZTLP clients and the Elixir relay node interoperate
correctly over real UDP sockets.

## What It Tests

| # | Test | Description |
|---|------|-------------|
| 1 | Data A→B | Compact data packet forwarded from Node A through relay to Node B |
| 2 | Data B→A | Reverse direction — Node B sends through relay to Node A |
| 3 | Handshake format | Handshake-format packet (non-HELLO MsgType) forwarded through relay |
| 4 | 10-packet burst | 10 sequential data packets forwarded A→B, all verified |
| 5 | Wrong SessionID | Packet with unregistered SessionID is correctly dropped by relay |

## How It Works

```
┌───────────────────────────────────────────────────────┐
│  run_test.sh                                          │
│                                                       │
│  1. Compiles Elixir relay + Rust test binary          │
│  2. Calls orchestrate.py                              │
│     ├── Starts relay_server.exs (Elixir process)      │
│     │   └── Prints "READY <port>" to stdout           │
│     ├── Starts ztlp-interop-test (Rust binary)        │
│     │   └── Prints "PORTS <a> <b> <sid>" to stdout    │
│     ├── Sends "REGISTER <sid> <a> <b>" to relay stdin │
│     │   └── Relay responds "OK <sid>"                 │
│     ├── Sends "SESSION_REGISTERED" to Rust stdin      │
│     │   └── Rust runs 5 tests over UDP                │
│     └── Reports pass/fail based on exit code          │
└───────────────────────────────────────────────────────┘
```

The Elixir relay and Rust nodes communicate over real UDP on localhost.
The relay forwards packets by SessionID — it never sees plaintext.

## Prerequisites

- **Rust** — toolchain installed (`rustc`, `cargo`)
- **Elixir 1.12+** and **Erlang/OTP 24+** — with the relay already compiled
- **Python 3** — for the orchestration script

## Running

From the project root (`ztlp/`):

```bash
# Compile the relay first (one-time)
cd relay && mix compile && cd ..

# Run the interop test
bash interop/run_test.sh
```

Expected output:
```
╔══════════════════════════════════════════════════════════════╗
║     ZTLP Cross-Language Interop Test                        ║
║     Rust clients ↔ Elixir relay over real UDP               ║
╚══════════════════════════════════════════════════════════════╝

━━━ Compiling ━━━
  ✓ Both projects compiled

━━━ Starting Elixir relay ━━━
  Relay listening on port 56014
  ✓ Relay running

━━━ Registering session ━━━
  ✓ Session registered with relay

━━━ Running tests ━━━
  [interop] Test 1: Data packet A → Relay → B
  [interop]   ✓ B received exact packet from relay (61 bytes)
  [interop] Test 2: Data packet B → Relay → A
  [interop]   ✓ A received exact packet from relay (61 bytes)
  [interop] Test 3: Handshake-format packet (MsgType::Data) A → Relay → B
  [interop]   ✓ B received handshake-format packet from relay (100 bytes)
  [interop] Test 4: 10 sequential packets A → B through relay
  [interop]   ✓ All 10 packets forwarded correctly
  [interop] Test 5: Packet with wrong SessionID not forwarded
  [interop]   ✓ B correctly received nothing (wrong SessionID dropped)
  [interop] Results: 5 passed, 0 failed

  ✓ INTEROP TEST PASSED
```

## Files

| File | Language | Description |
|------|----------|-------------|
| `run_test.sh` | Bash | Entry point — compiles both projects, calls orchestrator |
| `orchestrate.py` | Python | Manages Elixir + Rust subprocess lifecycle |
| `relay_server.exs` | Elixir | Starts the relay, accepts `REGISTER` commands via stdin |
| `README.md` | — | This file |

The Rust test binary lives at `proto/src/bin/ztlp-interop-test.rs`.

## Troubleshooting

**"relay not compiled"** — Run `cd relay && mix compile` first.

**Test timeouts** — Each packet wait has a 2-second timeout. If the relay
is slow to start, increase the delay in `orchestrate.py`.

**Port conflicts** — All sockets use port 0 (random ephemeral). Conflicts
should not occur.
