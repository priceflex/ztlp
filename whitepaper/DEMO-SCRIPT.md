# ZTLP Demo Video Script

## Overview

**Format:** Terminal recording (asciinema) with voiceover narration
**Duration:** 5–6 minutes
**Audience:** CISOs, security engineers, conference attendees who've read (or skimmed) the whitepaper
**Goal:** Show ZTLP is real, working software — not vaporware. Demonstrate identity-first networking, DDoS rejection, namespace resolution, and end-to-end encrypted SSH tunneling through a relay.

**Recording setup:**
```bash
# Install asciinema
pip install asciinema

# Record with a clean terminal (120x30 for readability)
asciinema rec ztlp-demo.cast -c bash --cols 120 --rows 30

# After recording, replay or upload
asciinema play ztlp-demo.cast
asciinema upload ztlp-demo.cast
```

**Terminal prep:**
- Clean prompt: `export PS1='\[\e[1;36m\]ztlp-demo\[\e[0m\] $ '`
- Large font (16–18pt) for video clarity
- Dark background, light text
- Pre-build all binaries so there's no compile wait on camera

---

## Act 1 — Identity (0:00–0:45)

> **Narration:** "In ZTLP, identity comes before connectivity. Before you can talk to anything on the network, you need to prove who you are. Let's start by generating identities."

```bash
# Generate identities for Alice and Bob
ztlp keygen --output alice.json
ztlp keygen --output bob.json
cat alice.json | jq .
```

> **Narration:** "That's a ZTLP identity — a 128-bit NodeID bound to X25519 and Ed25519 key pairs. The NodeID is your address on the network. It's not tied to an IP, a MAC address, or a hostname. It's purely cryptographic."

**[Pause — ~2 seconds of clean terminal before next act]**

---

## Act 2 — Direct Encrypted Session (0:45–1:45)

> **Narration:** "The simplest ZTLP scenario: a direct connection between two nodes. Bob listens, Alice connects. They perform a Noise_XX handshake — three messages, mutual authentication, forward secrecy — and then they can exchange encrypted data."

**Terminal 1 (split screen — left: Bob):**
```bash
# Bob listens for incoming connections
ztlp listen --key bob.json --bind 0.0.0.0:23095
```

> Output:
> ```
> Bound to: 0.0.0.0:23095
> Waiting for connections...
> ```

**Terminal 2 (split screen — right: Alice):**
```bash
# Alice connects to Bob
ztlp connect 127.0.0.1:23095 --key alice.json
```

> Output:
> ```
> Connecting to 127.0.0.1:23095...
> Noise_XX handshake:
>   → HELLO (ephemeral key)
>   ← CHALLENGE (ephemeral + static)
>   → AUTH (static + proof)
> ✓ Session established
>   Remote NodeID: b7f2a3...
>   Session ID:    a1c9e4f802b3d7...
>   Handshake:     287 µs
>   Cipher:        ChaChaPoly
> ```

> **Narration:** "287 microseconds — that's the full Noise_XX handshake. Both sides proved their identity. Neither trusts the other based on IP address. Every packet from here on is encrypted with ChaCha20-Poly1305, authenticated, and replay-protected."

**Type messages back and forth:**

Alice types: `Hello from Alice — this is end-to-end encrypted`
Bob sees:    `[a4e1f0...] Hello from Alice — this is end-to-end encrypted`

Bob types:   `Received. Nobody between us can read this.`
Alice sees:  `[b7f2a3...] Received. Nobody between us can read this.`

> **Narration:** "End-to-end encrypted. No certificate authority, no TLS handshake, no PKI infrastructure. Just two identities, a Noise handshake, and a symmetric session."

**[Ctrl+C both sides]**

---

## Act 3 — The Pipeline: Rejecting Bad Traffic (1:45–2:45)

> **Narration:** "Now here's the part that matters for DDoS defense. Let's start a relay and watch what happens when unauthorized traffic hits it."

```bash
# Start a relay
ztlp relay start --bind 0.0.0.0:23095 --max-sessions 1000
```

> Output:
> ```
> ZTLP Relay started on 0.0.0.0:23095
>   Max sessions: 1000
>   Pipeline: L1 Magic → L2 SessionID → L3 AuthTag
> ```

> **Narration:** "The relay is running the three-layer admission pipeline. Let's throw some garbage at it."

```bash
# Send random garbage — rejected at Layer 1 (no ZTLP magic)
echo "deadbeef0000000000000000" | xxd -r -p | nc -u -w1 127.0.0.1 23095
```

> **Narration:** "Random bytes — no ZTLP magic header. Rejected at Layer 1 in about 19 nanoseconds. The relay spent effectively zero CPU on that."

```bash
# Quantify it with the load generator
ztlp-load pipeline --packets 1000000 --sessions 1000
```

> Output:
> ```
> ZTLP Pipeline Benchmark
> ========================
> Sessions in table: 1,000
> Packets generated: 1,000,000
>
> Results:
>   L1 reject (bad magic):       18.7 ns/pkt   53,475,936 pps
>   L2 reject (unknown session): 30.9 ns/pkt   32,362,460 pps
>   Full pipeline (valid):      876.2 ns/pkt    1,141,320 pps
>
> Cost ratio: Reject is 47× cheaper than admit
> ```

> **Narration:** "53 million rejects per second at Layer 1. On a single core. That's the structural advantage — attackers pay bandwidth, defenders pay nanoseconds. An attacker would need to guess a valid 96-bit SessionID just to reach the crypto layer. That's a 1-in-2^96 chance per packet."

**[Pause — let the numbers sink in]**

---

## Act 4 — Namespace Registration & Resolution (2:45–3:45)

> **Narration:** "Raw IP addresses don't scale. ZTLP-NS is a cryptographically signed namespace — think DNS, but every record is signed and only the record owner can update it. Let's register Bob's identity."

```bash
# Start the ZTLP-NS server (in background or separate pane)
# (Already running if using Docker compose)

# Register Bob's identity + endpoint address
ztlp ns register \
    --name bob.demo.ztlp \
    --zone demo.ztlp \
    --key bob.json \
    --address 127.0.0.1:23095 \
    --ns-server 127.0.0.1:5353
```

> Output:
> ```
> ZTLP-NS Registration
>   Name:       bob.demo.ztlp
>   Zone:       demo.ztlp
>   NodeID:     b7f2a31e...
>   Public Key: 9c4f8a2b...
>   NS Server:  127.0.0.1:5353
>   Address:    127.0.0.1:23095
>
> → Registering KEY record...
>   ✓ KEY record registered
> → Registering SVC record...
>   ✓ SVC record registered (127.0.0.1:23095)
>
> → Verifying registration...
>   ✓ Registration verified — record found in NS
>
> ✓ Registration complete!
>
>   Verify:  ztlp ns lookup bob.demo.ztlp --ns-server 127.0.0.1:5353
>   Connect: ztlp connect bob.demo.ztlp --ns-server 127.0.0.1:5353
> ```

> **Narration:** "Two records created — a KEY record binding the name to Bob's cryptographic identity, and a SVC record with his endpoint. Both signed by the namespace authority. Now watch this."

```bash
# Verify: look up the record
ztlp ns lookup bob.demo.ztlp --ns-server 127.0.0.1:5353
```

> **Narration:** "The record is live. Now Alice can connect to Bob by *name* — no IP address needed."

**Terminal 1 (Bob):**
```bash
ztlp listen --key bob.json --bind 0.0.0.0:23095
```

**Terminal 2 (Alice):**
```bash
# Connect by name — auto-resolves via ZTLP-NS
ztlp connect bob.demo.ztlp --key alice.json --ns-server 127.0.0.1:5353
```

> Output:
> ```
> Resolving bob.demo.ztlp via ZTLP-NS...
>   ✓ SVC record → 127.0.0.1:23095
>   ✓ KEY record found
>   ℹ NodeID: b7f2a31e...
> Connecting to 127.0.0.1:23095...
> ✓ Session established
>   Handshake: 291 µs
> ```

> **Narration:** "Alice typed a name — not an IP. ZTLP-NS resolved it to Bob's endpoint and verified his cryptographic identity. This is what zero-trust name resolution looks like — every lookup is signed, every identity is verified."

**[Ctrl+C both sides]**

---

## Act 5 — Relayed Connection (3:45–4:15)

> **Narration:** "In the real world, nodes are behind NAT, on different networks. That's what relays are for. The relay forwards packets by SessionID but never holds session keys."

**Terminal 1 (Bob):**
```bash
ztlp listen --key bob.json --bind 0.0.0.0:23096
```

**Terminal 2 (Relay — already running on :23095)**

**Terminal 3 (Alice):**
```bash
# Connect to Bob through the relay
ztlp connect bob.demo.ztlp --key alice.json --relay 127.0.0.1:23095 --ns-server 127.0.0.1:5353
```

> Output:
> ```
> Resolving bob.demo.ztlp via ZTLP-NS...
>   ✓ SVC record → 127.0.0.1:23096
> Connecting via relay 127.0.0.1:23095...
> ✓ Session established (relayed)
>   Handshake: 312 µs
>   Relay:     127.0.0.1:23095
> ```

> **Narration:** "312 microseconds through the relay. The relay is doing SessionID-based label switching — like an MPLS router. The encryption is end-to-end between Alice and Bob."

**[Ctrl+C all]**

---

## Act 6 — SSH Tunnel: Protecting Real Services (4:15–5:30)

> **Narration:** "Here's where it gets practical. Let's protect an SSH server with ZTLP. The SSH port disappears from the network — it's only accessible through an authenticated ZTLP tunnel. No port scanning, no brute-force login attempts, no attack surface."

**Terminal 1 (Server — "Bob" with SSH):**
```bash
# Bob's server: forward authenticated ZTLP sessions to local sshd
ztlp listen --key bob.json --bind 0.0.0.0:23095 --forward 127.0.0.1:22
```

> Output:
> ```
> Bound to: 0.0.0.0:23095
> TCP forward: authenticated sessions → 127.0.0.1:22
> Waiting for connections...
> ```

> **Narration:** "Port 22 is no longer exposed. The only way in is through ZTLP — you need a valid identity, you need to complete the Noise_XX handshake, and your NodeID needs to be authorized."

**Terminal 2 (Client — Alice tunnels SSH):**
```bash
# Alice opens a local port that tunnels through ZTLP to Bob's SSH
ztlp connect bob.demo.ztlp --key alice.json --ns-server 127.0.0.1:5353 \
    -L 2222:127.0.0.1:22
```

> Output:
> ```
> Resolving bob.demo.ztlp via ZTLP-NS...
>   ✓ SVC record → 127.0.0.1:23095
>   ✓ KEY record found
> Connecting to 127.0.0.1:23095...
> ✓ Session established
>   Handshake: 295 µs
> ✓ Local forward: 127.0.0.1:2222 → tunnel → 127.0.0.1:22
>   Listening for TCP connections on 127.0.0.1:2222...
> ```

> **Narration:** "Alice's machine is now listening on port 2222. Any connection to that port flows through the ZTLP encrypted tunnel to Bob's SSH server. Let's use it."

**Terminal 3 (SSH through the tunnel):**
```bash
# SSH through the ZTLP tunnel
ssh -p 2222 user@127.0.0.1
```

> Output:
> ```
> The authenticity of host '[127.0.0.1]:2222 (...)' can't be established.
> ED25519 key fingerprint is SHA256:xR3f0...
> Are you sure you want to continue connecting (yes/no)? yes
> user@server:~$
> ```

> **Narration:** "We're in. That SSH connection traveled through ZTLP — encrypted, authenticated, replay-protected — before SSH's own encryption even started. The SSH server has *no idea* it's behind a ZTLP tunnel. It just sees a TCP connection from localhost."

```bash
# Show we're connected
whoami
hostname
```

> **Narration:** "And here's the key point: if you nmap Bob's public IP, you won't find port 22 — it's not open. You'll find port 23095, the ZTLP port, and every packet that hits it without valid credentials is rejected at Layer 1 in 19 nanoseconds. SSH brute-force attacks are structurally impossible."

```bash
# Show what an attacker sees
nmap -p 22 127.0.0.1
```

> Output:
> ```
> PORT   STATE  SERVICE
> 22/tcp closed ssh
> ```

> **Narration:** "Closed. The service exists, but it's invisible to the network. Only authenticated ZTLP identities can reach it."

**[Ctrl+C, exit SSH]**

---

## Act 7 — Packet Inspection (5:30–5:50)

> **Narration:** "Let's look at what's actually on the wire."

```bash
# Inspect a sample ZTLP data packet
ztlp inspect 5a37100b0000f8d2a1e703c4b90a1b2c000000000000002a4d8f1c3e7b2a9d0e5f4c8b1a3d6e9f
```

> Output (colorized):
> ```
> ┌─────────────────────────────────────────────┐
> │ ZTLP Data Packet (Compact Header)           │
> ├──────────────┬──────────────────────────────┤
> │ Magic        │ 0x5A37 ✓                     │
> │ Version      │ 1                            │
> │ HdrLen       │ 11 (44 bytes — data packet)  │
> │ SessionID    │ f8d2a1e703c4b90a1b2c         │
> │ PacketSeq    │ 42                           │
> │ HeaderAuthTag│ 4d8f1c3e7b2a9d0e5f4c8b1a... │
> └──────────────┴──────────────────────────────┘
> ```

> **Narration:** "42 bytes of header. No NodeIDs, no identity information, no source or destination addresses. A passive observer sees a session identifier that changes every connection. They can't tell who's talking or what they're saying."

---

## Act 8 — Closing (5:50–6:00)

> **Narration:** "That's ZTLP. Identity before connectivity. 19-nanosecond rejection. Named identity resolution. End-to-end encrypted SSH through an untrusted relay — no open ports, no attack surface. The specification, reference implementation, and benchmarks are at ztlp.org under Apache 2.0."

**Final terminal:**
```bash
echo ""
echo "  ZTLP — Zero Trust Layer Protocol"
echo "  ztlp.org | Apache 2.0"
echo "  2,278 tests. Zero failures."
echo ""
```

**[Hold for 3 seconds, then end recording]**

---

## Production Notes

### Pre-Recording Checklist

- [ ] Build all binaries: `cd proto && cargo build --release`
- [ ] Symlink or alias: `alias ztlp='./target/release/ztlp'`
- [ ] Start ZTLP-NS server (Elixir): `cd ns && mix run --no-halt`
- [ ] Pre-generate identity files with consistent NodeIDs across takes
- [ ] Pre-register `bob.demo.ztlp` with NS (or show registration live as in Act 4)
- [ ] Ensure SSH server running on localhost:22 (for Act 6)
- [ ] Verify all commands work end-to-end before pressing record
- [ ] Clear terminal history
- [ ] Set clean PS1 prompt
- [ ] Test split-screen layout (tmux — see below)
- [ ] Verify asciinema recording quality at target resolution

### tmux Layout for Recording

```bash
# Create the session with 3 panes
tmux new-session -s ztlp-demo -d

# Pane 0: Bob / Server (left full height)
tmux split-window -h -t ztlp-demo

# Pane 1: Alice / Client (top-right)
tmux split-window -v -t ztlp-demo:.1

# Pane 2: SSH / Inspector (bottom-right)

# Attach
tmux attach -t ztlp-demo
```

Layout:
```
┌──────────────────┬──────────────────┐
│                  │                  │
│  Bob / Server    │  Alice / Client  │
│  (listener)      │  (connect)       │
│                  ├──────────────────┤
│                  │  SSH / inspect   │
│                  │  (tunnel user)   │
└──────────────────┴──────────────────┘
```

### Demo Flow Summary (Quick Reference)

| Act | Duration | What happens | Key takeaway |
|-----|----------|-------------|--------------|
| 1 | 0:45 | `keygen` for Alice & Bob | Identity is cryptographic, not IP-based |
| 2 | 1:00 | Direct connect + chat | 287µs Noise_XX, E2E encrypted |
| 3 | 1:00 | Pipeline benchmark | 53M rejects/sec, 47× cost ratio |
| 4 | 1:00 | NS register + connect by name | Signed namespace, no IPs needed |
| 5 | 0:30 | Relayed connection by name | Relay is blind — SessionID switching |
| 6 | 1:15 | **SSH tunnel through ZTLP** | Port 22 invisible, brute-force impossible |
| 7 | 0:20 | Packet inspection | No identity leaks on wire |
| 8 | 0:10 | Closing slate | ztlp.org, Apache 2.0 |

### Voiceover Tips

- **Pace:** Slightly slower than conversational. Let the terminal output appear, then narrate what it means.
- **Tone:** Confident but not salesy. Let the technology speak. The numbers are the pitch.
- **Emphasis points:** The 19ns rejection, the 287µs handshake, the 47× cost ratio, "connect by name," "port 22 is invisible," "the relay can't read this."
- **Don't explain everything.** The whitepaper exists for detail. The demo shows it working.
- **The SSH tunnel is the closer.** This is where skeptics go from "interesting concept" to "I need this." Let it breathe.

### Post-Production

- Trim dead time (long compile waits, typos, etc.)
- Add chapter markers if publishing to YouTube
- Consider adding a simple title card at the start and end
- Subtitles/captions recommended for accessibility
- Export from asciinema to SVG or GIF for embedding in presentations

### Alternative: GIF Version

For embedding in the GitHub README or whitepaper:

```bash
# Convert asciinema to GIF using agg
agg ztlp-demo.cast ztlp-demo.gif --theme monokai --font-size 14

# Or use svg-term for SVG
svg-term --in ztlp-demo.cast --out ztlp-demo.svg --window
```

**Short versions for different audiences:**
- **60-second GIF** (Acts 1+3): Keygen + pipeline rejection → social media / README
- **90-second GIF** (Acts 1+4+6): Keygen + NS register + SSH tunnel → conference slides
- **Full 6-minute** (all acts): YouTube / conference talk embedded video
