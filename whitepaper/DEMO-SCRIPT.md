# ZTLP Demo Video Script

## Overview

**Format:** Terminal recording (asciinema) with voiceover narration
**Duration:** 4–5 minutes
**Audience:** CISOs, security engineers, conference attendees who've read (or skimmed) the whitepaper
**Goal:** Show ZTLP is real, working software — not vaporware. Demonstrate the identity-first model, the pipeline rejecting bad traffic, and an end-to-end encrypted session through a relay.

**Recording setup:**
```bash
# Install asciinema
pip install asciinema

# Record with a clean terminal (80x24 or 120x30 for readability)
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

> **Narration:** "In ZTLP, identity comes before connectivity. Before you can talk to anything on the network, you need to prove who you are. Let's start by generating an identity."

```bash
# Generate an identity for Alice
ztlp keygen --output alice.json
cat alice.json
```

> **Narration:** "That's a ZTLP identity — a 128-bit NodeID bound to X25519 and Ed25519 key pairs. The NodeID is your address on the network. It's not tied to an IP, a MAC address, or a hostname. It's purely cryptographic. Let's make one for Bob too."

```bash
# Generate an identity for Bob
ztlp keygen --output bob.json
cat bob.json
```

> **Narration:** "Alice and Bob each have a unique identity. Now let's see what happens when they try to communicate."

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
> Listening on 0.0.0.0:23095
> NodeID: b7f2a3...
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

> **Narration:** "End-to-end encrypted. No certificate authority, no TLS handshake, no PKI infrastructure. Just two identities, a Noise_XX handshake, and a symmetric session."

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
# Send random garbage — should be rejected at Layer 1
echo "deadbeef0000000000000000" | xxd -r -p | nc -u -w1 127.0.0.1 23095
```

> **Narration:** "Random bytes — no ZTLP magic header. Rejected at Layer 1 in about 19 nanoseconds. The relay spent effectively zero CPU on that."

```bash
# Now use the load generator to quantify it
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
>   L1 reject (bad magic):      18.7 ns/pkt   53,475,936 pps
>   L2 reject (unknown session): 30.9 ns/pkt   32,362,460 pps
>   Full pipeline (valid):      876.2 ns/pkt    1,141,320 pps
>
> Cost ratio: Reject is 47x cheaper than admit
> ```

> **Narration:** "53 million rejects per second at Layer 1. On a single core. That's the structural advantage — attackers pay bandwidth, defenders pay nanoseconds. An attacker would need to guess a valid 96-bit SessionID just to reach the crypto layer. That's a 1-in-2^96 chance per packet."

**[Pause — let the numbers sink in]**

---

## Act 4 — Relayed Connection (2:45–3:45)

> **Narration:** "In the real world, nodes are behind NAT, on different networks, across the globe. That's what relays are for. Let's connect Alice to Bob through a relay — the relay forwards packets by SessionID but never sees the plaintext."

**Terminal 1 (Bob):**
```bash
ztlp listen --key bob.json --bind 0.0.0.0:23096
```

**Terminal 2 (Relay — already running on :23095)**

**Terminal 3 (Alice):**
```bash
# Alice connects to Bob via the relay
ztlp connect 127.0.0.1:23096 --key alice.json --relay 127.0.0.1:23095
```

> Output:
> ```
> Connecting via relay 127.0.0.1:23095...
> Noise_XX handshake (relayed):
>   → HELLO (via relay)
>   ← CHALLENGE (via relay)
>   → AUTH (via relay)
> ✓ Session established (relayed)
>   Remote NodeID: b7f2a3...
>   Session ID:    f8d2a1e703c4b9...
>   Relay:         127.0.0.1:23095
>   Handshake:     312 µs
> ```

> **Narration:** "312 microseconds through the relay. The relay forwarded the handshake packets and now forwards data — but it never holds session keys. It's doing SessionID-based label switching, like an MPLS router. The encryption is end-to-end between Alice and Bob."

**Exchange a message to prove it works:**

Alice types: `Relayed and encrypted — the relay can't read this`
Bob sees:    `[a4e1f0...] Relayed and encrypted — the relay can't read this`

**[Ctrl+C all]**

---

## Act 5 — Packet Inspection (3:45–4:15)

> **Narration:** "Let's look at what's actually on the wire. Here's a captured ZTLP data packet."

```bash
# Inspect a sample data packet (compact 42-byte header)
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
> │ Flags        │ 0x0000                        │
> │ SessionID    │ f8d2a1e703c4b90a1b2c         │
> │ PacketSeq    │ 42                           │
> │ HeaderAuthTag│ 4d8f1c3e7b2a9d0e5f4c8b1a... │
> └──────────────┴──────────────────────────────┘
> ```

> **Narration:** "42 bytes of header. SessionID for routing, sequence number for replay protection, auth tag for integrity. No NodeIDs, no identity information, no source or destination addresses. A passive observer sees a session identifier that changes every connection. They can't tell who's talking or what they're saying."

---

## Act 6 — Closing (4:15–4:30)

> **Narration:** "That's ZTLP. Identity before connectivity. 19-nanosecond rejection. End-to-end encryption through an untrusted relay mesh. No open ports. No attack surface. The full specification, reference implementation, and benchmarks are available at ztlp.org under Apache 2.0."

**Final terminal:**
```bash
echo ""
echo "  ZTLP — Zero Trust Layer Protocol"
echo "  ztlp.org | Apache 2.0"
echo "  723 tests. Zero failures."
echo ""
```

**[Hold for 3 seconds, then end recording]**

---

## Production Notes

### Pre-Recording Checklist

- [ ] Build all binaries: `cd proto && cargo build --release`
- [ ] Symlink or alias: `alias ztlp='./target/release/ztlp'`
- [ ] Verify `keygen`, `listen`, `connect`, `relay start`, `inspect`, and `ztlp-load pipeline` all work
- [ ] Clear terminal history
- [ ] Set clean PS1 prompt
- [ ] Test split-screen layout (tmux recommended: 3 panes)
- [ ] Pre-generate identity files if you want consistent NodeIDs across takes
- [ ] Verify asciinema recording quality at target resolution

### tmux Layout for Recording

```bash
# Create the session
tmux new-session -s ztlp-demo

# Split for Act 2 and Act 4 (side by side)
tmux split-window -h
tmux split-window -v

# Pane 0: Bob (left)
# Pane 1: Alice (top-right)  
# Pane 2: Relay (bottom-right)
```

### Voiceover Tips

- **Pace:** Slightly slower than conversational. Let the terminal output appear, then narrate what it means.
- **Tone:** Confident but not salesy. Let the technology speak. The numbers are the pitch.
- **Emphasis points:** The 19ns rejection, the 287µs handshake, the 47× cost ratio, "no NodeIDs on the data path," "the relay can't read this."
- **Don't explain everything.** The whitepaper exists for detail. The demo shows it working.

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

A shorter version (Acts 1+3 only — keygen + pipeline rejection) makes a good 60-second GIF for social media.
