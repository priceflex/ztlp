# Handshake Retransmit Implementation

## Security Requirements

### MUST
1. **No nonce reuse with different plaintext** — retransmitted messages MUST be byte-identical to originals
2. **Responder MUST cache HELLO_ACK** — if a duplicate HELLO arrives for the same session_id, resend the cached HELLO_ACK bytes, do NOT create a new HandshakeContext (new ephemeral key would break the handshake)
3. **Responder MUST NOT amplify** — limit retransmit count to prevent being used as a DDoS amplifier. Max 3 retransmissions of HELLO_ACK per session_id
4. **Half-open cache MUST be bounded** — cached handshake state (for retransmit) must have a max size and TTL to prevent memory exhaustion
5. **Retransmit timer MUST use exponential backoff** — prevents thundering herd on congested links

### MUST NOT
1. **MUST NOT retransmit on any received packet** — only retransmit on timeout or on seeing a duplicate of the previous message
2. **MUST NOT hold HandshakeContext longer than necessary** — TTL on half-open states (15 seconds max)
3. **MUST NOT allow retransmit to bypass rate limiting** — retransmitted HELLOs count toward the rate limit

## Design

### Initiator Side (connect)

The initiator drives retransmit for msg1 and msg3:

```
State: INIT
  → Send HELLO (msg1)
  → Start timer T1 = max(500ms, 2×srtt_estimate)
  
State: WAIT_HELLO_ACK
  Timer T1 fires:
    if retries < MAX_RETRIES(5):
      → Re-send HELLO (exact same bytes as original msg1)
      → T1 = T1 × 2 (exponential backoff, cap at 5s)
      → retries++
    else:
      → Handshake FAILED
  
  Receive HELLO_ACK:
    → Process msg2 (read_message)
    → Send msg3
    → Start timer T3 = max(500ms, 2×srtt_estimate)
    → State = WAIT_ESTABLISHED

State: WAIT_ESTABLISHED
  Timer T3 fires:
    if retries3 < MAX_RETRIES(5):
      → Re-send msg3 (exact same bytes)
      → T3 = T3 × 2
      → retries3++
    else:
      → Handshake FAILED
  
  Receive first DATA packet from responder:
    → Handshake COMPLETE (responder got msg3 and started sending data)
    → Cancel T3
```

Key: msg1 and msg3 bytes are stored after first send and re-sent verbatim.

### Responder Side (listen)

The responder caches sent messages and handles duplicates:

```
State: IDLE
  Receive HELLO:
    → Create HandshakeContext
    → read_message(msg1)
    → Generate HELLO_ACK (msg2)
    → Cache: session_id → {msg2_bytes, timestamp, retransmit_count}
    → Send HELLO_ACK
    → Start timer T2 = max(500ms, 2×srtt_estimate)
    → State = WAIT_MSG3

State: WAIT_MSG3
  Receive msg3:
    → read_message(msg3)
    → Finalize handshake
    → Remove from cache
    → State = ESTABLISHED
  
  Receive duplicate HELLO (same session_id):
    → Check cache for session_id
    → If found AND retransmit_count < 3:
      → Re-send cached msg2_bytes (verbatim)
      → retransmit_count++
    → If retransmit_count >= 3:
      → Drop (DoS protection)
  
  Timer T2 fires:
    → If retransmit_count < 3:
      → Re-send cached msg2_bytes
      → retransmit_count++
      → T2 = T2 × 2
    → If retransmit_count >= 3 OR elapsed > 15s:
      → Cleanup: remove from cache
      → State = IDLE
```

### Half-Open Cache

```rust
struct HalfOpenHandshake {
    ctx: HandshakeContext,        // Noise state (for finalize)
    msg2_bytes: Vec<u8>,          // Cached HELLO_ACK packet (full packet, not just payload)
    peer_addr: SocketAddr,        // Where to retransmit
    created_at: Instant,          // TTL tracking
    retransmit_count: u8,         // DoS protection
    hello_data: Vec<u8>,          // Original HELLO (for duplicate detection)
}

// Bounded HashMap: max 64 entries, LRU eviction, 15s TTL
struct HalfOpenCache {
    entries: HashMap<SessionId, HalfOpenHandshake>,
    max_entries: usize,           // 64
    ttl: Duration,                // 15 seconds
}
```

## Implementation — Files to Change

### `proto/src/bin/ztlp-cli.rs`

#### 1. Initiator (`do_connect` function, ~line 1656)

Replace:
```rust
// Message 1: HELLO
let msg1 = ctx.write_message(&[])?;
// ... build pkt1 ...
node.send_raw(&pkt1, send_addr).await?;

// Message 2: receive HELLO_ACK
let (recv2, _from2) = timeout(HANDSHAKE_TIMEOUT, node.recv_raw())
    .await
    .map_err(|_| "handshake timeout waiting for HELLO_ACK")??;
```

With retransmit loop:
```rust
// Message 1: HELLO (with retransmit)
let msg1 = ctx.write_message(&[])?;
// ... build pkt1 ...
node.send_raw(&pkt1, send_addr).await?;

let mut retry_delay = Duration::from_millis(500);
const MAX_HS_RETRIES: u8 = 5;
const MAX_HS_RETRY_DELAY: Duration = Duration::from_secs(5);
let mut retries: u8 = 0;

let (recv2, _from2) = loop {
    match timeout(retry_delay, node.recv_raw()).await {
        Ok(Ok((data, addr))) => {
            if data.len() >= HANDSHAKE_HEADER_SIZE {
                if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                    if hdr.msg_type == MsgType::HelloAck && hdr.session_id == session_id {
                        break (data, addr);
                    }
                }
            }
            // Not a HELLO_ACK for our session — ignore and keep waiting
            continue;
        }
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            // Timeout — retransmit
            retries += 1;
            if retries > MAX_HS_RETRIES {
                return Err("handshake failed: no HELLO_ACK after 5 retransmits".into());
            }
            debug!("handshake: retransmitting HELLO (attempt {}/{})", retries, MAX_HS_RETRIES);
            eprintln!("  {} retransmitting HELLO ({}/{})", c_yellow("⟳"), retries, MAX_HS_RETRIES);
            node.send_raw(&pkt1, send_addr).await?;  // EXACT same bytes
            retry_delay = (retry_delay * 2).min(MAX_HS_RETRY_DELAY);
        }
    }
};
```

Same pattern for msg3 — after sending, wait for the first DATA packet (which confirms the responder received msg3). If timeout, re-send msg3 (same bytes).

#### 2. Responder (`handle_new_session` function, ~line 2450)

Add a half-open cache. When a duplicate HELLO arrives with a session_id that's already in the cache, resend the cached HELLO_ACK bytes instead of creating a new context.

In the multi-session listener loop (~line 2350):
```rust
// Before creating a new session, check if this is a retransmitted HELLO
if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
    if hdr.msg_type == MsgType::Hello {
        if let Some(cached) = half_open_cache.get_mut(&hdr.session_id) {
            if cached.retransmit_count < 3 {
                // Resend cached HELLO_ACK
                node.send_raw(&cached.msg2_bytes, from).await?;
                cached.retransmit_count += 1;
                debug!("handshake: resent cached HELLO_ACK for session {} (retransmit {})",
                    hdr.session_id, cached.retransmit_count);
                continue;
            } else {
                debug!("handshake: dropping duplicate HELLO for session {} (max retransmits reached)",
                    hdr.session_id);
                continue;
            }
        }
        // New session — proceed with normal handshake
    }
}
```

In `handle_new_session`, after sending HELLO_ACK, cache it:
```rust
half_open_cache.insert(session_id, HalfOpenHandshake {
    msg2_bytes: pkt2.clone(),
    peer_addr: from,
    created_at: Instant::now(),
    retransmit_count: 0,
});
```

After msg3 is received and handshake completes, remove from cache:
```rust
half_open_cache.remove(&session_id);
```

#### 3. Responder single-session mode

Same pattern in the `do_listen` function (~line 1907).

### Constants

```rust
/// Maximum handshake retransmit attempts per message.
const MAX_HANDSHAKE_RETRIES: u8 = 5;

/// Initial handshake retransmit delay.
const INITIAL_HANDSHAKE_RETRY_MS: u64 = 500;

/// Maximum handshake retransmit delay (exponential backoff cap).
const MAX_HANDSHAKE_RETRY_MS: u64 = 5000;

/// Maximum half-open handshake cache entries (DoS protection).
const MAX_HALF_OPEN_HANDSHAKES: usize = 64;

/// Half-open handshake TTL (seconds).
const HALF_OPEN_TTL_SECS: u64 = 15;

/// Maximum responder retransmits of HELLO_ACK per session (amplification limit).
const MAX_RESPONDER_RETRANSMITS: u8 = 3;
```

## Testing

### New unit tests
1. `test_handshake_retransmit_msg1_lost` — initiator retransmits HELLO after timeout
2. `test_handshake_retransmit_msg2_lost` — initiator retransmits HELLO, responder resends cached HELLO_ACK
3. `test_handshake_retransmit_msg3_lost` — initiator retransmits msg3 after timeout
4. `test_handshake_retransmit_backoff` — verify exponential backoff timing
5. `test_handshake_retransmit_max_retries` — fails after MAX_HANDSHAKE_RETRIES
6. `test_half_open_cache_bounded` — cache evicts oldest when full
7. `test_half_open_cache_ttl` — entries expire after HALF_OPEN_TTL_SECS
8. `test_responder_amplification_limit` — stops retransmitting after MAX_RESPONDER_RETRANSMITS
9. `test_duplicate_hello_different_session` — different session IDs create independent handshakes
10. `test_retransmitted_msg_identical` — verify byte-for-byte identical retransmit

### Stress test validation
After implementation, re-run scenarios 6 (burst loss) and 11 (combined hell) to verify improvement.

## Execution Steps
1. `export PATH="$HOME/.cargo/bin:$PATH"`
2. Implement changes in `ztlp-cli.rs` and `handshake.rs`
3. `cargo fmt`
4. `cargo clippy -- -D warnings`
5. `cargo test` — all existing + new tests must pass
6. `cd ../relay && mix test` + `cd ../ns && mix test` + `cd ../gateway && mix test`
7. Commit: `git -c user.name="Steven Price" -c user.email="steve@techrockstars.com" commit -m "feat(handshake): retransmit with exponential backoff + half-open cache"`
8. Push: `git -c core.sshCommand="ssh -i ~/.ssh/openclaw" push`
