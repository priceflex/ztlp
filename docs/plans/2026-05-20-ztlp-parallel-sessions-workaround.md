# ZTLP Multiplexed TCP Pipeline (Phase 3)

> **For Hermes:** Use subagent-driven-development skill to implement this workaround via parallel sessions.

**Goal:** Unblock the "passwordless admin dashboard" browser experience by allowing `ztlp connect` to process concurrent browser asset streams instantly, rather than stalling them in a serialized TCP backlog.

**Architecture:** The current protocol (`tunnel.rs`) does not support multiplexing multiple inner TCP streams over a single Noise session; it "swallows" `FRAME_OPEN` and `FRAME_CLOSE` frames. Implementing full mux in the Rust gateway is a multi-day protocol task. The Elixir gateway does support full mux, but lacks the Noise-static-key HTTP header injection.

Therefore, the only viable immediate architecture to unblock the browser experience is **Parallel Noise Sessions**. 

The client `cmd_connect` will be modified to wrap the TCP `accept` handler and bridge in a `tokio::spawn` task. Each incoming TCP connection from the browser will trigger a new, concurrent Noise handshake to the gateway, establishing a dedicated 1:1 `SessionId` for that TCP stream. The Rust gateway already supports `--max-sessions 100`, so it can easily handle a browser bursting 6 concurrent handshakes.

**Expected overhead:** Handshakes benchmarked at ~280µs. A burst of 6 handshakes will cost <2ms. This is entirely invisible to the user compared to the current 65-second keep-alive stalls.

**Tech Stack:** Rust, Tokio.

---

### Task 1: Refactor `cmd_connect` logic to enable parallel sessions

**Objective:** Split the serial `accept` / `run_bridge` loop so that multiple TCP connections can be handled concurrently by allocating a fresh session per stream.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` (in `cmd_connect`)

**Changes needed:**
Currently, `session_id` and the `first_connection` toggle are determined *outside* the `loop { tcp_listener.accept().await? ... }`. We must:
1. Ensure the user didn't explicitly pass `--session-id` via args (if they did, parallel sessions aren't possible and we hit a conflict, or we must gracefully fall back).
2. Inside the accept loop, generate a *new* `SessionId` if we are running in parallel mode.
3. Spawn a dedicated `tokio::task` for each accepted TCP stream.
4. Call `tunnel::run_bridge` inside the spawned task. (We no longer need `run_bridge_with_reset` unless we fall back to single-session mode for some reason, as every connection is "first" on its new session).

**Step 1: Write/adapt the change**
Inside `src/bin/ztlp-cli.rs` around line `2605`:

```rust
        eprintln!(
            "{} {}",
            c_green("✓ Listening for TCP connections on"),
            listen_addr
        );

        // If the user pinned a session ID, we MUST stay single-stream serial
        // to avoid session ID collisions on the gateway. Otherwise, we can
        // spawn concurrent handshakes for every incoming TCP connection.
        let is_parallel = session_id_hex.is_none();
        
        let mut first_connection = true;

        loop {
            let (tcp_stream, tcp_addr) = tcp_listener.accept().await?;
            eprintln!("{} {} → tunnel", c_cyan("TCP connection from"), tcp_addr);

            let udp = node.socket.clone();
            let pipeline = node.pipeline.clone();
            let peer = send_addr;

            if is_parallel {
                // Parallel Mode (Browser/Assets): Generate a fresh session for every stream
                let current_session = SessionId::generate();
                
                tokio::spawn(async move {
                    let result = tunnel::run_bridge(tcp_stream, udp, pipeline, current_session, peer).await;
                    match result {
                        Ok(_outcome) => {
                            eprintln!("{} {}", c_dim("TCP connection closed:"), tcp_addr);
                        }
                        Err(e) => {
                            eprintln!("{} {}", c_red("✗ tunnel error:"), e);
                        }
                    }
                });
            } else {
                // Legacy serial mode (pinned sessions)
                let result = if first_connection {
                    first_connection = false;
                    tunnel::run_bridge(tcp_stream, udp, pipeline, session_id, peer).await
                } else {
                    tunnel::run_bridge_with_reset(tcp_stream, udp, pipeline, session_id, peer).await
                };

                match result {
                    Ok(_outcome) => {
                        eprintln!("{} {}", c_dim("TCP connection closed:"), tcp_addr);
                    }
                    Err(e) => {
                        eprintln!("{} {}", c_red("✗ tunnel error:"), e);
                    }
                }
            }
        }
```

**Note on variables:** `cmd_connect` currently constructs the handshake packet *before* the `accept` loop (around line 2449) and runs `wait_for_handshake` serially. 
Wait, looking closely at `cmd_connect`, the entire hand-shake happens **before** the `tcp_listener.bind`! 

```rust
    // Handshake
    let recv1_header = tunnel::wait_for_handshake(...)
    // ...
    let tcp_listener = tokio::net::TcpListener::bind(&listen_addr)
```

**Critical architecture correction:** Changing `cmd_connect` is slightly harder because the handshake is currently strictly orchestrated before the port binds. To make it parallel *after* bind, we have to move the `encrypt_and_send` (HELLO msg 1) and `wait_for_handshake` inside the `tokio::spawn`.

**Refined Task 1 Plan:**
We cannot just duplicate `run_bridge`. The entire sequence from:
```rust
    // Register temporary session...
```
down through:
```rust
    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;
```
must be extracted into a helper async function `establish_tunnel_session` so it can be called *inside* the parallel task spawned by `accept`. 

*Because of this structural complexity, we will execute the plan in the next session ensuring we have the exact boundaries.*

---

### Task 2: Validate execution with local client

**Objective:** Prove that 6 parallel curls resolve instantly instead of taking 65 seconds.

**Process:**
1. Build `ztlp`.
2. Connect to the cloud passwordless gateway.
3. Observe multiple "Handshake complete" logs firing concurrently.

---

### Alternative explored (Documented for the user)
- **Rust Client `vip.rs` Mux**: Confirmed we hold a working StreamDispatcher in `vip.rs`. We confirmed `tunnel.rs` drops Mux packets. This requires days.
- **Elixir Gateway Mux**: Confirmed Elixir has full Mux capabilities. However, Elixir lacks the Noise-static-key identity injection required for this feature.
