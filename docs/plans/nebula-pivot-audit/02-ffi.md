# Section 2 — FFI Surface Audit (Nebula Pivot)

Scope: `proto/src/ffi.rs` + `proto/include/ztlp.h`.
Branch: `nebula-style-pivot`.
Read-only. No source changes.

Total `pub extern "C" fn ztlp_*` in `proto/src/ffi.rs`: **141**.
Declarations in `proto/include/ztlp.h`: every Rust extern is declared in the header. No header-only symbols detected except the callback typedefs (`ZtlpRecvCallback`, `ZtlpAckSendCallback`, etc., which are not `fn`s).

Cross-check note: a handful of `ztlp_*` identifiers referenced in Swift do NOT correspond to a `pub extern "C" fn` (e.g. `ztlp_replay_reject_count`, `ztlp_connection_state`, `ztlp_connected_since`, `ztlp_peer_address`, `ztlp_selected_relay`, `ztlp_ne_memory_mb`, `ztlp_ne_virtual_mb`, `ztlp_find_utun_fd`). These appear in Swift as `static let …Key = "ztlp_xxx"` string-constant keys for IPC/message dispatch or as local Swift helpers, not FFI imports. Flagged but not in scope of this FFI inventory. Swift subagent should confirm.

---

## FFI FUNCTION INVENTORY

| FFI function | File:line | Purpose (1 line) | Action | Rationale |
|---|---|---|---|---|
| ztlp_init | ffi.rs:323 | Initialise global FFI state | KEEP | Lifecycle bootstrap, transport-agnostic. |
| ztlp_shutdown | ffi.rs:332 | Tear down global FFI state | KEEP | Lifecycle. |
| ztlp_identity_generate | ffi.rs:339 | Generate a new node identity | KEEP | Identity/Noise static key. |
| ztlp_identity_from_file | ffi.rs:359 | Load identity from disk | KEEP | Identity. |
| ztlp_identity_from_hardware | ffi.rs:392 | Load identity from SE/Keystore | KEEP | Identity. |
| ztlp_identity_node_id | ffi.rs:417 | Return node ID hex string | KEEP | Identity accessor. |
| ztlp_identity_public_key | ffi.rs:427 | Return identity pubkey hex | KEEP | Identity accessor. |
| ztlp_identity_save | ffi.rs:437 | Persist identity JSON | KEEP | Identity. |
| ztlp_identity_free | ffi.rs:467 | Free identity handle | KEEP | Identity. |
| ztlp_client_new | ffi.rs:479 | Construct ZtlpClient wrapper | UNCERTAIN | Client aggregates reliability state; likely shrinks to a thin Noise+mux+utun holder. Keep the symbol, rewrite internals. Q: retain handle type or rename to `ZtlpNode`? |
| ztlp_client_free | ffi.rs:533 | Destroy ZtlpClient | UNCERTAIN | Mirrors `ztlp_client_new`; same outcome. |
| ztlp_config_new | ffi.rs:551 | Allocate config builder | UNCERTAIN | Config currently carries relay/STUN/NAT/timeout/service. Nebula-style likely keeps a thinner config. Keep constructor symbol. |
| ztlp_config_set_relay | ffi.rs:563 | Set relay address | UNCERTAIN | Relay is a ZTLP concept; if the pivot drops relays, DELETE. Q: do we still need a relay in Nebula-mode, or only lighthouses? |
| ztlp_config_set_stun_server | ffi.rs:583 | Set STUN server | UNCERTAIN | NAT traversal belongs to new Nebula-style core; likely KEEP but maybe re-shape. |
| ztlp_config_set_nat_assist | ffi.rs:603 | Toggle NAT-assist | UNCERTAIN | Tied to existing hole-punch path. |
| ztlp_config_set_timeout_ms | ffi.rs:614 | Connect timeout | KEEP | Generic knob, reusable. |
| ztlp_config_set_service | ffi.rs:630 | Set service name | UNCERTAIN | Service/VIP concept — revisit when VIP proxy is decided. |
| ztlp_config_free | ffi.rs:655 | Free config builder | KEEP | Lifecycle. |
| ztlp_connect | ffi.rs:676 | Async connect entry (tokio) | DELETE | Session-oriented connect that drives the reliability state machine (retries, ACK-driven progress). Nebula-style uses utun fd I/O; Swift already uses `ztlp_connect_sync` + `ztlp_ios_tunnel_engine_start`. |
| ztlp_disconnect | ffi.rs:2102 | Async teardown | DELETE | Paired with `ztlp_connect`. Unused by Swift. |
| ztlp_disconnect_transport | ffi.rs:2140 | Drop transport, keep session | DELETE | Supports hot-swap reconnect of the reliability session. Not Nebula-shaped. Unused by Swift. |
| ztlp_listen | ffi.rs:2168 | Passive listen | DELETE | Server-side async listen on ZTLP reliability. Unused by Swift. |
| ztlp_send | ffi.rs:2191 | App-level send that allocates data_seq and FRAME_DATAs | DELETE | Explicitly generates `data_seq` → reliability-coupled. Nebula-style sends are utun packets + mux frames, not data_seq streams. Unused by Swift. |
| ztlp_set_recv_callback | ffi.rs:2253 | Install recv callback | DELETE | Bound to the async `ztlp_connect`/`ztlp_send` data path. Unused by Swift. |
| ztlp_set_disconnect_callback | ffi.rs:2276 | Install disconnect callback | DELETE | Tied to async session lifecycle. Unused by Swift. |
| ztlp_set_ack_send_callback | ffi.rs:2299 | Install ACK-send callback | DELETE | Pure reliability (ACK emission hook). |
| ztlp_session_peer_node_id | ffi.rs:2323 | Session → peer node id | UNCERTAIN | Accessor on `ZtlpSession` which is part of async reliability session. If `ZtlpSession` goes away, DELETE. Swift doesn't call it. |
| ztlp_session_id | ffi.rs:2333 | Session → session id | UNCERTAIN | Same as above. |
| ztlp_session_peer_addr | ffi.rs:2343 | Session → peer socket addr | UNCERTAIN | Same. |
| ztlp_bytes_sent | ffi.rs:2357 | Client send byte counter | KEEP | Plain telemetry, can be repointed at utun/mux counter. |
| ztlp_bytes_received | ffi.rs:2376 | Client recv byte counter | KEEP | Plain telemetry. |
| ztlp_tunnel_start | ffi.rs:2396 | Start local TCP-tunnel listener | DELETE | ZTLP-specific L4 tunnel entry; replaced by utun-fd path. Unused by Swift. |
| ztlp_tunnel_stop | ffi.rs:2425 | Stop local tunnel | DELETE | Pair of `ztlp_tunnel_start`. Unused by Swift. |
| ztlp_string_free | ffi.rs:2436 | Free C string returned by FFI | KEEP | Generic memory helper. |
| ztlp_version | ffi.rs:2445 | Library version | KEEP | Diagnostics. |
| ztlp_last_error | ffi.rs:2451 | Thread-local last error | KEEP | Diagnostics. |
| ztlp_vip_add_service | ffi.rs:2472 | Register VIP→service mapping | UNCERTAIN | Userspace VIP proxy. Not reliability per se; depends on whether Nebula-pivot keeps in-tunnel VIP routing or delegates to utun+packet_router. Used by Swift (`ZTLPVIPProxy.swift:55`). |
| ztlp_vip_start | ffi.rs:2546 | Start VIP proxy loop | UNCERTAIN | Same; called from `ZTLPVIPProxy.swift:55`. |
| ztlp_vip_stop | ffi.rs:2645 | Stop VIP proxy loop | UNCERTAIN | Same. |
| ztlp_dns_start | ffi.rs:2682 | Start in-tunnel DNS responder | UNCERTAIN | Local DNS piece; decision tied to whether `.ztlp` name resolution stays in library. |
| ztlp_dns_stop | ffi.rs:2739 | Stop DNS responder | UNCERTAIN | Same. |
| ztlp_ns_resolve | ffi.rs:2779 | Async NS resolve | UNCERTAIN | ZTLP-NS name service; orthogonal to reliability. KEEP symbol, but async variant may be dropped in favour of `_sync`. Unused by Swift. |
| ztlp_ns_fetch_ca_root | ffi.rs:2891 | Fetch NS CA root cert | KEEP | NS bootstrap, independent of reliability. |
| ztlp_bytes_free | ffi.rs:3014 | Free byte buffer | KEEP | Memory helper. |
| ztlp_ns_fetch_ca_chain_pem | ffi.rs:3030 | Fetch NS CA chain PEM | KEEP | NS bootstrap. |
| ztlp_router_new | ffi.rs:3144 | Create async packet router bound to client | DELETE | Async variant superseded by `_sync` router; iOS uses the sync one exclusively. |
| ztlp_router_add_service | ffi.rs:3282 | Async router add service | DELETE | Async variant; unused by Swift. |
| ztlp_router_write_packet | ffi.rs:3350 | Async router ingest utun packet | DELETE | Async variant; unused by Swift. |
| ztlp_router_read_packet | ffi.rs:3410 | Async router dequeue reply packet | DELETE | Async variant; unused by Swift. |
| ztlp_router_stop | ffi.rs:3462 | Async router stop | DELETE | Async variant; unused by Swift. |
| ztlp_pin_gateway_key | ffi.rs:3496 | Pin a gateway pubkey | KEEP | Identity/trust pinning; survives the pivot. |
| ztlp_verify_gateway_pin | ffi.rs:3572 | Verify a gateway pin | KEEP | Identity/trust pinning. |
| ztlp_ios_tunnel_engine_start | ffi.rs:3641 | Start utun engine on given fd | KEEP | **Nebula-core**: utun fd I/O. |
| ztlp_ios_tunnel_engine_stop | ffi.rs:3670 | Stop utun engine | KEEP | Nebula-core. |
| ztlp_ios_tunnel_engine_start_read_metadata_loop | ffi.rs:3681 | Background loop reading utun metadata | KEEP | Nebula-core. |
| ztlp_ios_tunnel_engine_set_router_action_callback | ffi.rs:3706 | Install router action callback | KEEP | Nebula-core wiring. |
| ztlp_ios_tunnel_engine_start_router_ingress_loop | ffi.rs:3733 | Loop feeding router from utun | KEEP | Nebula-core. |
| ztlp_ios_tunnel_engine_reconnect | ffi.rs:3762 | Re-point engine at new transport | KEEP | Nebula-core (path change / roaming). |
| ztlp_ios_tunnel_engine_udp_bind | ffi.rs:3785 | Bind UDP socket inside engine | KEEP | Nebula-core (outer UDP). |
| ztlp_ios_tunnel_engine_udp_send | ffi.rs:3834 | Send a UDP datagram | KEEP | Nebula-core. |
| ztlp_ios_tunnel_engine_udp_local_port | ffi.rs:3866 | Local UDP port accessor | KEEP | Nebula-core. |
| ztlp_ios_tunnel_engine_start_udp_recv_loop | ffi.rs:3885 | Loop draining UDP → engine | KEEP | Nebula-core. |
| ztlp_ios_tunnel_engine_free | ffi.rs:3910 | Destroy engine | KEEP | Nebula-core. |
| ztlp_mux_new | ffi.rs:3944 | Create mux engine | REPURPOSE | Mux framing stays (FRAME_OPEN/CLOSE/DATA) but the reliability state inside `MuxEngine` must be stripped. Keep constructor, slim internals. |
| ztlp_mux_free | ffi.rs:3959 | Destroy mux engine | KEEP | Lifecycle. |
| ztlp_mux_enqueue_data | ffi.rs:3970 | Enqueue FRAME_DATA(stream_id, payload) | KEEP | Mux framing. |
| ztlp_mux_enqueue_open | ffi.rs:4001 | Enqueue FRAME_OPEN | KEEP | Mux framing. |
| ztlp_mux_enqueue_close | ffi.rs:4040 | Enqueue FRAME_CLOSE | KEEP | Mux framing. |
| ztlp_mux_take_send_bytes | ffi.rs:4073 | Drain outbound frame bytes | KEEP | Mux framing egress. |
| ztlp_mux_tick_retransmit | ffi.rs:4117 | Periodic retransmit tick | DELETE | Retransmission = reliability. |
| ztlp_mux_take_retransmit_bytes | ffi.rs:4135 | Drain retransmit bytes | DELETE | Reliability. |
| ztlp_mux_on_ack | ffi.rs:4172 | Feed ACK (cumulative + rwnd) | DELETE | Reliability. |
| ztlp_mux_on_data_received | ffi.rs:4200 | Record received data_seq | DELETE | Reliability / ACK generation input. |
| ztlp_mux_mark_outbound_demand | ffi.rs:4224 | Hint that data is queued | DELETE | Coupled to autotune/rwnd pacing. |
| ztlp_mux_tick_rwnd | ffi.rs:4268 | Recompute advertised rwnd | DELETE | Reliability (flow control tick). |
| ztlp_mux_advertised_rwnd | ffi.rs:4311 | Get packet-unit rwnd | DELETE | Reliability accessor. |
| ztlp_mux_cumulative_ack | ffi.rs:4325 | Get cumulative ACK | DELETE | Reliability accessor. |
| ztlp_mux_inflight_len | ffi.rs:4336 | Inflight packet count | DELETE | Reliability accessor. |
| ztlp_mux_rtt_goodput_snapshot | ffi.rs:4382 | Snapshot RTT/BDP/goodput | DELETE | Reliability/telemetry for autotune. |
| ztlp_mux_observe_sent | ffi.rs:4421 | Shadow-observe a sent data_seq | DELETE | Reliability (Karn's algorithm input). |
| ztlp_mux_observe_ack_cumulative | ffi.rs:4448 | Shadow-observe a cumulative ACK | DELETE | Reliability. |
| ztlp_mux_shadow_inflight_len | ffi.rs:4472 | Shadow inflight count | DELETE | Reliability. |
| ztlp_mux_note_peer_sent_v2 | ffi.rs:4490 | Flag that peer speaks ACK_V2 | DELETE | Reliability negotiation. |
| ztlp_mux_peer_speaks_v2 | ffi.rs:4508 | Query ACK_V2 capability | DELETE | Reliability negotiation. |
| ztlp_mux_advertised_window_bytes | ffi.rs:4525 | Byte-unit advertised window | DELETE | Byte-rwnd — explicitly reliability. |
| ztlp_mux_advertised_window_kb | ffi.rs:4542 | KB-unit advertised window | DELETE | Byte-rwnd. |
| ztlp_mux_set_initial_window_kb | ffi.rs:4558 | Seed initial window | DELETE | Autotune config. |
| ztlp_mux_set_autotune_bounds_kb | ffi.rs:4586 | Set autotune min/max | DELETE | Autotune config. |
| ztlp_mux_autotune_target_kb | ffi.rs:4609 | Current autotune target | DELETE | Autotune. |
| ztlp_mux_autotune_min_kb | ffi.rs:4624 | Autotune lower bound | DELETE | Autotune. |
| ztlp_mux_autotune_max_kb | ffi.rs:4639 | Autotune upper bound | DELETE | Autotune. |
| ztlp_mux_autotune_reason | ffi.rs:4657 | Autotune decision reason string | DELETE | Autotune telemetry. |
| ztlp_health_new | ffi.rs:4715 | Create session health detector | DELETE | Stall detector = reliability session health. |
| ztlp_health_free | ffi.rs:4723 | Destroy health detector | DELETE | Same. |
| ztlp_health_tick | ffi.rs:4747 | Tick health state, decide PROBE/RECONNECT | DELETE | Session health. |
| ztlp_health_on_pong | ffi.rs:4797 | Record keepalive pong | DELETE | Part of reliability session health. (Note: raw PING/PONG framing stays at wire level, but the health state machine is what we're deleting.) |
| ztlp_health_reset_after_reconnect | ffi.rs:4813 | Reset health after reconnect | DELETE | Session health. |
| ztlp_health_state | ffi.rs:4830 | Current health state enum | DELETE | Session health. |
| ztlp_router_new_sync | ffi.rs:4859 | Sync packet router ctor | KEEP | Used by iOS utun pipeline (PacketTunnelProvider.swift:1154,1156). Router maps utun IP packets → mux streams; orthogonal to ZTLP reliability. |
| ztlp_router_add_service_sync | ffi.rs:4893 | Add VIP→service to router | KEEP | Used by Swift (:1164). |
| ztlp_router_write_packet_sync | ffi.rs:4948 | Inject utun packet into router | KEEP | Used by Swift (:1275). Core Nebula-style data path. |
| ztlp_router_read_packet_sync | ffi.rs:5041 | Drain return packet from router | KEEP | Used by Swift (:1556). |
| ztlp_router_gateway_data_sync | ffi.rs:5075 | Feed decrypted gateway TCP data back into router | KEEP | Used by Swift (:1493, :1509). |
| ztlp_router_has_stream_sync | ffi.rs:5102 | Check if stream_id is tracked | KEEP | Router bookkeeping. |
| ztlp_router_gateway_close_sync | ffi.rs:5119 | Handle FIN/RST from gateway | KEEP | Used by Swift (:1504). |
| ztlp_router_cleanup_stale_flows | ffi.rs:5144 | Reap idle flows | KEEP | Used by Swift (:441, :1717). Housekeeping. |
| ztlp_router_reset_runtime_state | ffi.rs:5170 | Reset router on reconnect | KEEP | Used by Swift (:462). |
| ztlp_free_string | ffi.rs:5187 | Free C string (alt name) | KEEP | Memory helper; used by Swift. |
| ztlp_router_stats | ffi.rs:5198 | Router stats JSON string | KEEP | Diagnostics; used by Swift. |
| ztlp_router_stop_sync | ffi.rs:5223 | Stop sync router | KEEP | Used by Swift (:1035). |
| ztlp_handshake_start | ffi.rs:5317 | Begin Noise handshake (msg1) | KEEP | Noise handshake. Used by Swift (:245,:249). |
| ztlp_handshake_process_msg2 | ffi.rs:5420 | Process Noise msg2 | KEEP | Noise handshake. Used by Swift (:282,:292). |
| ztlp_handshake_finalize | ffi.rs:5495 | Derive session keys | KEEP | Noise handshake. Used by Swift (:303,:305). |
| ztlp_handshake_free | ffi.rs:5547 | Free handshake state | KEEP | Noise. Used by Swift (:264). |
| ztlp_crypto_context_extract | ffi.rs:5563 | Lift session keys out of client | UNCERTAIN | Used by Swift (ZTLPTunnelConnection.swift:171, ZTLPVIPProxy.swift:113). Depends on `ZtlpClient` internals which are reliability-heavy today. If we rebuild `ZtlpClient` as a thin Noise-session container, this stays with same signature. |
| ztlp_crypto_context_free | ffi.rs:5625 | Free crypto context | KEEP | Noise/AEAD. Used by Swift (:184). |
| ztlp_crypto_context_session_id | ffi.rs:5634 | Session id accessor | KEEP | Noise/AEAD. Used by Swift (:585). |
| ztlp_crypto_context_peer_addr | ffi.rs:5643 | Peer addr accessor | KEEP | Noise/AEAD. Used by Swift (:594). |
| ztlp_encrypt_packet | ffi.rs:5665 | AEAD seal a frame | KEEP | AEAD. Used by Swift (ZTLPTunnelConnection:386,:465 and ZTLPVIPProxy:322). |
| ztlp_decrypt_packet | ffi.rs:5738 | AEAD open + replay-bitmap check | KEEP | AEAD + replay. Used by Swift (:681 and ZTLPVIPProxy:17). |
| ztlp_frame_data | ffi.rs:5823 | Build FRAME_DATA(data_seq, payload) | UNCERTAIN | Currently emits the legacy `[FRAME_DATA \| data_seq(8 BE) \| payload]` framing. If Nebula-pivot drops `data_seq`, signature changes or symbol is replaced by mux FRAME_DATA builders. Used by Swift (ZTLPTunnelConnection:385,:411; ZTLPVIPProxy:303). Q: does Nebula-pivot keep a top-level FRAME_DATA with seq for anti-replay only, or is the mux-layer FRAME_DATA the only one? |
| ztlp_parse_frame | ffi.rs:5870 | Parse a wire frame (any type) | UNCERTAIN | Needed, but may shed ACK/ACK_V2 variants. Signature likely stable. Used by Swift (:709,:829,:835; ZTLPVIPProxy:17). |
| ztlp_set_client_profile | ffi.rs:5941 | Set radio/interface profile hints | DELETE | Only consumed by autotune / reliability pacing. Swift calls it at :759, but downstream it drives `connect_sync` reliability tuning. |
| ztlp_connect_sync | ffi.rs:5989 | Synchronous Noise+session connect | REPURPOSE | Used by Swift (ZTLPTunnelConnection:170, ZTLPVIPProxy:113, PacketTunnelProvider:1130). Today it runs Noise handshake AND stands up reliability session + transports. Pivot: keep symbol, reduce to Noise+UDP+crypto-context. Signature may shrink. |
| ztlp_build_ack | ffi.rs:6259 | Build legacy FRAME_ACK(9B) | DELETE | Pure reliability frame. |
| ztlp_build_ack_with_rwnd | ffi.rs:6274 | Build FRAME_ACK with packet-rwnd | DELETE | Reliability. Used by Swift (ZTLPTunnelConnection:555) — must be removed from Swift. |
| ztlp_build_ack_v2 | ffi.rs:6316 | Build FRAME_ACK_V2 (byte-rwnd) | DELETE | Reliability. Used by Swift (:549). |
| ztlp_ns_resolve_sync | ffi.rs:6426 | Sync NS resolve | KEEP | NS. |
| ztlp_ns_result_free | ffi.rs:6643 | Free NS result | KEEP | NS memory. |
| ztlp_ns_result_get_address | ffi.rs:6690 | Get address from NS result | KEEP | NS accessor. |
| ztlp_ns_resolve_relays_sync | ffi.rs:6744 | Resolve relay set | KEEP | Used by Swift (:1762). Transport-neutral. |
| ztlp_relay_list_free | ffi.rs:6890 | Free relay list | KEEP | Used by Swift (:1803). |
| ztlp_relay_pool_new | ffi.rs:6959 | Allocate relay pool | KEEP | Used by Swift (:1749). Relay selection stays whether we use it or not; cheap to keep. |
| ztlp_relay_pool_update_from_ns | ffi.rs:6994 | Merge NS into pool | KEEP | Used by Swift (:1772). |
| ztlp_relay_pool_select | ffi.rs:7127 | Pick a relay | KEEP | Used by Swift (:1824). |
| ztlp_relay_pool_healthy_count | ffi.rs:7149 | Healthy relay count | KEEP | Used by Swift (:1774,:1814,:1828). |
| ztlp_relay_pool_total_count | ffi.rs:7159 | Total relay count | KEEP | Used by Swift (:1775). |
| ztlp_relay_pool_report_success | ffi.rs:7177 | Mark relay success | KEEP | Used by Swift (:2011,:866). |
| ztlp_relay_pool_report_failure | ffi.rs:7210 | Mark relay failure | KEEP | Used by Swift (:1928,:1996,:790). |
| ztlp_relay_pool_needs_refresh | ffi.rs:7235 | Should the pool refresh | KEEP | Used by Swift (:1936). |
| ztlp_relay_pool_free | ffi.rs:7245 | Free relay pool | KEEP | Used by Swift (:1063,:1743). |

---

## HEADER DIFF PREVIEW

Expected deletions from `proto/include/ztlp.h` (symbols only):

Async client/session surface (tokio feature):
- `ztlp_connect`
- `ztlp_disconnect`
- `ztlp_disconnect_transport`
- `ztlp_listen`
- `ztlp_send`
- `ztlp_set_recv_callback`
- `ztlp_set_disconnect_callback`
- `ztlp_set_ack_send_callback`
- `ztlp_tunnel_start`
- `ztlp_tunnel_stop`
- `ztlp_router_new`
- `ztlp_router_add_service`
- `ztlp_router_write_packet`
- `ztlp_router_read_packet`
- `ztlp_router_stop`

Reliability (ACK builders):
- `ztlp_build_ack`
- `ztlp_build_ack_with_rwnd`
- `ztlp_build_ack_v2`

Mux reliability internals:
- `ztlp_mux_tick_retransmit`
- `ztlp_mux_take_retransmit_bytes`
- `ztlp_mux_on_ack`
- `ztlp_mux_on_data_received`
- `ztlp_mux_mark_outbound_demand`
- `ztlp_mux_tick_rwnd`
- `ztlp_mux_advertised_rwnd`
- `ztlp_mux_cumulative_ack`
- `ztlp_mux_inflight_len`
- `ztlp_mux_rtt_goodput_snapshot`
- `ztlp_mux_observe_sent`
- `ztlp_mux_observe_ack_cumulative`
- `ztlp_mux_shadow_inflight_len`
- `ztlp_mux_note_peer_sent_v2`
- `ztlp_mux_peer_speaks_v2`
- `ztlp_mux_advertised_window_bytes`
- `ztlp_mux_advertised_window_kb`
- `ztlp_mux_set_initial_window_kb`
- `ztlp_mux_set_autotune_bounds_kb`
- `ztlp_mux_autotune_target_kb`
- `ztlp_mux_autotune_min_kb`
- `ztlp_mux_autotune_max_kb`
- `ztlp_mux_autotune_reason`

Session-health detector:
- `ztlp_health_new`
- `ztlp_health_free`
- `ztlp_health_tick`
- `ztlp_health_on_pong`
- `ztlp_health_reset_after_reconnect`
- `ztlp_health_state`

Profile hint (feeds autotune):
- `ztlp_set_client_profile`

Associated typedefs the header will almost certainly lose:
- `ZtlpAckSendCallback`, `ZtlpRecvCallback`, `ZtlpDisconnectCallback` (once their setters are gone)
- `ZtlpRttGoodputSnapshot` struct
- `ZtlpRwndSignals` / `ZtlpRwndStats` structs (inputs to `ztlp_mux_tick_rwnd`)
- `ZtlpHealthInputs` / `ZtlpHealthState` enum
- `ZtlpSessionHealth`, `ZtlpMuxEngine` reliability methods — the opaque struct for Mux stays but its method set shrinks.

### KEPT functions with potential signature change

- `ztlp_connect_sync` — REPURPOSE. Today it does Noise handshake + reliability session setup. Pivot likely reduces it to a Noise-only sync handshake; the return type (`ZtlpCryptoContext *`) can stay but parameters around relay/service may shrink. Swift callers: `ZTLPTunnelConnection.swift:170`, `ZTLPVIPProxy.swift:113`, `PacketTunnelProvider.swift:1130`.
- `ztlp_frame_data` — UNCERTAIN. If `data_seq` is dropped from the top-level wire frame, this function's `data_seq: u64` arg goes away. Swift currently passes `data_seq`.
- `ztlp_crypto_context_extract` — UNCERTAIN. If the client type is rebuilt, the input pointer type may change, though we'd keep the symbol name.
- `ztlp_mux_new` — REPURPOSE. Symbol keeps identical signature, but the underlying `MuxEngine` loses its reliability fields.

No other KEPT function is expected to change shape.

---

## iOS CALLSITE REFERENCES (for DELETE-classified FFI)

File prefix: `ios/ZTLP/ZTLPTunnel/`

- ztlp_connect: **unused in Swift** — FLAG (Swift uses `ztlp_connect_sync` instead).
- ztlp_disconnect: **unused in Swift** — FLAG.
- ztlp_disconnect_transport: **unused in Swift** — FLAG.
- ztlp_listen: **unused in Swift** — FLAG.
- ztlp_send: **unused in Swift** — FLAG.
- ztlp_set_recv_callback: **unused in Swift** — FLAG.
- ztlp_set_disconnect_callback: **unused in Swift** — FLAG.
- ztlp_set_ack_send_callback: **unused in Swift** — FLAG.
- ztlp_tunnel_start: **unused in Swift** — FLAG.
- ztlp_tunnel_stop: **unused in Swift** — FLAG.
- ztlp_router_new: **unused in Swift** — FLAG (sync variant is used).
- ztlp_router_add_service: **unused in Swift** — FLAG.
- ztlp_router_write_packet: **unused in Swift** — FLAG.
- ztlp_router_read_packet: **unused in Swift** — FLAG.
- ztlp_router_stop: **unused in Swift** — FLAG.
- ztlp_build_ack: **unused in Swift** — FLAG.
- ztlp_build_ack_with_rwnd:
  - `ZTLPTunnelConnection.swift:555`
- ztlp_build_ack_v2:
  - `ZTLPTunnelConnection.swift:549`
- ztlp_mux_tick_retransmit: **unused in Swift** — FLAG.
- ztlp_mux_take_retransmit_bytes: **unused in Swift** — FLAG.
- ztlp_mux_on_ack: **unused in Swift** — FLAG.
- ztlp_mux_on_data_received: **unused in Swift** — FLAG.
- ztlp_mux_mark_outbound_demand:
  - `PacketTunnelProvider.swift:334`
- ztlp_mux_tick_rwnd:
  - `PacketTunnelProvider.swift:516`, `:523`, `:526`, `:540` (one live call, three log strings — the logs go away when the symbol does)
- ztlp_mux_advertised_rwnd: **unused in Swift** — FLAG.
- ztlp_mux_cumulative_ack: **unused in Swift** — FLAG.
- ztlp_mux_inflight_len: **unused in Swift** — FLAG.
- ztlp_mux_rtt_goodput_snapshot:
  - `PacketTunnelProvider.swift:2349`
- ztlp_mux_observe_sent:
  - `PacketTunnelProvider.swift:2329`
  - `ZTLPTunnelConnection.swift:83` (comment only — clean up on delete)
- ztlp_mux_observe_ack_cumulative:
  - `PacketTunnelProvider.swift:2287`
  - `ZTLPTunnelConnection.swift:429` (call site)
- ztlp_mux_shadow_inflight_len:
  - `PacketTunnelProvider.swift:2355`
- ztlp_mux_note_peer_sent_v2:
  - `PacketTunnelProvider.swift:2315`
  - `PacketTunnelProvider.swift:931` (comment)
- ztlp_mux_peer_speaks_v2:
  - `PacketTunnelProvider.swift:2356`
- ztlp_mux_advertised_window_bytes: **unused in Swift** — FLAG.
- ztlp_mux_advertised_window_kb:
  - `PacketTunnelProvider.swift:534`, `:2316`, `:2357`
- ztlp_mux_set_initial_window_kb: **unused in Swift** — FLAG.
- ztlp_mux_set_autotune_bounds_kb: **unused in Swift** — FLAG.
- ztlp_mux_autotune_target_kb:
  - `PacketTunnelProvider.swift:2359`
- ztlp_mux_autotune_min_kb: **unused in Swift** — FLAG.
- ztlp_mux_autotune_max_kb: **unused in Swift** — FLAG.
- ztlp_mux_autotune_reason:
  - `PacketTunnelProvider.swift:2362`
- ztlp_health_new:
  - `PacketTunnelProvider.swift:943`, `:948`
- ztlp_health_free:
  - `PacketTunnelProvider.swift:921`, `:1016`
- ztlp_health_tick:
  - `PacketTunnelProvider.swift:570`, `:579`, `:581`, `:586`, `:196` (comment)
- ztlp_health_on_pong:
  - `PacketTunnelProvider.swift:2379`
- ztlp_health_reset_after_reconnect:
  - `PacketTunnelProvider.swift:945`
- ztlp_health_state: **unused in Swift** — FLAG.
- ztlp_set_client_profile:
  - `PacketTunnelProvider.swift:759`

Swift subagent input summary: live call-sites to rip out are concentrated in `PacketTunnelProvider.swift` (mux/health/rwnd/autotune block around lines 334, 516-586, 917-948, 2287-2379) and `ZTLPTunnelConnection.swift` (ACK builders at :549/:555, mux observers at :83/:429, plus ack-building in the RX loop).

---

## TALLY

- Total FFI fns: **141**
- DELETE: **48**
- KEEP: **72**
- REPURPOSE: **2** (`ztlp_mux_new` — internals shrink; `ztlp_connect_sync` — reduce to Noise-only)
- UNCERTAIN: **19**

Check: 48 + 72 + 2 + 19 = 141. ✓
