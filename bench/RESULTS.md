# ZTLP Performance Benchmark Results

## System Information

| Property | Value |
|----------|-------|
| Date | 2026-04-01 03:12:43 UTC |
| OS | Linux 5.15.0-1044-kvm x86_64 |
| CPU | AMD EPYC 4564P 16-Core Processor |
| CPU Cores | 2 |
| Memory | 7.8Gi |
| Elixir | Mix 1.12.2 (compiled with Erlang/OTP 24) |
| Erlang/OTP | 24 |
| Rust | rustc 1.94.1 (e408947bf 2026-03-25) |
| Cargo | cargo 1.94.1 (29ea6fb6a 2026-03-24) |

---

## Elixir Benchmarks

### Gateway: Pipeline Admission

```
Compiling 49 files (.ex)
Generated ztlp_gateway app

03:12:45.941 [info]  [ztlp-gateway] No config file found (checked /etc/ztlp/gateway.yaml), using defaults

03:12:45.945 [info]  [metrics] Gateway Prometheus endpoint on port 9102

03:12:45.945 [info]  [AuditCollector] Started (max_events=10000, retention_days=30)

03:12:45.945 [info]  [AuditCollectorServer] Audit HTTP API on 127.0.0.1:9104

03:12:45.945 [info]  [Listener] ZTLP Gateway listening on UDP port 23097

03:12:45.945 [info]  [RelayRegistrar] No ZTLP_RELAY_SERVER configured, relay registration disabled

03:12:45.945 [info]  [ServiceRegistrar] No ZTLP_NS_SERVER configured, NS registration disabled

03:12:45.946 [info]  [AdminDashboard] Listening on http://127.0.0.1:9105
=============================================================
  ZTLP Gateway Pipeline Benchmarks
=============================================================

--- Layer 1: Magic Byte Check ---

  Packet.valid_magic?/1 — valid ZTLP packet
  -----------------------------------------
  iterations:  50000
  total:       3867.4 µs
  mean:        77.3 ns
  median:      61 ns
  p99:         160 ns
  min:         58 ns
  max:         94395 ns
  throughput:  12928479.0 ops/sec

  Packet.valid_magic?/1 — invalid magic
  -------------------------------------
  iterations:  50000
  total:       3755.7 µs
  mean:        75.1 ns
  median:      61 ns
  p99:         191 ns
  min:         58 ns
  max:         107008 ns
  throughput:  13312952.0 ops/sec

  Pipeline.layer1_magic/1 — valid
  -------------------------------
  iterations:  50000
  total:       3963.7 µs
  mean:        79.3 ns
  median:      61 ns
  p99:         181 ns
  min:         58 ns
  max:         247541 ns
  throughput:  12614460.0 ops/sec

  Pipeline.layer1_magic/1 — reject bad magic
  ------------------------------------------
  iterations:  50000
  total:       3697.7 µs
  mean:        74.0 ns
  median:      61 ns
  p99:         181 ns
  min:         58 ns
  max:         47479 ns
  throughput:  13521890.0 ops/sec

  Pipeline.layer1_magic/1 — reject garbage
  ----------------------------------------
  iterations:  50000
  total:       3854.2 µs
  mean:        77.1 ns
  median:      61 ns
  p99:         170 ns
  min:         58 ns
  max:         165297 ns
  throughput:  12972770.0 ops/sec

--- Layer 2: SessionID Lookup ---

  Pipeline.layer2_session/1 — known session (100 sessions in ETS)
  ---------------------------------------------------------------
  iterations:  50000
  total:       11101.0 µs
  mean:        222.0 ns
  median:      200 ns
  p99:         511 ns
  min:         188 ns
  max:         27562 ns
  throughput:  4504092.0 ops/sec

  Pipeline.layer2_session/1 — unknown session (100 sessions)
  ----------------------------------------------------------
  iterations:  50000
  total:       10210.5 µs
  mean:        204.2 ns
  median:      180 ns
  p99:         341 ns
  min:         169 ns
  max:         48971 ns
  throughput:  4896931.0 ops/sec

  Pipeline.layer2_session/1 — known session (1000 sessions in ETS)
  ----------------------------------------------------------------
  iterations:  50000
  total:       11377.5 µs
  mean:        227.5 ns
  median:      200 ns
  p99:         571 ns
  min:         181 ns
  max:         83245 ns
  throughput:  4394652.0 ops/sec

  Pipeline.layer2_session/1 — unknown session (1000 sessions)
  -----------------------------------------------------------
  iterations:  50000
  total:       10655.9 µs
  mean:        213.1 ns
  median:      181 ns
  p99:         380 ns
  min:         169 ns
  max:         46336 ns
  throughput:  4692221.0 ops/sec

  Pipeline.layer2_session/1 — known session (10000 sessions in ETS)
  -----------------------------------------------------------------
  iterations:  50000
  total:       10434.8 µs
  mean:        208.7 ns
  median:      200 ns
  p99:         311 ns
  min:         179 ns
  max:         29746 ns
  throughput:  4791648.0 ops/sec

  Pipeline.layer2_session/1 — unknown session (10000 sessions)
  ------------------------------------------------------------
  iterations:  50000
  total:       9405.0 µs
  mean:        188.1 ns
  median:      180 ns
  p99:         271 ns
  min:         169 ns
  max:         25708 ns
  throughput:  5316322.0 ops/sec

  Pipeline.layer2_session/1 — HELLO packet (always pass)
  ------------------------------------------------------
  iterations:  50000
  total:       3808.3 µs
  mean:        76.2 ns
  median:      70 ns
  p99:         160 ns
  min:         58 ns
  max:         42980 ns
  throughput:  13129083.0 ops/sec

--- Full Pipeline Admission ---

  Pipeline.admit/1 — valid known session
  --------------------------------------
  iterations:  50000
  total:       10956.4 µs
  mean:        219.1 ns
  median:      210 ns
  p99:         360 ns
  min:         189 ns
  max:         34725 ns
  throughput:  4563561.0 ops/sec

  Pipeline.admit/1 — HELLO (new session)
  --------------------------------------
  iterations:  50000
  total:       4393.3 µs
  mean:        87.9 ns
  median:      80 ns
  p99:         170 ns
  min:         68 ns
  max:         125973 ns
  throughput:  11381026.0 ops/sec

  Pipeline.admit/1 — bad magic (rejected at L1)
  ---------------------------------------------
  iterations:  50000
  total:       3580.1 µs
  mean:        71.6 ns
  median:      69 ns
  p99:         161 ns
  min:         58 ns
  max:         41878 ns
  throughput:  13965930.0 ops/sec

  Pipeline.admit/1 — unknown session (rejected at L2)
  ---------------------------------------------------
  iterations:  50000
  total:       10269.0 µs
  mean:        205.4 ns
  median:      190 ns
  p99:         702 ns
  min:         178 ns
  max:         116065 ns
  throughput:  4869036.0 ops/sec

--- Packet Parsing ---

  Packet.parse/1 — data packet
  ----------------------------
  iterations:  50000
  total:       7920.6 µs
  mean:        158.4 ns
  median:      130 ns
  p99:         371 ns
  min:         119 ns
  max:         29505 ns
  throughput:  6312616.0 ops/sec

  Packet.parse/1 — handshake packet
  ---------------------------------
  iterations:  50000
  total:       9391.7 µs
  mean:        187.8 ns
  median:      151 ns
  p99:         320 ns
  min:         139 ns
  max:         1071460 ns
  throughput:  5323853.0 ops/sec

  Packet.extract_session_id/1
  ---------------------------
  iterations:  50000
  total:       5810.7 µs
  mean:        116.2 ns
  median:      80 ns
  p99:         391 ns
  min:         69 ns
  max:         61924 ns
  throughput:  8604832.0 ops/sec

  Packet.hello?/1 — HELLO
  -----------------------
  iterations:  50000
  total:       3910.3 µs
  mean:        78.2 ns
  median:      70 ns
  p99:         180 ns
  min:         58 ns
  max:         122368 ns
  throughput:  12786870.0 ops/sec

  Packet.hello?/1 — not HELLO
  ---------------------------
  iterations:  50000
  total:       3507.2 µs
  mean:        70.1 ns
  median:      61 ns
  p99:         81 ns
  min:         58 ns
  max:         133747 ns
  throughput:  14256379.0 ops/sec

=============================================================
  Pipeline benchmarks complete.
=============================================================
warning: unused alias Crypto
  bench/bench_pipeline.exs:63
```

### Gateway: Handshake & Crypto

```

03:12:46.521 [info]  [ztlp-gateway] No config file found (checked /etc/ztlp/gateway.yaml), using defaults

03:12:46.531 [info]  [metrics] Gateway Prometheus endpoint on port 9102

03:12:46.531 [info]  [AuditCollector] Started (max_events=10000, retention_days=30)

03:12:46.531 [info]  [AuditCollectorServer] Audit HTTP API on 127.0.0.1:9104

03:12:46.552 [info]  [Listener] ZTLP Gateway listening on UDP port 23097

03:12:46.552 [info]  [RelayRegistrar] No ZTLP_RELAY_SERVER configured, relay registration disabled

03:12:46.552 [info]  [ServiceRegistrar] No ZTLP_NS_SERVER configured, NS registration disabled

03:12:46.552 [info]  [AdminDashboard] Listening on http://127.0.0.1:9105
warning: variable "priv_b" is unused (if the variable is not meant to be used, prefix it with an underscore)
  bench/bench_handshake.exs:72

warning: variable "pub_a" is unused (if the variable is not meant to be used, prefix it with an underscore)
  bench/bench_handshake.exs:71

=============================================================
  ZTLP Gateway Handshake & Crypto Benchmarks
=============================================================

--- X25519 Key Operations ---

  Crypto.generate_keypair/0 (X25519)
  ----------------------------------
  iterations:  10000
  total:       286227.6 µs
  mean:        28622.8 ns
  median:      27671 ns
  p99:         42349 ns
  min:         27340 ns
  max:         107099 ns
  throughput:  34937.0 ops/sec

  Crypto.dh/2 (X25519 shared secret)
  ----------------------------------
  iterations:  10000
  total:       526894.5 µs
  mean:        52689.5 ns
  median:      51416 ns
  p99:         71252 ns
  min:         50423 ns
  max:         119593 ns
  throughput:  18979.0 ops/sec

--- ChaCha20-Poly1305 AEAD ---

  Crypto.encrypt/4 — 64B payload
  ------------------------------
  iterations:  10000
  total:       8245.3 µs
  mean:        824.5 ns
  median:      752 ns
  p99:         1493 ns
  min:         721 ns
  max:         19538 ns
  throughput:  1212818.0 ops/sec

  Crypto.decrypt/5 — 64B payload
  ------------------------------
  iterations:  10000
  total:       8331.8 µs
  mean:        833.2 ns
  median:      741 ns
  p99:         1533 ns
  min:         710 ns
  max:         49712 ns
  throughput:  1200222.0 ops/sec

  Crypto.encrypt/4 — 1KB payload
  ------------------------------
  iterations:  10000
  total:       10699.8 µs
  mean:        1070.0 ns
  median:      972 ns
  p99:         1593 ns
  min:         931 ns
  max:         29254 ns
  throughput:  9.346e5 ops/sec

  Crypto.decrypt/5 — 1KB payload
  ------------------------------
  iterations:  10000
  total:       10553.4 µs
  mean:        1055.3 ns
  median:      962 ns
  p99:         1412 ns
  min:         921 ns
  max:         33612 ns
  throughput:  947563.0 ops/sec

  Crypto.encrypt/4 — 8KB payload
  ------------------------------
  iterations:  10000
  total:       24632.6 µs
  mean:        2463.3 ns
  median:      2354 ns
  p99:         4168 ns
  min:         2244 ns
  max:         23502 ns
  throughput:  405966.0 ops/sec

  Crypto.decrypt/5 — 8KB payload
  ------------------------------
  iterations:  10000
  total:       24405.4 µs
  mean:        2440.5 ns
  median:      2335 ns
  p99:         3938 ns
  min:         2233 ns
  max:         26479 ns
  throughput:  409745.0 ops/sec

  Crypto.encrypt/4 — 64KB payload
  -------------------------------
  iterations:  10000
  total:       132183.8 µs
  mean:        13218.4 ns
  median:      12904 ns
  p99:         18566 ns
  min:         12603 ns
  max:         53810 ns
  throughput:  75652.0 ops/sec

  Crypto.decrypt/5 — 64KB payload
  -------------------------------
  iterations:  10000
  total:       131562.9 µs
  mean:        13156.3 ns
  median:      12875 ns
  p99:         17883 ns
  min:         12622 ns
  max:         44383 ns
  throughput:  76009.0 ops/sec

--- BLAKE2s / HMAC / HKDF ---

  Crypto.hash/1 (BLAKE2s) — 32 bytes
  ----------------------------------
  iterations:  50000
  total:       19518.0 µs
  mean:        390.4 ns
  median:      371 ns
  p99:         601 ns
  min:         340 ns
  max:         168133 ns
  throughput:  2561744.0 ops/sec

  Crypto.hash/1 (BLAKE2s) — 256 bytes
  -----------------------------------
  iterations:  50000
  total:       32786.1 µs
  mean:        655.7 ns
  median:      621 ns
  p99:         1092 ns
  min:         590 ns
  max:         113601 ns
  throughput:  1525038.0 ops/sec

  Crypto.hmac_blake2s/2 — 32 byte key + 32 byte data
  --------------------------------------------------
  iterations:  50000
  total:       102666.8 µs
  mean:        2053.3 ns
  median:      1923 ns
  p99:         3075 ns
  min:         1832 ns
  max:         261918 ns
  throughput:  487012.0 ops/sec

  Crypto.hkdf_extract/2
  ---------------------
  iterations:  50000
  total:       100997.1 µs
  mean:        2019.9 ns
  median:      1903 ns
  p99:         2996 ns
  min:         1823 ns
  max:         80510 ns
  throughput:  495064.0 ops/sec

  Crypto.hkdf_expand/3 — 64 bytes output
  --------------------------------------
  iterations:  50000
  total:       218831.1 µs
  mean:        4376.6 ns
  median:      3988 ns
  p99:         7143 ns
  min:         3857 ns
  max:         327167 ns
  throughput:  228487.0 ops/sec

  Crypto.hkdf_noise/2 — Noise chaining key update
  -----------------------------------------------
  iterations:  50000
  total:       293354.7 µs
  mean:        5867.1 ns
  median:      5480 ns
  p99:         10099 ns
  min:         5139 ns
  max:         130863 ns
  throughput:  170442.0 ops/sec

  Crypto.hkdf_noise_split/2 — Noise transport key split
  -----------------------------------------------------
  iterations:  50000
  total:       389316.8 µs
  mean:        7786.3 ns
  median:      7304 ns
  p99:         13515 ns
  min:         6883 ns
  max:         107489 ns
  throughput:  128430.0 ops/sec

--- Ed25519 Sign / Verify ---

  Crypto.generate_identity_keypair/0 (Ed25519)
  --------------------------------------------
  iterations:  5000
  total:       142829.6 µs
  mean:        28565.9 ns
  median:      28093 ns
  p99:         40324 ns
  min:         27933 ns
  max:         68678 ns
  throughput:  35007.0 ops/sec

  Crypto.sign/2 (Ed25519) — 128 byte message
  ------------------------------------------
  iterations:  5000
  total:       278390.2 µs
  mean:        55678.0 ns
  median:      55092 ns
  p99:         62767 ns
  min:         54651 ns
  max:         196978 ns
  throughput:  17960.0 ops/sec

  Crypto.verify/3 (Ed25519) — 128 byte message
  --------------------------------------------
  iterations:  5000
  total:       385631.8 µs
  mean:        77126.4 ns
  median:      76041 ns
  p99:         95819 ns
  min:         75150 ns
  max:         130914 ns
  throughput:  12966.0 ops/sec

--- Noise_XX Handshake (3-message round trip) ---

  Full Noise_XX handshake (init + 3 msgs + split)
  -----------------------------------------------
  iterations:  2000
  total:       935949.0 µs
  mean:        467974.5 ns
  median:      460877 ns
  p99:         577202 ns
  min:         446521 ns
  max:         627105 ns
  throughput:  2137.0 ops/sec

=============================================================
  Handshake & crypto benchmarks complete.
=============================================================
```

### Gateway: Throughput

```

03:12:51.343 [info]  [ztlp-gateway] No config file found (checked /etc/ztlp/gateway.yaml), using defaults

03:12:51.354 [info]  [metrics] Gateway Prometheus endpoint on port 9102

03:12:51.354 [info]  [AuditCollector] Started (max_events=10000, retention_days=30)

03:12:51.354 [info]  [AuditCollectorServer] Audit HTTP API on 127.0.0.1:9104

03:12:51.377 [info]  [Listener] ZTLP Gateway listening on UDP port 23097

03:12:51.377 [info]  [RelayRegistrar] No ZTLP_RELAY_SERVER configured, relay registration disabled

03:12:51.377 [info]  [ServiceRegistrar] No ZTLP_NS_SERVER configured, NS registration disabled

03:12:51.377 [info]  [AdminDashboard] Listening on http://127.0.0.1:9105
=============================================================
  ZTLP Gateway Throughput Benchmarks
=============================================================

--- Data Packet Decrypt Throughput ---

  Decrypt 64B payload (ChaCha20-Poly1305)
  ---------------------------------------
  iterations:  10000
  total:       7853.4 µs
  mean:        785.3 ns
  median:      751 ns
  p99:         1202 ns
  min:         730 ns
  max:         33463 ns
  throughput:  1273330.0 ops/sec

  Decrypt 1KB payload (ChaCha20-Poly1305)
  ---------------------------------------
  iterations:  10000
  total:       10756.0 µs
  mean:        1075.6 ns
  median:      982 ns
  p99:         1413 ns
  min:         941 ns
  max:         29075 ns
  throughput:  929718.0 ops/sec

  Decrypt 8KB payload (ChaCha20-Poly1305)
  ---------------------------------------
  iterations:  10000
  total:       24572.0 µs
  mean:        2457.2 ns
  median:      2355 ns
  p99:         4208 ns
  min:         2243 ns
  max:         26480 ns
  throughput:  406968.0 ops/sec

  Decrypt 64KB payload (ChaCha20-Poly1305)
  ----------------------------------------
  iterations:  10000
  total:       132916.3 µs
  mean:        13291.6 ns
  median:      12914 ns
  p99:         19426 ns
  min:         12713 ns
  max:         61384 ns
  throughput:  75235.0 ops/sec

--- Policy Engine Evaluation ---

  PolicyEngine.authorize?/2 — :all rule (always allow)
  ----------------------------------------------------
  iterations:  50000
  total:       8867.3 µs
  mean:        177.3 ns
  median:      160 ns
  p99:         290 ns
  min:         148 ns
  max:         165288 ns
  throughput:  5638668.0 ops/sec

  PolicyEngine.authorize?/2 — exact match (2 entries)
  ---------------------------------------------------
  iterations:  50000
  total:       10607.8 µs
  mean:        212.2 ns
  median:      190 ns
  p99:         450 ns
  min:         178 ns
  max:         112409 ns
  throughput:  4713519.0 ops/sec

  PolicyEngine.authorize?/2 — wildcard match
  ------------------------------------------
  iterations:  50000
  total:       14414.5 µs
  mean:        288.3 ns
  median:      270 ns
  p99:         501 ns
  min:         250 ns
  max:         14527 ns
  throughput:  3468721.0 ops/sec

  PolicyEngine.authorize?/2 — deny (no match)
  -------------------------------------------
  iterations:  50000
  total:       13415.2 µs
  mean:        268.3 ns
  median:      210 ns
  p99:         942 ns
  min:         189 ns
  max:         169195 ns
  throughput:  3727110.0 ops/sec

  PolicyEngine.authorize?/2 — deny (no rule for service)
  ------------------------------------------------------
  iterations:  50000
  total:       12048.8 µs
  mean:        241.0 ns
  median:      230 ns
  p99:         290 ns
  min:         219 ns
  max:         101308 ns
  throughput:  4149791.0 ops/sec

  PolicyEngine.authorize?/2 — large rule (10 patterns)
  ----------------------------------------------------
  iterations:  50000
  total:       15519.4 µs
  mean:        310.4 ns
  median:      290 ns
  p99:         521 ns
  min:         269 ns
  max:         17411 ns
  throughput:  3221775.0 ops/sec

  PolicyEngine.authorize?/2 — large rule miss
  -------------------------------------------
  iterations:  50000
  total:       19157.1 µs
  mean:        383.1 ns
  median:      361 ns
  p99:         601 ns
  min:         339 ns
  max:         14797 ns
  throughput:  2609998.0 ops/sec

--- Identity Resolution ---

  Identity.resolve/1 — cache hit
  ------------------------------
  iterations:  50000
  total:       9197.7 µs
  mean:        184.0 ns
  median:      170 ns
  p99:         341 ns
  min:         159 ns
  max:         54331 ns
  throughput:  5436126.0 ops/sec

  Identity.resolve/1 — cache miss (ETS miss, no NS)
  -------------------------------------------------
  iterations:  50000
  total:       7579.7 µs
  mean:        151.6 ns
  median:      141 ns
  p99:         191 ns
  min:         138 ns
  max:         172380 ns
  throughput:  6596580.0 ops/sec

  Identity.resolve_or_hex/1 — cache hit
  -------------------------------------
  iterations:  50000
  total:       9508.3 µs
  mean:        190.2 ns
  median:      170 ns
  p99:         360 ns
  min:         159 ns
  max:         31520 ns
  throughput:  5258541.0 ops/sec

  Identity.resolve_or_hex/1 — cache miss (hex fallback)
  -----------------------------------------------------
  iterations:  50000
  total:       30560.1 µs
  mean:        611.2 ns
  median:      531 ns
  p99:         1162 ns
  min:         491 ns
  max:         438113 ns
  throughput:  1636121.0 ops/sec

--- Combined: Decrypt + Policy Check ---

  Decrypt 1KB + resolve identity (cached) + authorize
  ---------------------------------------------------
  iterations:  10000
  total:       13629.0 µs
  mean:        1362.9 ns
  median:      1253 ns
  p99:         1972 ns
  min:         1202 ns
  max:         30617 ns
  throughput:  733731.0 ops/sec

=============================================================
  Gateway throughput benchmarks complete.
=============================================================
```

### ZTLP-NS: Namespace

```
Compiling 35 files (.ex)
Generated ztlp_ns app
03:12:52.935 [info] [ztlp-ns] No config file found (checked /etc/ztlp/ns.yaml), using defaults
03:12:52.937 [info] Application mnesia exited: :stopped
03:12:52.986 [info] [NS] Created Mnesia disk schema for nonode@nohost
03:12:53.084 [info] [metrics] NS Prometheus endpoint on port 9103
03:12:53.084 [info] [ztlp-ns] Started in standalone mode
warning: variable "node_priv" is unused (if the variable is not meant to be used, prefix it with an underscore)
  bench/bench_ns.exs:67

=============================================================
  ZTLP-NS Namespace Benchmarks
=============================================================

--- Record Serialization ---

  Record.serialize/1 — ZTLP_KEY record
  ------------------------------------
  iterations:  50000
  total:       91174.3 µs
  mean:        1823.5 ns
  median:      1452 ns
  p99:         17172 ns
  min:         1332 ns
  max:         385346 ns
  throughput:  5.484e5 ops/sec

  Record.deserialize/1 — ZTLP_KEY record
  --------------------------------------
  iterations:  50000
  total:       18629.7 µs
  mean:        372.6 ns
  median:      350 ns
  p99:         582 ns
  min:         319 ns
  max:         19837 ns
  throughput:  2683892.0 ops/sec

  Record.encode/1 — wire format (with sig)
  ----------------------------------------
  iterations:  50000
  total:       99153.4 µs
  mean:        1983.1 ns
  median:      1522 ns
  p99:         2986 ns
  min:         1411 ns
  max:         162783 ns
  throughput:  504269.0 ops/sec

  Record.decode/1 — wire format (with sig)
  ----------------------------------------
  iterations:  50000
  total:       20488.0 µs
  mean:        409.8 ns
  median:      381 ns
  p99:         731 ns
  min:         349 ns
  max:         41568 ns
  throughput:  2440447.0 ops/sec

--- Ed25519 Signature Verification ---

  Record.verify/1 — valid signature
  ---------------------------------
  iterations:  10000
  total:       792254.8 µs
  mean:        79225.5 ns
  median:      77344 ns
  p99:         97552 ns
  min:         75912 ns
  max:         277014 ns
  throughput:  12622.0 ops/sec

  Record.verify/1 — invalid signature (tampered)
  ----------------------------------------------
  iterations:  10000
  total:       792929.0 µs
  mean:        79292.9 ns
  median:      77535 ns
  p99:         98083 ns
  min:         75951 ns
  max:         272767 ns
  throughput:  12611.0 ops/sec

  Crypto.generate_keypair/0 (Ed25519)
  -----------------------------------
  iterations:  5000
  total:       142495.7 µs
  mean:        28499.1 ns
  median:      27963 ns
  p99:         39063 ns
  min:         27651 ns
  max:         48971 ns
  throughput:  35089.0 ops/sec

  Crypto.sign/2 — 128 byte message
  --------------------------------
  iterations:  5000
  total:       280373.6 µs
  mean:        56074.7 ns
  median:      55081 ns
  p99:         65261 ns
  min:         54451 ns
  max:         253902 ns
  throughput:  17833.0 ops/sec

  Crypto.verify/3 — 128 byte message
  ----------------------------------
  iterations:  5000
  total:       377633.7 µs
  mean:        75526.7 ns
  median:      74679 ns
  p99:         87072 ns
  min:         73567 ns
  max:         108021 ns
  throughput:  13240.0 ops/sec

--- Store Insert Throughput ---

  Store.insert/1 — signed ZTLP_KEY records (serial insert)
  --------------------------------------------------------
03:12:56.056 [error] Task #PID<0.589.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:56.063 [error] Task #PID<0.625.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:56.249 [error] Task #PID<0.1562.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:56.300 [error] Task #PID<0.1803.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:56.349 [warn] Mnesia(:nonode@nohost): ** WARNING ** Mnesia is overloaded: {:dump_log, :write_threshold}

03:12:56.502 [error] Task #PID<0.2817.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:56.506 [warn] Mnesia(:nonode@nohost): ** WARNING ** Mnesia is overloaded: {:dump_log, :write_threshold}

03:12:56.640 [warn] Mnesia(:nonode@nohost): ** WARNING ** Mnesia is overloaded: {:dump_log, :write_threshold}

03:12:56.856 [error] Task #PID<0.4595.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:56.872 [error] Task #PID<0.4673.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:56.907 [warn] Mnesia(:nonode@nohost): ** WARNING ** Mnesia is overloaded: {:dump_log, :write_threshold}

03:12:57.014 [error] Task #PID<0.5361.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
  iterations:  5000
  total:       1035950.1 µs
  mean:        207190.0 ns
  median:      190644 ns
  p99:         421001 ns
  min:         170386 ns
  max:         2086828 ns
  throughput:  4826.0 ops/sec

--- Store Lookup Throughput ---
03:12:57.290 [error] Task #PID<0.6652.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
03:12:57.310 [warn] Mnesia(:nonode@nohost): ** WARNING ** Mnesia is overloaded: {:dump_log, :write_threshold}


  Store.lookup/2 — known record (ETS hit)
  ---------------------------------------
  iterations:  50000
  total:       33141.2 µs
  mean:        662.8 ns
  median:      601 ns
  p99:         971 ns
  min:         580 ns
  max:         32529 ns
  throughput:  1508695.0 ops/sec

  Store.lookup/2 — unknown record (ETS miss)
  ------------------------------------------
  iterations:  50000
  total:       25741.8 µs
  mean:        514.8 ns
  median:      471 ns
  p99:         901 ns
  min:         459 ns
  max:         49181 ns
  throughput:  1942365.0 ops/sec

--- Query (Lookup + Verify) ---

  Query.lookup/2 — known record (lookup + sig verify)
  ---------------------------------------------------
  iterations:  10000
  total:       816036.2 µs
  mean:        81603.6 ns
  median:      79239 ns
  p99:         103181 ns
  min:         77233 ns
  max:         320865 ns
  throughput:  12254.0 ops/sec

  Query.lookup/2 — unknown record
  -------------------------------
  iterations:  10000
  total:       5085.7 µs
  mean:        508.6 ns
  median:      471 ns
  p99:         901 ns
  min:         459 ns
  max:         16409 ns
  throughput:  1966279.0 ops/sec

--- Trust Chain Verification ---

  Query.lookup_verified/2 — 1-level chain (zone → root)
  -----------------------------------------------------
03:12:58.327 [error] Task #PID<0.7150.0> started from #PID<0.94.0> terminating
** (ArgumentError) errors were found at the given arguments:

  * 1st argument: invalid table name (must be an atom)

    (stdlib 3.17) :ets.whereis(:ztlp_ns_replication_metrics)
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:100: ZtlpNs.Replication.ensure_metrics_table/0
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:90: ZtlpNs.Replication.increment_metric/1
    (ztlp_ns 0.23.0) lib/ztlp_ns/replication.ex:30: ZtlpNs.Replication.replicate/1
    (elixir 1.12.2) lib/task/supervised.ex:90: Task.Supervised.invoke_mfa/2
    (stdlib 3.17) proc_lib.erl:226: :proc_lib.init_p_do_apply/3
Function: #Function<1.127814584/0 in ZtlpNs.Replication.replicate_async/1>
    Args: []
  iterations:  2000
  total:       329596.3 µs
  mean:        164798.1 ns
  median:      159997 ns
  p99:         245757 ns
  min:         157703 ns
  max:         330535 ns
  throughput:  6068.0 ops/sec

  Query.lookup_verified/2 — 2-level chain (zone → org → root)
  -----------------------------------------------------------
  iterations:  1000
  total:       248020.4 µs
  mean:        248020.4 ns
  median:      242651 ns
  p99:         312200 ns
  min:         237060 ns
  max:         1560109 ns
  throughput:  4032.0 ops/sec

--- TrustAnchor Operations ---

  TrustAnchor.trusted?/1 — known anchor
  -------------------------------------
  iterations:  50000
  total:       42091.6 µs
  mean:        841.8 ns
  median:      821 ns
  p99:         1013 ns
  min:         790 ns
  max:         21239 ns
  throughput:  1187885.0 ops/sec

  TrustAnchor.trusted?/1 — unknown key
  ------------------------------------
  iterations:  50000
  total:       42376.3 µs
  mean:        847.5 ns
  median:      821 ns
  p99:         1132 ns
  min:         790 ns
  max:         38781 ns
  throughput:  1179906.0 ops/sec

=============================================================
  ZTLP-NS benchmarks complete.
=============================================================
```

### Relay: Pipeline & Packet Processing

```
Compiling 37 files (.ex)
Generated ztlp_relay app

03:13:00.363 [info]  [ztlp-relay] No config file found (checked /etc/ztlp/relay.yaml), using defaults

03:13:00.368 [info]  [metrics] Prometheus endpoint listening on port 9101

03:13:00.369 [info]  ZTLP Relay listening on 0.0.0.0:23095
warning: variable "garbage" is unused (if the variable is not meant to be used, prefix it with an underscore)
  bench/bench_relay.exs:86

=============================================================
  ZTLP Relay Benchmarks
=============================================================

--- Layer 1: Magic Byte Check ---

  Packet.valid_magic?/1 — valid
  -----------------------------
  iterations:  50000
  total:       4074.1 µs
  mean:        81.5 ns
  median:      61 ns
  p99:         180 ns
  min:         58 ns
  max:         250906 ns
  throughput:  12272770.0 ops/sec

  Packet.valid_magic?/1 — invalid
  -------------------------------
  iterations:  50000
  total:       3667.0 µs
  mean:        73.3 ns
  median:      61 ns
  p99:         190 ns
  min:         58 ns
  max:         76142 ns
  throughput:  13635039.0 ops/sec

  Pipeline.layer1_magic/1 — valid
  -------------------------------
  iterations:  50000
  total:       3974.0 µs
  mean:        79.5 ns
  median:      69 ns
  p99:         311 ns
  min:         58 ns
  max:         303893 ns
  throughput:  12581706.0 ops/sec

  Pipeline.layer1_magic/1 — reject
  --------------------------------
  iterations:  50000
  total:       4059.7 µs
  mean:        81.2 ns
  median:      69 ns
  p99:         221 ns
  min:         58 ns
  max:         71072 ns
  throughput:  12316214.0 ops/sec

--- Layer 2: SessionID Lookup ---

  Pipeline.layer2_session/1 — known session (100+ sessions)
  ---------------------------------------------------------
  iterations:  50000
  total:       12899.3 µs
  mean:        258.0 ns
  median:      221 ns
  p99:         561 ns
  min:         209 ns
  max:         139290 ns
  throughput:  3876178.0 ops/sec

  Pipeline.layer2_session/1 — unknown session (100+ sessions)
  -----------------------------------------------------------
  iterations:  50000
  total:       11424.2 µs
  mean:        228.5 ns
  median:      211 ns
  p99:         351 ns
  min:         200 ns
  max:         82183 ns
  throughput:  4376682.0 ops/sec

  Pipeline.layer2_session/1 — known session (1000+ sessions)
  ----------------------------------------------------------
  iterations:  50000
  total:       11615.5 µs
  mean:        232.3 ns
  median:      220 ns
  p99:         340 ns
  min:         209 ns
  max:         19246 ns
  throughput:  4304592.0 ops/sec

  Pipeline.layer2_session/1 — unknown session (1000+ sessions)
  ------------------------------------------------------------
  iterations:  50000
  total:       11443.8 µs
  mean:        228.9 ns
  median:      211 ns
  p99:         361 ns
  min:         200 ns
  max:         77585 ns
  throughput:  4369168.0 ops/sec

  Pipeline.layer2_session/1 — known session (10000+ sessions)
  -----------------------------------------------------------
  iterations:  50000
  total:       11503.2 µs
  mean:        230.1 ns
  median:      220 ns
  p99:         251 ns
  min:         209 ns
  max:         59581 ns
  throughput:  4346615.0 ops/sec

  Pipeline.layer2_session/1 — unknown session (10000+ sessions)
  -------------------------------------------------------------
  iterations:  50000
  total:       11465.6 µs
  mean:        229.3 ns
  median:      211 ns
  p99:         310 ns
  min:         209 ns
  max:         108171 ns
  throughput:  4360872.0 ops/sec

  Pipeline.layer2_session/1 — HELLO (always pass)
  -----------------------------------------------
  iterations:  50000
  total:       3735.9 µs
  mean:        74.7 ns
  median:      70 ns
  p99:         160 ns
  min:         59 ns
  max:         113721 ns
  throughput:  13383631.0 ops/sec

--- Layer 3: HeaderAuthTag Verification ---

  Crypto.compute_header_auth_tag/2 — handshake header AAD
  -------------------------------------------------------
  iterations:  10000
  total:       7019.8 µs
  mean:        702.0 ns
  median:      672 ns
  p99:         982 ns
  min:         641 ns
  max:         73897 ns
  throughput:  1424552.0 ops/sec

  Crypto.verify_header_auth_tag/3 — valid tag
  -------------------------------------------
  iterations:  10000
  total:       6746.3 µs
  mean:        674.6 ns
  median:      662 ns
  p99:         921 ns
  min:         641 ns
  max:         14847 ns
  throughput:  1482291.0 ops/sec

  Crypto.verify_header_auth_tag/3 — invalid tag
  ---------------------------------------------
  iterations:  10000
  total:       6826.5 µs
  mean:        682.7 ns
  median:      671 ns
  p99:         982 ns
  min:         641 ns
  max:         17904 ns
  throughput:  1464876.0 ops/sec

--- Full Pipeline ---

  Pipeline.process/2 — valid data packet (no auth, relay mode)
  ------------------------------------------------------------
  iterations:  20000
  total:       30930.1 µs
  mean:        1546.5 ns
  median:      1392 ns
  p99:         2746 ns
  min:         1302 ns
  max:         26740 ns
  throughput:  646619.0 ops/sec

  Pipeline.process/2 — valid data packet (with auth)
  --------------------------------------------------
  iterations:  10000
  total:       27102.5 µs
  mean:        2710.2 ns
  median:      2496 ns
  p99:         4578 ns
  min:         2294 ns
  max:         57226 ns
  throughput:  368970.0 ops/sec

  Pipeline.process/2 — HELLO packet
  ---------------------------------
  iterations:  20000
  total:       27221.2 µs
  mean:        1361.1 ns
  median:      1202 ns
  p99:         2503 ns
  min:         1131 ns
  max:         48921 ns
  throughput:  734722.0 ops/sec

  Pipeline.process/2 — bad magic (L1 reject)
  ------------------------------------------
  iterations:  50000
  total:       59201.2 µs
  mean:        1184.0 ns
  median:      1082 ns
  p99:         1853 ns
  min:         951 ns
  max:         42489 ns
  throughput:  844578.0 ops/sec

  Pipeline.process/2 — unknown session (L2 reject)
  ------------------------------------------------
  iterations:  20000
  total:       30937.2 µs
  mean:        1546.9 ns
  median:      1472 ns
  p99:         2685 ns
  min:         1192 ns
  max:         83396 ns
  throughput:  646472.0 ops/sec

--- Packet Parsing & Serialization ---

  Packet.parse/1 — handshake header
  ---------------------------------
  iterations:  50000
  total:       8646.2 µs
  mean:        172.9 ns
  median:      160 ns
  p99:         270 ns
  min:         139 ns
  max:         31909 ns
  throughput:  5782897.0 ops/sec

  Packet.parse/1 — data compact header
  ------------------------------------
  iterations:  50000
  total:       8006.3 µs
  mean:        160.1 ns
  median:      130 ns
  p99:         401 ns
  min:         119 ns
  max:         17141 ns
  throughput:  6245086.0 ops/sec

  Packet.serialize/1 — handshake
  ------------------------------
  iterations:  50000
  total:       13702.1 µs
  mean:        274.0 ns
  median:      221 ns
  p99:         450 ns
  min:         209 ns
  max:         417385 ns
  throughput:  3649084.0 ops/sec

  Packet.serialize/1 — data compact
  ---------------------------------
  iterations:  50000
  total:       10686.6 µs
  mean:        213.7 ns
  median:      161 ns
  p99:         391 ns
  min:         148 ns
  max:         134731 ns
  throughput:  4678759.0 ops/sec

  Packet.extract_session_id/1
  ---------------------------
  iterations:  50000
  total:       5031.3 µs
  mean:        100.6 ns
  median:      80 ns
  p99:         220 ns
  min:         69 ns
  max:         128398 ns
  throughput:  9937752.0 ops/sec

  Packet.extract_aad/1 — data header
  ----------------------------------
  iterations:  50000
  total:       8507.6 µs
  mean:        170.2 ns
  median:      150 ns
  p99:         381 ns
  min:         130 ns
  max:         245326 ns
  throughput:  5877122.0 ops/sec

--- Session Registry Operations ---

  SessionRegistry.session_exists?/1 — known
  -----------------------------------------
  iterations:  50000
  total:       9501.7 µs
  mean:        190.0 ns
  median:      180 ns
  p99:         241 ns
  min:         169 ns
  max:         359518 ns
  throughput:  5262231.0 ops/sec

  SessionRegistry.session_exists?/1 — unknown
  -------------------------------------------
  iterations:  50000
  total:       8735.3 µs
  mean:        174.7 ns
  median:      170 ns
  p99:         200 ns
  min:         160 ns
  max:         28362 ns
  throughput:  5723884.0 ops/sec

  SessionRegistry.lookup_session/1 — known
  ----------------------------------------
  iterations:  50000
  total:       11179.0 µs
  mean:        223.6 ns
  median:      201 ns
  p99:         451 ns
  min:         188 ns
  max:         123079 ns
  throughput:  4472676.0 ops/sec

  SessionRegistry.lookup_peer/2 — known peer
  ------------------------------------------
  iterations:  50000
  total:       12510.4 µs
  mean:        250.2 ns
  median:      220 ns
  p99:         571 ns
  min:         209 ns
  max:         62005 ns
  throughput:  3996688.0 ops/sec

=============================================================
  Relay benchmarks complete.
=============================================================
```

---

## Rust Benchmarks (Proto)

```
warning: field `send_seq` is never read
  --> src/send_controller.rs:43:5
   |
37 | struct SendEntry {
   |        --------- field in this struct
...
43 |     send_seq: u64,
   |     ^^^^^^^^
   |
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: `ztlp-proto` (lib) generated 1 warning
    Finished `release` profile [optimized] target(s) in 0.87s
     Running `target/release/ztlp-bench`
=============================================================
  ZTLP Proto (Rust) Benchmarks
=============================================================

--- Layer 1: Magic Check ---

  layer1_magic_check — valid ZTLP
  ---------------------------------
  iterations:  100000
  total:       1835.4 µs
  mean:        18.4 ns
  median:      20 ns
  p99:         21 ns
  min:         8 ns
  max:         5651 ns
  throughput:  54483442 ops/sec

  layer1_magic_check — bad magic
  --------------------------------
  iterations:  100000
  total:       1834.8 µs
  mean:        18.3 ns
  median:      20 ns
  p99:         21 ns
  min:         9 ns
  max:         9788 ns
  throughput:  54502002 ops/sec

  layer1_magic_check — garbage
  ------------------------------
  iterations:  100000
  total:       1846.7 µs
  mean:        18.5 ns
  median:      20 ns
  p99:         21 ns
  min:         8 ns
  max:         25728 ns
  throughput:  54149621 ops/sec

--- Layer 2: Session Lookup ---

  layer2_session_check — known (100 sessions)
  ---------------------------------------------
  iterations:  50000
  total:       1459.4 µs
  mean:        29.2 ns
  median:      30 ns
  p99:         31 ns
  min:         19 ns
  max:         19146 ns
  throughput:  34260984 ops/sec

  layer2_session_check — unknown (100 sessions)
  -----------------------------------------------
  iterations:  50000
  total:       1316.5 µs
  mean:        26.3 ns
  median:      30 ns
  p99:         31 ns
  min:         18 ns
  max:         7344 ns
  throughput:  37979837 ops/sec

  layer2_session_check — known (1000 sessions)
  ----------------------------------------------
  iterations:  50000
  total:       1407.6 µs
  mean:        28.2 ns
  median:      30 ns
  p99:         31 ns
  min:         18 ns
  max:         14107 ns
  throughput:  35522187 ops/sec

  layer2_session_check — unknown (1000 sessions)
  ------------------------------------------------
  iterations:  50000
  total:       1303.4 µs
  mean:        26.1 ns
  median:      29 ns
  p99:         31 ns
  min:         18 ns
  max:         4840 ns
  throughput:  38360179 ops/sec

  layer2_session_check — known (10000 sessions)
  -----------------------------------------------
  iterations:  50000
  total:       1404.9 µs
  mean:        28.1 ns
  median:      30 ns
  p99:         31 ns
  min:         18 ns
  max:         14567 ns
  throughput:  35589798 ops/sec

  layer2_session_check — unknown (10000 sessions)
  -------------------------------------------------
  iterations:  50000
  total:       1311.7 µs
  mean:        26.2 ns
  median:      29 ns
  p99:         31 ns
  min:         19 ns
  max:         18823 ns
  throughput:  38118879 ops/sec

  layer2_session_check — HELLO (pass-through)
  ---------------------------------------------
  iterations:  50000
  total:       958.0 µs
  mean:        19.2 ns
  median:      20 ns
  p99:         21 ns
  min:         9 ns
  max:         5009 ns
  throughput:  52193810 ops/sec

--- Layer 3: HeaderAuthTag Verification ---

  compute_header_auth_tag
  -----------------------
  iterations:  50000
  total:       40856.4 µs
  mean:        817.1 ns
  median:      802 ns
  p99:         851 ns
  min:         790 ns
  max:         21779 ns
  throughput:  1223798 ops/sec

  layer3_auth_check — valid tag
  -------------------------------
  iterations:  20000
  total:       17014.7 µs
  mean:        850.7 ns
  median:      841 ns
  p99:         872 ns
  min:         821 ns
  max:         22772 ns
  throughput:  1175455 ops/sec

--- Full Pipeline ---

  pipeline.process — valid data packet (full 3 layers)
  ------------------------------------------------------
  iterations:  20000
  total:       17260.9 µs
  mean:        863.0 ns
  median:      851 ns
  p99:         872 ns
  min:         840 ns
  max:         18033 ns
  throughput:  1158689 ops/sec

  pipeline.process — HELLO
  --------------------------
  iterations:  50000
  total:       1191.2 µs
  mean:        23.8 ns
  median:      20 ns
  p99:         31 ns
  min:         18 ns
  max:         19155 ns
  throughput:  41974021 ops/sec

  pipeline.process — bad magic (L1 reject)
  ------------------------------------------
  iterations:  100000
  total:       2771.1 µs
  mean:        27.7 ns
  median:      30 ns
  p99:         31 ns
  min:         18 ns
  max:         16140 ns
  throughput:  36087391 ops/sec

--- Noise_XX Handshake ---

  Full Noise_XX handshake (3 messages + finalize)
  -----------------------------------------------
  iterations:  1000
  total:       286886.1 µs
  mean:        286886.1 ns
  median:      285591 ns
  p99:         312621 ns
  min:         275422 ns
  max:         325275 ns
  throughput:  3486 ops/sec

--- ChaCha20-Poly1305 Encrypt/Decrypt ---

  encrypt 64B payload
  -------------------
  iterations:  10000
  total:       11544.8 µs
  mean:        1154.5 ns
  median:      1142 ns
  p99:         1233 ns
  min:         1122 ns
  max:         8186 ns
  throughput:  866187 ops/sec

  decrypt 64B payload
  -------------------
  iterations:  10000
  total:       11453.5 µs
  mean:        1145.4 ns
  median:      1132 ns
  p99:         1283 ns
  min:         1121 ns
  max:         6753 ns
  throughput:  873092 ops/sec

  encrypt 1KB payload
  -------------------
  iterations:  10000
  total:       15824.8 µs
  mean:        1582.5 ns
  median:      1563 ns
  p99:         1844 ns
  min:         1542 ns
  max:         8416 ns
  throughput:  631918 ops/sec

  decrypt 1KB payload
  -------------------
  iterations:  10000
  total:       15740.2 µs
  mean:        1574.0 ns
  median:      1553 ns
  p99:         1854 ns
  min:         1532 ns
  max:         14787 ns
  throughput:  635315 ops/sec

  encrypt 8KB payload
  -------------------
  iterations:  10000
  total:       51028.2 µs
  mean:        5102.8 ns
  median:      5018 ns
  p99:         6422 ns
  min:         4938 ns
  max:         16671 ns
  throughput:  195970 ops/sec

  decrypt 8KB payload
  -------------------
  iterations:  10000
  total:       50892.8 µs
  mean:        5089.3 ns
  median:      5029 ns
  p99:         6282 ns
  min:         4949 ns
  max:         13976 ns
  throughput:  196491 ops/sec

  encrypt 64KB payload
  --------------------
  iterations:  10000
  total:       333561.4 µs
  mean:        33356.1 ns
  median:      32992 ns
  p99:         41116 ns
  min:         32490 ns
  max:         63838 ns
  throughput:  29979 ops/sec

  decrypt 64KB payload
  --------------------
  iterations:  10000
  total:       334192.2 µs
  mean:        33419.2 ns
  median:      33082 ns
  p99:         39464 ns
  min:         32440 ns
  max:         51576 ns
  throughput:  29923 ops/sec

--- Identity Generation ---

  NodeId::generate()
  ------------------
  iterations:  50000
  total:       1231.5 µs
  mean:        24.6 ns
  median:      20 ns
  p99:         71 ns
  min:         18 ns
  max:         4188 ns
  throughput:  40600992 ops/sec

  NodeIdentity::generate() (NodeID + X25519 keypair)
  --------------------------------------------------
  iterations:  5000
  total:       59160.6 µs
  mean:        11832.1 ns
  median:      11662 ns
  p99:         16209 ns
  min:         11520 ns
  max:         29686 ns
  throughput:  84516 ops/sec

  SessionId::generate()
  ---------------------
  iterations:  50000
  total:       1358.8 µs
  mean:        27.2 ns
  median:      21 ns
  p99:         71 ns
  min:         18 ns
  max:         4519 ns
  throughput:  36797661 ops/sec

--- Packet Serialize / Deserialize ---

  HandshakeHeader::serialize()
  ----------------------------
  iterations:  50000
  total:       1279.1 µs
  mean:        25.6 ns
  median:      29 ns
  p99:         31 ns
  min:         18 ns
  max:         4970 ns
  throughput:  39091391 ops/sec

  HandshakeHeader::deserialize()
  ------------------------------
  iterations:  50000
  total:       1273.4 µs
  mean:        25.5 ns
  median:      29 ns
  p99:         31 ns
  min:         19 ns
  max:         5470 ns
  throughput:  39266409 ops/sec

  DataHeader::serialize()
  -----------------------
  iterations:  50000
  total:       1267.4 µs
  mean:        25.3 ns
  median:      29 ns
  p99:         31 ns
  min:         19 ns
  max:         4709 ns
  throughput:  39450408 ops/sec

  DataHeader::deserialize()
  -------------------------
  iterations:  50000
  total:       1188.5 µs
  mean:        23.8 ns
  median:      21 ns
  p99:         31 ns
  min:         18 ns
  max:         4147 ns
  throughput:  42070296 ops/sec

  Data packet serialize + deserialize round-trip
  ----------------------------------------------
  iterations:  50000
  total:       1656.9 µs
  mean:        33.1 ns
  median:      30 ns
  p99:         41 ns
  min:         29 ns
  max:         4277 ns
  throughput:  30177528 ops/sec

=============================================================
  Rust benchmarks complete.
=============================================================
```

---

## Throughput Benchmarks (GSO/GRO)

```
warning: field `send_seq` is never read
  --> src/send_controller.rs:43:5
   |
37 | struct SendEntry {
   |        --------- field in this struct
...
43 |     send_seq: u64,
   |     ^^^^^^^^
   |
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: `ztlp-proto` (lib) generated 1 warning
    Finished `release` profile [optimized] target(s) in 0.05s
     Running `target/release/ztlp-throughput --mode all --size 104857600 --repeat 3`

ZTLP Throughput Benchmark
═══════════════════════════════════════════════════════
Transfer size: 100.0 MB
System: Linux 5.15.0-1044-kvm (GSO: unavailable, GRO: available)
Iterations: 3

Mode                   Throughput       Time    Packets   Overhead
────────────────────────────────────────────────────────────────
Raw TCP                 7.96 GB/s     12.3ms        N/A   baseline
[2m2026-04-01T03:13:03.554276Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:03.554321Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:03.554325Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:03.650672Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:03.650689Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:03.650691Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:04.990151Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:04.990177Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:04.990182Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:05.087126Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:05.087145Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:05.087147Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:06.432422Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:06.432460Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:06.432464Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:06.528985Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:06.529029Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:06.529037Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
ZTLP (no GSO)             84 MB/s       1.2s      6,404      99.0%
[2m2026-04-01T03:13:07.866706Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:07.866726Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:07.866733Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:07.963799Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:07.963814Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:07.963816Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:09.291090Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:09.291117Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:09.291122Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:09.389524Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:09.389544Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:09.389545Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:10.731611Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:10.731637Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:10.731641Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:10.828763Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:10.828790Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:10.828795Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
ZTLP (GRO only)           85 MB/s       1.2s      6,404      99.0%
[2m2026-04-01T03:13:12.145776Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:12.145794Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:12.145799Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:12.243567Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:12.243590Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:12.243592Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:13.563194Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:13.563219Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:13.563223Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:13.660405Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:13.660435Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:13.660441Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:14.985148Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:14.985175Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:14.985179Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
[2m2026-04-01T03:13:15.083389Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m UDP receive buffer is 416KB (target: 7168KB). Throughput may be reduced.
[2m2026-04-01T03:13:15.083405Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m To fix: sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
[2m2026-04-01T03:13:15.083407Z[0m [33m WARN[0m [2mztlp_proto::pacing[0m[2m:[0m Or run: ztlp tune (applies optimal kernel settings)
ZTLP (auto)               86 MB/s       1.2s      6,404      98.9%
```

---

## Analysis

_Analysis will be written after benchmarks run._

