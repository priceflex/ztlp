# NE Throttle + Logger Analysis — 2026-04-12

## Summary

The handoff plan correctly identifies the 12MB soft limit as too low (steady state
is 18-21MB). But there are THREE interacting problems, not one. The logger is the
biggest hidden contributor to memory pressure.

## Problem 1: TunnelLogger is catastrophically expensive in the NE hot path

### The appendLine() read-modify-write pattern

Every single `logger.debug()`/`.warn()`/`.info()` call in the NE does this:

```
1. Read ENTIRE log file from disk (~500KB at 5000 lines)
2. Parse into String
3. Split by newline into [String] array (5000 String allocations)
4. Append 1 new line
5. Check count > 5000, create suffix array if needed
6. Join all lines back into single String (~500KB allocation)
7. Write ENTIRE file atomically to disk (~500KB + temp file)
8. Post NotificationCenter notification on main thread
```

### How many times per packet?

There are 100 logger calls in PacketTunnelProvider.swift alone, with ~51 in hot
path functions. Per packet flowing through the NE:

- readPacketLoop: "received N packets" + "Pkt: dst=..." + "Router: N actions" = 3
- processRouterActions: per-action log (OpenStream/SendData/CloseStream) + mux frame = 2
- Plus throttle warnings when those fire = 2 more

Conservative: **5 log calls per packet** in the normal flow.

### Memory impact

At 5000-line log file (~586KB):
- Per log call: read 586KB + 5000 String allocs + join 586KB + write 586KB
- Per packet: ~8.6 MB of transient allocations (5 calls × 3 × 586KB)
- At 10 packets/sec: ~86 MB/s allocation churn, 50 file I/O ops/sec
- At 100 packets/sec: ~858 MB/s allocation churn, 500 file I/O ops/sec

Even though ARC frees these allocations, the peak resident memory spikes because:
- Multiple log calls overlap on the serial queue
- Each creates ~1.2MB of transient objects (read string + array + write string)
- iOS counts peak RSS for jetsam, not average

This is almost certainly why steady-state NE memory sits at 18-21MB when the
binary + framework overhead should be ~10-12MB. The gap is logger allocation
pressure keeping 5-10MB of transient strings alive at any given moment.

### Evidence from bootstrap benchmarks

- Benchmark #26 (8/8 PASSED): 416KB device_logs, 0 throttle messages, 20MB resident
- Benchmark #30 (manual dump): 59KB device_logs, 190 throttle messages, 21MB resident
- Benchmark #27 (0/8 FAILED): 417KB device_logs, 0 throttle messages, 20MB resident

The 416KB log payloads in the successful runs show MASSIVE debug output
(every packet logged). Each of those log lines caused a full file rewrite.

## Problem 2: Memory throttle is self-defeating

The `shouldThrottleRouterWork()` function:
- Calls `task_info()` (Mach kernel syscall) via `currentResidentMemoryMB()` 
- Called in 4 hot paths: readPacketLoop, processRouterActions (2×), flushOutbound
- When memory >= 12MB: logs a WARN (which triggers the expensive appendLine!)
- Then returns true, which logs ANOTHER debug line ("throttling router work...")

So when memory is high, the throttle check:
1. Makes a syscall (overhead)
2. Logs a warning (500KB read + write, MORE memory pressure)
3. Logs a debug message (ANOTHER 500KB read + write)
4. Breaks out of the packet loop (blocking traffic)

The throttle literally makes the memory problem worse by generating more logs.

In benchmark #30: 190 throttle messages × 2 log calls each = 380 extra
file-rewrite cycles, each allocating ~1.2MB transiently. That's ~456MB of
extra allocation churn CAUSED BY the throttle trying to reduce memory.

## Problem 3: DNS responder failures (separate bug)

Benchmark #27 (0/8) failed with zero throttle messages. Cause: repeated
"DNS query matched but no response generated" in the logs. The DNS responder's
`handleQuery()` returned nil despite `isDNSQuery()` matching. This is a separate
code path bug unrelated to memory.

## Recommended Fix (3 parts)

### Part 1: Fix the logger (HIGHEST IMPACT)

Replace the read-modify-write appendLine() with append-only file I/O:

```swift
private func appendLine(_ line: String) {
    guard let url = logFileURL else { return }
    let data = (line + "\n").data(using: .utf8)!
    
    if let handle = try? FileHandle(forWritingTo: url) {
        handle.seekToEndOfFile()
        handle.write(data)
        handle.closeFile()
    } else {
        // File doesn't exist yet — create it
        try? data.write(to: url, atomically: false)
    }
}
```

Move the rotation check to a separate periodic task (every 60 seconds or on
explicit flush), NOT per-line. This changes per-log-call cost from ~1.2MB
allocation + full file I/O to ~100 bytes append.

Also: Gate debug-level logs in NE behind a compile flag or runtime toggle.
In production, the NE should only log INFO and above. The per-packet "Pkt: dst=..."
and "received N packets" lines are development diagnostics — they generate enormous
I/O with zero value in production.

### Part 2: Remove memory-based throttle

Replace shouldThrottleRouterWork():

```swift
private func shouldThrottleRouterWork() -> Bool {
    if let tunnelConnection, tunnelConnection.isOverloaded {
        logger.debug("Router throttle: tunnelConnection overloaded", source: "Tunnel")
        return true
    }
    return false
}
```

Keep memory logging in the periodic `logMemoryDiagnostics()` for visibility.
Remove the per-packet `task_info()` syscall entirely.

### Part 3: Fix DNS responder (separate bug)

Investigate why `handleQuery()` returns nil when `isDNSQuery()` matches.
This caused 0/8 benchmark failure in #27 independent of memory.

## Expected Impact

- Logger fix: NE memory should drop 3-8MB (eliminating transient string pressure)
- Throttle removal: traffic flows normally at 18-21MB (proven working in benchmarks #25, #26)
- Combined: NE should sit at ~12-15MB steady state, well under any jetsam limit

## Evidence Table

| Benchmark | Score | NE Memory | Throttle Msgs | Log Size | Root Cause |
|-----------|-------|-----------|---------------|----------|------------|
| #16       | 4/4   | nil       | N/A           | N/A      | Crypto-only, no traffic |
| #25       | 8/8   | 20MB      | 0             | ~400KB   | PASSED - traffic worked |
| #26       | 8/8   | 20MB      | 0             | 417KB    | PASSED - traffic worked |
| #27       | 0/8   | 20MB      | 0             | 417KB    | DNS responder nil bug |
| #30       | 1/4   | 21MB      | 190           | 59KB     | Self-throttle blocked all traffic |

Note: #25/#26 prove the NE works fine at 20MB when throttle doesn't fire.
#30 proves the throttle (when it fires) completely kills traffic flow.
#27 proves there's a separate DNS bug.

## The Feedback Loop (why the throttle makes it worse)

When memory crosses 12MB, shouldThrottleRouterWork() fires. Here's what happens:

1. task_info() syscall to read resident memory (overhead)
2. Memory >= 12MB → logger.warn("Router throttle: resident=18.3MB exceeds soft limit 12.0MB")
   → appendLine() reads ~500KB log file, allocates ~1.2MB of transient Strings, writes ~500KB back
3. Returns true → caller logs logger.debug("readPacketLoop: throttling router work...")
   → ANOTHER appendLine() cycle: ~1.2MB more transient allocations
4. Breaks out of packet loop (traffic blocked)
5. Next packet arrives ~1 second later, same cycle repeats

So every throttle event generates ~2.4MB of transient allocations trying to
REDUCE memory. In benchmark #30, 190 throttle events × 2 log calls each =
380 extra file-rewrite cycles = ~456MB of cumulative allocation churn caused
entirely by the throttle + logger interaction.

The throttle is not just failing to help — it's actively making the memory
situation worse while simultaneously blocking all traffic. It's a perfect
self-defeating feedback loop.

## Files to Change

1. `ios/ZTLP/ZTLP/Services/TunnelLogger.swift` — append-only I/O, periodic rotation
2. `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — remove memory throttle, reduce debug logging
3. `ios/ZTLP/ZTLPTunnel/ZTLPDNSResponder.swift` — investigate nil response bug
