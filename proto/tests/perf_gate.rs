//! Performance regression gate tests.
//!
//! Each gate runs the `ztlp-throughput` benchmark binary in a subprocess.
//! This is the only reliable way to test tunnel throughput because the binary
//! uses its own tokio runtime and process — identical to production.
//!
//! **IMPORTANT:** These tests MUST run serially (`--test-threads=1`) to avoid
//! port/CPU contention. We enforce this with a global mutex.
//!
//! Thresholds are intentionally conservative (10–20× below baseline) to
//! avoid flaky failures on CI machines with variable load.

use std::process::Command;
use std::sync::Mutex;

/// Global mutex to enforce serial execution of perf gates even when the
/// test runner uses multiple threads. Each test locks this before running.
static PERF_GATE_LOCK: Mutex<()> = Mutex::new(());

/// Run `ztlp-throughput` and parse the throughput line.
/// Returns (throughput_mb_s, time_ms, packets, exit_code).
fn run_benchmark(mode: &str, size: usize) -> (f64, f64, usize, i32) {
    let bin = env!("CARGO_BIN_EXE_ztlp-throughput");
    let output = Command::new("timeout")
        .args([
            "30",
            bin,
            "--mode",
            mode,
            "--size",
            &size.to_string(),
            "--repeat",
            "1",
        ])
        .output()
        .expect("failed to run ztlp-throughput");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse the throughput line, e.g.:
    //   ZTLP (no GSO)             67 MB/s     59.3ms        257        N/A
    //   Raw TCP (loopback)      1536 MB/s      2.5ms        N/A        N/A
    let mut throughput = 0.0f64;
    let mut time_ms = 0.0f64;
    let mut packets = 0usize;

    for line in stdout.lines().chain(stderr.lines()) {
        // Look for a line containing MB/s or GB/s
        if (line.contains("MB/s") || line.contains("GB/s"))
            && !line.contains("Mode")
            && !line.contains("────")
        {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Find the throughput value (number followed by MB/s or GB/s)
            for (i, part) in parts.iter().enumerate() {
                if *part == "MB/s" && i > 0 {
                    if let Ok(v) = parts[i - 1].parse::<f64>() {
                        throughput = v;
                    }
                } else if *part == "GB/s" && i > 0 {
                    if let Ok(v) = parts[i - 1].parse::<f64>() {
                        throughput = v * 1024.0;
                    }
                }
            }
            // Find time (number followed by ms or s)
            for (i, part) in parts.iter().enumerate() {
                if i > 0 {
                    if part.ends_with("ms") {
                        if let Ok(v) = part.trim_end_matches("ms").parse::<f64>() {
                            time_ms = v;
                        }
                    } else if part.ends_with('s') && !part.ends_with("ms") {
                        if let Ok(v) = part.trim_end_matches('s').parse::<f64>() {
                            time_ms = v * 1000.0;
                        }
                    }
                }
            }
            // Find packets (number in the packets column)
            for part in &parts {
                if part.parse::<usize>().is_ok() {
                    let v = part.parse::<usize>().unwrap_or(0);
                    if v > 0 && v < 100_000 {
                        packets = v;
                    }
                }
            }
        }
    }

    (throughput, time_ms, packets, exit_code)
}

/// Handshake latency check — uses the benchmark's handshake path.
#[test]
#[ignore = "perf gate — run with --ignored or --include-ignored"]
fn perf_gate_01_handshake() {
    let _lock = PERF_GATE_LOCK.lock().unwrap();
    // The 256KB transfer includes handshake time in its ~50ms. If the
    // handshake were slow (>1s), the 256KB gate would catch it. We do
    // a small transfer to isolate handshake timing more precisely.
    let (throughput, time_ms, _packets, exit) = run_benchmark("ztlp-nogso", 1024);
    eprintln!(
        "[perf_gate] handshake+1KB: {:.1} MB/s, {:.1}ms, exit={}",
        throughput, time_ms, exit
    );
    // The time is dominated by the 50ms sender delay + handshake.
    // Threshold: must complete within 5 seconds.
    assert_eq!(exit, 0, "benchmark process failed (exit {})", exit);
    assert!(
        time_ms < 5000.0,
        "handshake+1KB took {:.0}ms (threshold: 5000ms)",
        time_ms
    );
}

/// 256KB transfer — baseline: ~5 MB/s, ~52ms
#[test]
#[ignore = "perf gate — run with --ignored or --include-ignored"]
fn perf_gate_02_256kb() {
    let _lock = PERF_GATE_LOCK.lock().unwrap();
    let (throughput, time_ms, packets, exit) = run_benchmark("ztlp-nogso", 262144);
    eprintln!(
        "[perf_gate] 256KB: {:.1} MB/s, {:.1}ms, {} packets, exit={}",
        throughput, time_ms, packets, exit
    );
    assert_eq!(exit, 0, "benchmark failed (exit {})", exit);
    assert!(
        time_ms < 5000.0,
        "256KB took {:.0}ms (threshold: 5000ms)",
        time_ms
    );
    assert!(
        throughput > 0.5,
        "256KB throughput {:.1} MB/s below minimum 0.5 MB/s",
        throughput
    );
}

/// 1MB transfer — baseline: ~18 MB/s, ~55ms
#[test]
#[ignore = "perf gate — run with --ignored or --include-ignored"]
fn perf_gate_03_1mb() {
    let _lock = PERF_GATE_LOCK.lock().unwrap();
    let (throughput, time_ms, packets, exit) = run_benchmark("ztlp-nogso", 1048576);
    eprintln!(
        "[perf_gate] 1MB: {:.1} MB/s, {:.1}ms, {} packets, exit={}",
        throughput, time_ms, packets, exit
    );
    assert_eq!(exit, 0, "benchmark failed (exit {})", exit);
    assert!(
        time_ms < 10000.0,
        "1MB took {:.0}ms (threshold: 10000ms)",
        time_ms
    );
    assert!(
        throughput > 1.0,
        "1MB throughput {:.1} MB/s below minimum 1.0 MB/s",
        throughput
    );
}

/// 4MB transfer — baseline: ~67 MB/s, ~60ms
#[test]
#[ignore = "perf gate — run with --ignored or --include-ignored"]
fn perf_gate_04_4mb() {
    let _lock = PERF_GATE_LOCK.lock().unwrap();
    let (throughput, time_ms, packets, exit) = run_benchmark("ztlp-nogso", 4194304);
    eprintln!(
        "[perf_gate] 4MB: {:.1} MB/s, {:.1}ms, {} packets, exit={}",
        throughput, time_ms, packets, exit
    );
    assert_eq!(exit, 0, "benchmark failed (exit {})", exit);
    assert!(
        time_ms < 30000.0,
        "4MB took {:.0}ms (threshold: 30000ms)",
        time_ms
    );
    assert!(
        throughput > 5.0,
        "4MB throughput {:.1} MB/s below minimum 5.0 MB/s",
        throughput
    );
}

/// Raw TCP baseline for comparison — not a regression check, just informational.
#[test]
#[ignore = "perf gate — run with --ignored or --include-ignored"]
fn perf_gate_05_tcp_baseline() {
    let _lock = PERF_GATE_LOCK.lock().unwrap();
    let (throughput, time_ms, _packets, exit) = run_benchmark("raw", 4194304);
    eprintln!(
        "[perf_gate] TCP baseline (4MB): {:.1} MB/s, {:.1}ms, exit={}",
        throughput, time_ms, exit
    );
    // TCP baseline should always succeed; this test exists to log
    // the comparison number alongside the ZTLP results.
    assert_eq!(exit, 0, "TCP baseline failed (exit {})", exit);
}
