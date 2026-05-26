//! Cross-platform tests for the child-process supervisor.
//!
//! Pure unit tests for `BackoffPolicy` run on every target. Spawn-based
//! tests use `/bin/sh` and therefore only run on Unix; on Windows CI they
//! are excluded but the supervisor module itself still gets compile-checked
//! because `cfg(target_family = "windows")` excludes only the test bodies.

use std::time::Duration;

use ztlp_service::supervisor::BackoffPolicy;

/// Backoff sequence: 1s → 2s → 4s → 4s (capped at max=4s).
#[test]
fn backoff_grows_then_caps() {
    let policy = BackoffPolicy {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(4),
        multiplier: 2.0,
        reset_after: Duration::from_secs(60),
    };

    // Starting from `None` (no previous backoff) we get `initial`.
    let d0 = policy.next_after_crash(None);
    assert_eq!(d0, Duration::from_secs(1));

    // 1s → 2s
    let d1 = policy.next_after_crash(Some(d0));
    assert_eq!(d1, Duration::from_secs(2));

    // 2s → 4s
    let d2 = policy.next_after_crash(Some(d1));
    assert_eq!(d2, Duration::from_secs(4));

    // 4s * 2 = 8s but capped to 4s
    let d3 = policy.next_after_crash(Some(d2));
    assert_eq!(d3, Duration::from_secs(4));

    let d4 = policy.next_after_crash(Some(d3));
    assert_eq!(d4, Duration::from_secs(4));
}

/// After the child stays up at least `reset_after`, the next backoff
/// snaps back to `initial`.
#[test]
fn backoff_resets_after_long_uptime() {
    let policy = BackoffPolicy {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(60),
        multiplier: 2.0,
        reset_after: Duration::from_secs(60),
    };

    // We were at 16s of backoff but the child stayed up 2 minutes.
    let next = policy.next_after_uptime(Some(Duration::from_secs(16)), Duration::from_secs(120));
    assert_eq!(next, Duration::from_secs(1));

    // Child crashed almost immediately — keep growing.
    let next = policy.next_after_uptime(Some(Duration::from_secs(16)), Duration::from_secs(1));
    assert_eq!(next, Duration::from_secs(32));
}

#[cfg(target_family = "unix")]
mod unix_spawn {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use ztlp_service::supervisor::{BackoffPolicy, ChildSpec, Supervisor};

    fn tmp_log_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ztlp-supervisor-test-{}-{}.log",
            name,
            std::process::id()
        ));
        // Truncate any leftover from a prior run.
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Supervisor must exit cleanly within ~2s of a stop signal even if
    /// the child is happily sleeping.
    #[test]
    fn supervisor_exits_on_stop_signal() {
        let log_path = tmp_log_path("stop");
        let spec = ChildSpec {
            binary: "/bin/sh".into(),
            args: vec![OsString::from("-c"), OsString::from("sleep 30")],
            env: vec![],
            log_path: log_path.clone(),
        };

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let supervisor = Supervisor::new(spec, BackoffPolicy::default(), stop_rx);

        let handle = thread::spawn(move || supervisor.run());

        // Give the supervisor time to actually spawn the child.
        thread::sleep(Duration::from_millis(200));

        let start = Instant::now();
        stop_tx.send(()).expect("stop send");

        // Join with a deadline so the test fails loudly instead of hanging.
        let deadline = Duration::from_secs(3);
        let join_start = Instant::now();
        loop {
            if handle.is_finished() {
                break;
            }
            if join_start.elapsed() > deadline {
                panic!(
                    "supervisor did not exit within {:?} of stop signal",
                    deadline
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "supervisor took {:?} to exit after stop (expected <2s)",
            elapsed
        );

        let res = handle.join().expect("join supervisor thread");
        res.expect("supervisor run returned Err");
    }

    /// Supervisor must restart a fast-failing child multiple times with
    /// the configured (short) backoff, then exit on stop.
    #[test]
    fn supervisor_restarts_on_crash() {
        let log_path = tmp_log_path("restart");
        let spec = ChildSpec {
            binary: "/bin/sh".into(),
            args: vec![
                OsString::from("-c"),
                // Append a marker each invocation so we can count restarts.
                OsString::from(format!("echo CRASHMARK >> {} ; exit 1", log_path.display())),
            ],
            env: vec![],
            log_path: log_path.clone(),
        };

        let backoff = BackoffPolicy {
            initial: Duration::from_millis(20),
            max: Duration::from_millis(80),
            multiplier: 2.0,
            reset_after: Duration::from_secs(60),
        };

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let supervisor = Supervisor::new(spec, backoff, stop_rx);
        let handle = thread::spawn(move || supervisor.run());

        // Let it crash-restart a handful of times.
        thread::sleep(Duration::from_millis(800));
        stop_tx.send(()).expect("stop send");

        let deadline = Instant::now() + Duration::from_secs(3);
        while !handle.is_finished() {
            if Instant::now() > deadline {
                panic!("supervisor did not exit after stop");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let res = handle.join().expect("join supervisor thread");
        res.expect("supervisor run returned Err");

        let contents = std::fs::read_to_string(&log_path).expect("read log");
        let count = contents.matches("CRASHMARK").count();
        assert!(
            count >= 3,
            "expected at least 3 child restarts, got {} (log: {:?})",
            count,
            contents
        );
    }
}
