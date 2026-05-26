//! Child-process supervisor.
//!
//! Spawns an external binary, captures its stdout+stderr into a single
//! append log, and restarts it on exit with exponential backoff capped at
//! a configurable maximum. The supervisor is shut down by sending `()`
//! on the stop channel passed at construction time — both the child wait
//! and the cooldown sleep are interruptible by that signal.
//!
//! ## Design
//!
//! The supervisor runs on the calling thread. To make `Child::wait()`
//! interruptible we spawn a small watcher thread that calls `wait()`
//! and pushes the resulting `ExitStatus` (or io::Error) through an mpsc
//! channel. The main loop polls between that channel and `stop_rx`,
//! using `recv_timeout` to also drive the cooldown sleep.
//!
//! ## Cross-platform
//!
//! Everything in this module compiles on Unix and Windows. The kill path
//! uses `std::process::Child::kill()` which is SIGKILL on Unix and
//! `TerminateProcess` on Windows; both are abrupt but functional for
//! first-cut shutdown. A graceful SIGTERM-then-kill ladder is left for
//! a follow-up task.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Description of the child to supervise.
#[derive(Debug, Clone)]
pub struct ChildSpec {
    /// Absolute path to the binary to execute.
    pub binary: PathBuf,
    /// Command-line arguments (not including argv[0]).
    pub args: Vec<OsString>,
    /// Environment variables to set on the child, in addition to the
    /// supervisor's inherited environment.
    pub env: Vec<(OsString, OsString)>,
    /// File to which the child's stdout AND stderr are appended.
    /// Parent directory must already exist — the supervisor will not
    /// create it (callers like `service_main_inner` create the dir).
    pub log_path: PathBuf,
}

/// Restart backoff policy.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    /// Wait duration after the first crash.
    pub initial: Duration,
    /// Upper bound on the wait duration.
    pub max: Duration,
    /// Multiplier applied each consecutive crash.
    pub multiplier: f64,
    /// If the child stayed alive at least this long before exiting,
    /// reset the backoff to `initial`.
    pub reset_after: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            multiplier: 2.0,
            reset_after: Duration::from_secs(60),
        }
    }
}

impl BackoffPolicy {
    /// Compute the next cooldown given the previous cooldown.
    ///
    /// `previous = None` returns `initial` (this is the first crash).
    /// Otherwise returns `min(previous * multiplier, max)`.
    pub fn next_after_crash(&self, previous: Option<Duration>) -> Duration {
        match previous {
            None => self.initial,
            Some(prev) => {
                let scaled = prev.as_secs_f64() * self.multiplier;
                let capped = scaled.min(self.max.as_secs_f64());
                Duration::from_secs_f64(capped)
            }
        }
    }

    /// Compute the next cooldown taking uptime into account: if the child
    /// stayed up at least `reset_after`, reset to `initial`; otherwise
    /// grow per `next_after_crash`.
    pub fn next_after_uptime(&self, previous: Option<Duration>, uptime: Duration) -> Duration {
        if uptime >= self.reset_after {
            self.initial
        } else {
            self.next_after_crash(previous)
        }
    }
}

/// Supervisor handle. Construct with `new`, then call `run` (which
/// consumes self and blocks until `stop_rx` fires or an unrecoverable
/// error occurs).
pub struct Supervisor {
    spec: ChildSpec,
    backoff: BackoffPolicy,
    stop_rx: mpsc::Receiver<()>,
}

impl Supervisor {
    pub fn new(spec: ChildSpec, backoff: BackoffPolicy, stop_rx: mpsc::Receiver<()>) -> Self {
        Self {
            spec,
            backoff,
            stop_rx,
        }
    }

    /// Drive the supervise → restart loop until `stop_rx` fires.
    pub fn run(self) -> Result<()> {
        let mut last_backoff: Option<Duration> = None;

        loop {
            // -- Starting -------------------------------------------------
            tracing::info!(
                binary = %self.spec.binary.display(),
                "supervisor: spawning child"
            );
            let spawn_started = Instant::now();
            let child = match Self::spawn_child(&self.spec) {
                Ok(c) => c,
                Err(e) => {
                    // Spawn failure (binary missing, permission denied, …).
                    // Treat it identically to a crash so we don't busy-loop.
                    tracing::error!(error = %e, "supervisor: failed to spawn child");
                    let cooldown = self.backoff.next_after_crash(last_backoff);
                    last_backoff = Some(cooldown);
                    if self.sleep_or_stop(cooldown) {
                        return Ok(());
                    }
                    continue;
                }
            };

            // -- Running --------------------------------------------------
            // Hand the child to the watcher thread via Arc<Mutex<Option>>
            // so the main thread can still kill() it on stop without
            // racing with wait().
            let child_slot: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(Some(child)));
            let watcher_slot = Arc::clone(&child_slot);
            let (wait_tx, wait_rx) = mpsc::channel::<std::io::Result<std::process::ExitStatus>>();

            let watcher = thread::spawn(move || {
                // Take the child out of the slot for the duration of wait()
                // so the main thread can independently call kill() through
                // the same slot without contending on the lock.
                //
                // Actually: kill() requires &mut Child too. We can't both
                // wait() and kill() concurrently on Unix (waitpid races
                // with kill on a reaped pid). So: keep the child in the
                // slot, and have the watcher loop on try_wait() with a
                // short sleep. This is simpler than a wait/kill dance.
                loop {
                    let mut guard = watcher_slot.lock().expect("child_slot poisoned");
                    let child = match guard.as_mut() {
                        Some(c) => c,
                        None => return, // killed and removed by main
                    };
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let _ = wait_tx.send(Ok(status));
                            return;
                        }
                        Ok(None) => {
                            // still running — release lock and sleep
                        }
                        Err(e) => {
                            let _ = wait_tx.send(Err(e));
                            return;
                        }
                    }
                    drop(guard);
                    thread::sleep(Duration::from_millis(50));
                }
            });

            // Main loop: wait for either child exit or stop signal.
            let exit_status = loop {
                match self.stop_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) => {
                        tracing::info!("supervisor: stop signal received, terminating child");
                        kill_child_in_slot(&child_slot);
                        // Drain the watcher so it observes the exit and
                        // shuts down before we move on.
                        let _ = wait_rx.recv_timeout(Duration::from_secs(5));
                        let _ = watcher.join();
                        return Ok(());
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if let Ok(res) = wait_rx.try_recv() {
                            break res;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::warn!(
                            "supervisor: stop channel disconnected, treating as shutdown"
                        );
                        kill_child_in_slot(&child_slot);
                        let _ = wait_rx.recv_timeout(Duration::from_secs(5));
                        let _ = watcher.join();
                        return Ok(());
                    }
                }
            };

            let _ = watcher.join();
            let uptime = spawn_started.elapsed();

            match &exit_status {
                Ok(status) => {
                    tracing::warn!(
                        ?status,
                        uptime_secs = uptime.as_secs(),
                        "supervisor: child exited"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "supervisor: child.wait() failed");
                }
            }

            // -- CrashCooldown -------------------------------------------
            let cooldown = self.backoff.next_after_uptime(last_backoff, uptime);
            last_backoff = if uptime >= self.backoff.reset_after {
                None
            } else {
                Some(cooldown)
            };
            tracing::info!(
                cooldown_ms = cooldown.as_millis() as u64,
                "supervisor: sleeping before restart"
            );
            if self.sleep_or_stop(cooldown) {
                return Ok(());
            }
        }
    }

    /// Sleep for `dur`, returning `true` if a stop signal arrived during
    /// the sleep (caller should exit) and `false` on normal timeout.
    fn sleep_or_stop(&self, dur: Duration) -> bool {
        match self.stop_rx.recv_timeout(dur) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => false,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // No way for SCM to reach us anymore — exit.
                true
            }
        }
    }

    /// Spawn the child with stdout+stderr merged into the log file.
    fn spawn_child(spec: &ChildSpec) -> Result<Child> {
        let stdout_file = open_append_log(&spec.log_path)
            .with_context(|| format!("opening log file {}", spec.log_path.display()))?;
        let stderr_file = stdout_file
            .try_clone()
            .context("cloning log file handle for stderr")?;

        let mut cmd = Command::new(&spec.binary);
        cmd.args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }

        cmd.spawn()
            .with_context(|| format!("spawning {}", spec.binary.display()))
    }
}

/// Best-effort kill of the child currently held in `slot`. Logs and
/// swallows errors — the supervisor's exit path must not be derailed by
/// a missing/zombie child.
fn kill_child_in_slot(slot: &Arc<Mutex<Option<Child>>>) {
    let mut guard = match slot.lock() {
        Ok(g) => g,
        Err(_) => {
            tracing::warn!("supervisor: child slot mutex poisoned during kill");
            return;
        }
    };
    if let Some(c) = guard.as_mut() {
        if let Err(e) = c.kill() {
            tracing::warn!(error = %e, "supervisor: child.kill() failed");
        }
    }
}

/// Open the supervisor log in append+create mode and write a small
/// session banner so log readers can tell where one supervisor session
/// ends and the next begins.
fn open_append_log(path: &Path) -> std::io::Result<File> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    // Best-effort banner — ignore write errors so a transiently full
    // disk doesn't kill the supervisor.
    let _ = writeln!(
        f,
        "--- ztlp supervisor: opening child stdio at {:?} ---",
        std::time::SystemTime::now()
    );
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backoff_matches_plan() {
        let p = BackoffPolicy::default();
        assert_eq!(p.initial, Duration::from_secs(1));
        assert_eq!(p.max, Duration::from_secs(60));
        assert!((p.multiplier - 2.0).abs() < f64::EPSILON);
        assert_eq!(p.reset_after, Duration::from_secs(60));
    }

    #[test]
    fn first_crash_uses_initial() {
        let p = BackoffPolicy::default();
        assert_eq!(p.next_after_crash(None), Duration::from_secs(1));
    }
}
