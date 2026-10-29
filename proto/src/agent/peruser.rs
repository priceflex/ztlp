//! Per-user agent support (Windows per-user, unelevated agent; plan
//! `docs/plans/2026-10-29-windows-agent-per-user-unelevated.md`).
//!
//! On Windows the agent now runs as the logged-in user, started and
//! supervised by the desktop app. Everything that needs admin (DNS rule,
//! machine CA + its trust) is done once by the installer
//! (`ztlp agent machine-setup`). This module holds the small pieces the
//! per-user agent needs at runtime:
//!
//! * **freeze / thaw** — the desktop app sends `freeze` when the Windows
//!   session locks and `thaw` when it unlocks. While frozen the agent
//!   accepts no new VIP connections and answers ZTLP names with NXDOMAIN;
//!   established streams keep running until they idle out.
//! * **health probe** — a reserved name (`ztlp-health.ztlp`) the DNS stub
//!   always answers with a fixed loopback address, plus a TLS responder on
//!   that address. The desktop app resolves the name through the normal OS
//!   resolver (proves NRPT -> stub works) and opens TLS validated against
//!   the Windows store (proves the machine CA is trusted).
//! * **NS check-in result** — the last check-in outcome, surfaced in
//!   `status` so the app can show whether the identity is accepted.
//! * **machine CA location** — where the installer-created CA lives and
//!   which CA directory the agent should mint leaf certificates from.
//! * **parent watch** — `--parent-pid`: the agent exits when the desktop
//!   app that started it is gone, so no orphan agent keeps running.
//!
//! Everything here is platform-neutral; the machine CA directory is only
//! defined on Windows (or via `ZTLP_MACHINE_CA_DIR`), so macOS and Linux
//! behave exactly as before.

#![deny(unsafe_code)]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

// ── freeze / thaw ─────────────────────────────────────────────────────

static FROZEN: AtomicBool = AtomicBool::new(false);

/// Serializes tests that flip the process-wide frozen flag.
#[cfg(test)]
pub(crate) static FREEZE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Is the agent frozen (session locked)?
pub fn is_frozen() -> bool {
    FROZEN.load(Ordering::SeqCst)
}

/// Set the frozen flag. Returns the previous value.
pub fn set_frozen(frozen: bool) -> bool {
    FROZEN.swap(frozen, Ordering::SeqCst)
}

/// What the DNS stub should do with a query for a ZTLP name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDecision {
    /// Answer with the fixed health-probe address.
    HealthProbe,
    /// Frozen: answer NXDOMAIN without touching the name server.
    Refuse,
    /// Normal resolution through the name server.
    Resolve,
}

/// Pure decision for a ZTLP-name query. The health name is answered even
/// while frozen: it never leaves the box and carries no traffic.
pub fn dns_decision(ztlp_name: &str, frozen: bool) -> DnsDecision {
    if is_health_name(ztlp_name) {
        DnsDecision::HealthProbe
    } else if frozen {
        DnsDecision::Refuse
    } else {
        DnsDecision::Resolve
    }
}

/// Should a newly accepted VIP connection be served? (No while frozen.)
pub fn accept_new_connection(frozen: bool) -> bool {
    !frozen
}

// ── health probe ──────────────────────────────────────────────────────

/// Reserved name the desktop app resolves to prove `.ztlp` DNS works.
pub const HEALTH_NAME: &str = "ztlp-health.ztlp";

/// Fixed loopback address the health name resolves to. Next to the
/// control socket (127.100.255.1); the VIP pool allocates from the bottom
/// of 127.100.0.0/16 and never reaches it in practice.
pub const HEALTH_VIP: Ipv4Addr = Ipv4Addr::new(127, 100, 255, 2);

/// Port of the TLS health responder.
pub const HEALTH_PORT: u16 = 443;

/// Body the health responder sends after a successful handshake.
pub const HEALTH_BODY: &str = "ztlp-health-ok";

/// Case-insensitive match on the health name (with or without the
/// trailing root dot).
pub fn is_health_name(name: &str) -> bool {
    name.trim_end_matches('.').eq_ignore_ascii_case(HEALTH_NAME)
}

/// The full HTTP response the health responder writes.
pub fn health_http_response() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        HEALTH_BODY.len(),
        HEALTH_BODY
    )
}

// ── NS check-in result ────────────────────────────────────────────────

/// Last NS check-in outcome, as surfaced in `status`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckinRecord {
    /// "ok" | "not_renewable" | "not_registered" | "revoked" | "failed"
    pub state: String,
    /// Human-readable detail (device name, or the error).
    pub detail: String,
    /// Unix seconds of the check-in.
    pub at: u64,
}

impl CheckinRecord {
    /// Identity accepted by the name server (works now).
    pub fn accepted(&self) -> bool {
        self.state == "ok" || self.state == "not_renewable"
    }
}

static LAST_CHECKIN: Mutex<Option<CheckinRecord>> = Mutex::new(None);

/// Record the outcome of the latest check-in.
pub fn record_checkin(state: &str, detail: &str) {
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut g) = LAST_CHECKIN.lock() {
        *g = Some(CheckinRecord {
            state: state.to_string(),
            detail: detail.to_string(),
            at,
        });
    }
}

/// The latest check-in outcome, if any check-in has completed yet.
pub fn last_checkin() -> Option<CheckinRecord> {
    LAST_CHECKIN.lock().ok().and_then(|g| g.clone())
}

/// Sleep before the next check-in: the configured interval after a
/// definite answer, but retry within a minute after a network failure so
/// a box that booted offline turns green soon after it gets a network.
pub fn next_checkin_delay(interval: std::time::Duration, failed: bool) -> std::time::Duration {
    if failed {
        interval.min(std::time::Duration::from_secs(60))
    } else {
        interval
    }
}

// ── machine CA ────────────────────────────────────────────────────────

/// Windows: where the installer puts the machine CA.
pub const WINDOWS_MACHINE_CA_DIR: &str = r"C:\ProgramData\ZTLP\ca";

/// The machine CA directory for this platform: `ZTLP_MACHINE_CA_DIR` if
/// set (tests, unusual installs), else the Windows ProgramData path.
/// `None` on macOS/Linux (they keep their per-device CA flow).
pub fn machine_ca_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ZTLP_MACHINE_CA_DIR") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    if cfg!(target_os = "windows") {
        Some(PathBuf::from(WINDOWS_MACHINE_CA_DIR))
    } else {
        None
    }
}

/// A usable CA directory = intermediate cert + key present (what the
/// agent mints leaf certificates from).
pub fn ca_dir_can_mint(dir: &Path) -> bool {
    dir.join("intermediate.pem").exists() && dir.join("intermediate.key").exists()
}

/// Which CA directory the agent mints from: the machine CA when it is
/// usable (it is the one trusted machine-wide by the installer), else the
/// user's own `~/.ztlp/ca`.
pub fn effective_ca_dir(user_ca_dir: &Path, machine: Option<&Path>) -> PathBuf {
    match machine {
        Some(m) if ca_dir_can_mint(m) => m.to_path_buf(),
        _ => user_ca_dir.to_path_buf(),
    }
}

/// Is local TLS on? Yes when configured, and also whenever the machine CA
/// is usable: on Windows the installer provides trust, so the user never
/// has to run `ca-init` to flip `[tls] enabled`.
pub fn effective_tls_enabled(configured: bool, machine: Option<&Path>) -> bool {
    configured || machine.map(ca_dir_can_mint).unwrap_or(false)
}

/// Is the machine CA present and usable on this box?
pub fn machine_ca_available() -> bool {
    machine_ca_dir()
        .map(|d| ca_dir_can_mint(&d))
        .unwrap_or(false)
}

// ── parent watch ──────────────────────────────────────────────────────

/// Exit code when the agent stops because its parent (the desktop app)
/// is gone.
pub const EXIT_PARENT_GONE: i32 = 0;

/// Exit code when another user's agent already owns the control socket /
/// DNS stub. The desktop app shows "in use by another user" and retries.
pub const EXIT_PORTS_OWNED_BY_OTHER: i32 = 75;

/// Message prefix for the ports-owned-by-other startup error.
pub const PORTS_OWNED_BY_OTHER: &str = "ports_owned_by_other";

/// Should the agent stop now? Pure: the caller supplies whether the
/// parent process is still running.
pub fn parent_watch_should_exit(parent_pid: Option<u32>, parent_alive: bool) -> bool {
    parent_pid.is_some() && !parent_alive
}

/// Spawn the parent watch on a plain thread (works in standby and in the
/// full daemon alike): every `poll`, check the parent; when it is gone,
/// exit the process. Leaves no orphan agent holding the VIPs / DNS stub
/// after the desktop app is killed.
pub fn spawn_parent_watch(parent_pid: u32, poll: std::time::Duration) {
    let _ = std::thread::Builder::new()
        .name("ztlp-parent-watch".into())
        .spawn(move || loop {
            std::thread::sleep(poll);
            let alive = crate::agent::control::is_process_running(parent_pid);
            if parent_watch_should_exit(Some(parent_pid), alive) {
                tracing::info!("parent process {parent_pid} is gone; stopping the per-user agent");
                let _ = std::fs::remove_file(crate::agent::control::default_pid_path());
                std::process::exit(EXIT_PARENT_GONE);
            }
        });
}

/// Is `addr` (the control socket) already held by another process? Only
/// `AddrInUse` / `PermissionDenied` count: on a multi-user Windows box that
/// is another user's agent. Any other bind error is left to the real bind.
pub fn control_addr_owned_by_other(addr: &str) -> bool {
    match std::net::TcpListener::bind(addr) {
        Ok(_) => false,
        Err(e) => matches!(
            e.kind(),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
        ),
    }
}

/// Supervised by the desktop app with a pipe on stdin: exit when the pipe
/// closes (the app exited or crashed; the OS closes its end). Instant, no
/// polling. Only enabled when the app asks for it (`ZTLP_PARENT_STDIN=1`),
/// because a null stdin would read EOF immediately.
pub fn spawn_stdin_parent_watch() {
    let _ = std::thread::Builder::new()
        .name("ztlp-parent-stdin".into())
        .spawn(|| {
            use std::io::Read;
            let mut buf = [0u8; 64];
            let mut stdin = std::io::stdin();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            tracing::info!("parent closed our stdin; stopping the per-user agent");
            let _ = std::fs::remove_file(crate::agent::control::default_pid_path());
            std::process::exit(EXIT_PARENT_GONE);
        });
}

/// Did the parent ask for the stdin watch?
pub fn parent_stdin_watch_requested() -> bool {
    std::env::var("ZTLP_PARENT_STDIN")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// `--parent-pid` from the environment variable the CLI sets
/// (`ZTLP_PARENT_PID`), so the lifecycle code needs no new parameter.
pub fn parent_pid_from_env() -> Option<u32> {
    std::env::var("ZTLP_PARENT_PID")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|p| *p != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_name_matches_case_and_trailing_dot() {
        assert!(is_health_name("ztlp-health.ztlp"));
        assert!(is_health_name("ZTLP-Health.ZTLP."));
        assert!(!is_health_name("whoami.trs.ztlp"));
        assert!(!is_health_name("ztlp-health.ztlp.evil.com"));
    }

    #[test]
    fn dns_decision_answers_health_even_when_frozen() {
        assert_eq!(
            dns_decision("ztlp-health.ztlp", true),
            DnsDecision::HealthProbe
        );
        assert_eq!(
            dns_decision("ztlp-health.ztlp", false),
            DnsDecision::HealthProbe
        );
    }

    #[test]
    fn dns_decision_refuses_real_names_when_frozen() {
        assert_eq!(dns_decision("whoami.trs.ztlp", true), DnsDecision::Refuse);
        assert_eq!(dns_decision("whoami.trs.ztlp", false), DnsDecision::Resolve);
    }

    #[test]
    fn frozen_rejects_new_connections() {
        assert!(!accept_new_connection(true));
        assert!(accept_new_connection(false));
    }

    #[test]
    fn set_frozen_round_trips_and_returns_previous() {
        let _g = FREEZE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let before = set_frozen(true);
        assert!(is_frozen());
        assert!(set_frozen(false));
        assert!(!is_frozen());
        set_frozen(before);
    }

    #[test]
    fn health_vip_is_reserved_next_to_control_socket() {
        assert_eq!(HEALTH_VIP.to_string(), "127.100.255.2");
        assert_eq!(HEALTH_PORT, 443);
    }

    #[test]
    fn health_response_has_exact_content_length() {
        let r = health_http_response();
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(r.contains(&format!("Content-Length: {}\r\n", HEALTH_BODY.len())));
        assert!(r.ends_with(HEALTH_BODY));
    }

    #[test]
    fn checkin_record_accepted_states() {
        let r = |s: &str| CheckinRecord {
            state: s.into(),
            detail: String::new(),
            at: 0,
        };
        assert!(r("ok").accepted());
        assert!(r("not_renewable").accepted());
        assert!(!r("not_registered").accepted());
        assert!(!r("revoked").accepted());
        assert!(!r("failed").accepted());
    }

    #[test]
    fn record_checkin_is_readable_back() {
        record_checkin("ok", "dev.trs.ztlp");
        let c = last_checkin().expect("recorded");
        assert_eq!(c.state, "ok");
        assert_eq!(c.detail, "dev.trs.ztlp");
        assert!(c.at > 0);
    }

    #[test]
    fn failed_checkin_retries_within_a_minute() {
        use std::time::Duration;
        let hour = Duration::from_secs(3600);
        assert_eq!(next_checkin_delay(hour, true), Duration::from_secs(60));
        assert_eq!(next_checkin_delay(hour, false), hour);
        // never longer than the configured interval
        assert_eq!(
            next_checkin_delay(Duration::from_secs(10), true),
            Duration::from_secs(10)
        );
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ztlp-peruser-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn effective_ca_dir_prefers_usable_machine_ca() {
        let user = tmp("user1");
        let machine = tmp("machine1");
        std::fs::write(machine.join("intermediate.pem"), "x").unwrap();
        std::fs::write(machine.join("intermediate.key"), "x").unwrap();
        assert_eq!(effective_ca_dir(&user, Some(&machine)), machine);
    }

    #[test]
    fn effective_ca_dir_falls_back_to_user_ca() {
        let user = tmp("user2");
        let machine = tmp("machine2");
        // only the cert, no key: not usable
        std::fs::write(machine.join("intermediate.pem"), "x").unwrap();
        assert_eq!(effective_ca_dir(&user, Some(&machine)), user);
        assert_eq!(effective_ca_dir(&user, None), user);
    }

    #[test]
    fn tls_enabled_by_config_or_usable_machine_ca() {
        let machine = tmp("machine3");
        assert!(effective_tls_enabled(true, None));
        assert!(!effective_tls_enabled(false, None));
        assert!(!effective_tls_enabled(false, Some(&machine)));
        std::fs::write(machine.join("intermediate.pem"), "x").unwrap();
        std::fs::write(machine.join("intermediate.key"), "x").unwrap();
        assert!(effective_tls_enabled(false, Some(&machine)));
    }

    #[test]
    fn machine_ca_dir_is_windows_only_without_override() {
        // The env override is exercised implicitly by other tests via the
        // pure helpers; here only the platform default is pinned.
        if std::env::var("ZTLP_MACHINE_CA_DIR").is_err() {
            if cfg!(target_os = "windows") {
                assert_eq!(
                    machine_ca_dir(),
                    Some(PathBuf::from(WINDOWS_MACHINE_CA_DIR))
                );
            } else {
                assert_eq!(machine_ca_dir(), None);
            }
        }
    }

    #[test]
    fn control_addr_owned_by_other_detects_a_held_port() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = held.local_addr().unwrap().to_string();
        assert!(control_addr_owned_by_other(&addr));
        drop(held);
        assert!(!control_addr_owned_by_other(&addr));
    }

    #[test]
    fn parent_watch_exits_only_when_a_watched_parent_is_gone() {
        assert!(parent_watch_should_exit(Some(42), false));
        assert!(!parent_watch_should_exit(Some(42), true));
        assert!(!parent_watch_should_exit(None, false));
    }
}
