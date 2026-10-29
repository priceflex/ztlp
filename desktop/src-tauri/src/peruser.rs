//! Windows per-user agent support in the desktop app
//! (plan `docs/plans/2026-10-29-windows-agent-per-user-unelevated.md`).
//!
//! On Windows the app owns the agent: it starts `ztlp.exe agent start
//! --foreground --parent-pid <us>` as the logged-in user, restarts it if it
//! dies, tells it `freeze`/`thaw` when the session locks/unlocks, and shows
//! four end-to-end checks on Home: Agent, Identity, DNS, HTTPS.
//!
//! Pure logic (health report, backoff, lock transitions) is unit-tested on
//! every OS; the process / Win32 parts are `cfg(windows)`.

use serde::Serialize;
use serde_json::Value;
use std::net::Ipv4Addr;
use std::time::Duration;

use ztlp_proto::agent::peruser::{HEALTH_BODY, HEALTH_NAME, HEALTH_PORT, HEALTH_VIP};

/// Is this build using the per-user agent model? (Windows only; Linux keeps
/// its existing service flow, macOS uses the Swift app.)
pub const PER_USER_AGENT: bool = cfg!(target_os = "windows");

pub const IPC_ADDR: &str = "127.100.255.1:4433";

// ── health report (pure) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthRow {
    pub key: &'static str,
    pub title: &'static str,
    /// "ready" | "waiting" | "failed" | "action"
    pub state: &'static str,
    pub detail: String,
    /// "enroll" | "repair" (only when state is "action" or "failed")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthReport {
    pub per_user: bool,
    pub rows: Vec<HealthRow>,
    pub all_ready: bool,
    pub enrolled: bool,
    pub zone: String,
    pub frozen: bool,
    pub in_use_by_other: bool,
}

/// What the agent's control socket said.
#[derive(Debug, Clone)]
pub enum AgentProbe {
    /// Answered `status` (and `setup_status`, if it did).
    Up { status: Value, setup: Value },
    /// Someone answered but rejected our token: another user's agent.
    Unauthorized,
    /// Nothing answered (starting, crashed, not installed).
    Down(String),
}

impl AgentProbe {
    /// Classify an IPC result for `status`.
    pub fn from_status_result(r: Result<Value, String>, setup: Option<Value>) -> Self {
        match r {
            Ok(status) => AgentProbe::Up {
                status,
                setup: setup.unwrap_or(Value::Null),
            },
            Err(e) if e.to_ascii_lowercase().contains("unauthorized") => AgentProbe::Unauthorized,
            Err(e) => AgentProbe::Down(e),
        }
    }
}

pub struct HealthInputs {
    pub agent: AgentProbe,
    /// Supervisor's note when the agent is not up (last exit / error).
    pub supervisor_note: Option<String>,
    /// `None` = not probed (gated off).
    pub dns: Option<Result<Ipv4Addr, String>>,
    pub https: Option<Result<(), String>>,
}

fn row(
    key: &'static str,
    title: &'static str,
    state: &'static str,
    detail: impl Into<String>,
    action: Option<&'static str>,
) -> HealthRow {
    HealthRow {
        key,
        title,
        state,
        detail: detail.into(),
        action,
    }
}

/// Is the agent enrolled (i.e. running the full daemon, not standby)?
pub fn agent_enrolled(status: &Value, setup: &Value) -> bool {
    if status.get("standby").and_then(Value::as_bool) == Some(true) {
        return false;
    }
    match setup.get("identity_enrolled").and_then(Value::as_bool) {
        Some(b) => b,
        None => !status.is_null(),
    }
}

/// Should the app run the DNS/HTTPS probes now? Only against a running,
/// enrolled agent: probing earlier would make Windows cache a negative DNS
/// answer for the health name.
pub fn should_probe_network(agent: &AgentProbe) -> bool {
    match agent {
        AgentProbe::Up { status, setup } => agent_enrolled(status, setup),
        _ => false,
    }
}

/// The four Home rows, from what was observed. Pure.
pub fn compute_health(i: &HealthInputs) -> HealthReport {
    let mut zone = String::new();
    let mut frozen = false;
    let mut enrolled = false;
    let in_use_by_other = matches!(i.agent, AgentProbe::Unauthorized);

    // 1. Agent
    let agent_row = match &i.agent {
        AgentProbe::Up { status, setup } => {
            frozen = status
                .get("frozen")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            enrolled = agent_enrolled(status, setup);
            zone = setup
                .get("zone")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let ver = status
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let mut d = if ver.is_empty() {
                "Running".to_string()
            } else {
                format!("Running (v{ver})")
            };
            if frozen {
                d.push_str(" · paused while the screen is locked");
            }
            row("agent", "Agent", "ready", d, None)
        }
        AgentProbe::Unauthorized => row(
            "agent",
            "Agent",
            "failed",
            "In use by another Windows user on this PC. ZTLP will take over when they sign out.",
            None,
        ),
        AgentProbe::Down(e) => {
            let d = match &i.supervisor_note {
                Some(n) if !n.is_empty() => format!("Starting… ({n})"),
                _ => format!("Starting… ({})", short(e)),
            };
            row("agent", "Agent", "waiting", d, None)
        }
    };
    let agent_up = agent_row.state == "ready";

    // 2. Identity
    let identity_row = if !agent_up {
        row(
            "identity",
            "Identity",
            "waiting",
            "Waiting for the agent",
            None,
        )
    } else if !enrolled {
        row(
            "identity",
            "Identity",
            "action",
            "Not enrolled yet. Paste the enrollment link from your administrator.",
            Some("enroll"),
        )
    } else {
        let status = match &i.agent {
            AgentProbe::Up { status, .. } => status,
            _ => &Value::Null,
        };
        let ci = status.get("ns_checkin");
        let state = ci.and_then(|c| c.get("state")).and_then(Value::as_str);
        let detail = ci
            .and_then(|c| c.get("detail"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match state {
            Some("ok") | Some("not_renewable") => {
                let d = if detail.is_empty() {
                    format!("Enrolled in {zone}")
                } else {
                    detail
                };
                row("identity", "Identity", "ready", d, None)
            }
            Some("not_registered") | Some("revoked") => row(
                "identity",
                "Identity",
                "failed",
                format!("{detail}. Enroll again with a new link."),
                Some("enroll"),
            ),
            Some("failed") => row(
                "identity",
                "Identity",
                "waiting",
                format!("Can't reach the name server, retrying ({})", short(&detail)),
                None,
            ),
            _ => row(
                "identity",
                "Identity",
                "waiting",
                "Checking in with the name server…",
                None,
            ),
        }
    };

    // 3. DNS
    let dns_row = if !agent_up || !enrolled {
        row(
            "dns",
            "DNS",
            "waiting",
            if agent_up {
                "Waiting for enrollment"
            } else {
                "Waiting for the agent"
            },
            None,
        )
    } else {
        match &i.dns {
            None => row("dns", "DNS", "waiting", "Checking…", None),
            Some(Ok(ip)) if *ip == HEALTH_VIP => row(
                "dns",
                "DNS",
                "ready",
                ".ztlp names resolve through ZTLP",
                None,
            ),
            Some(Ok(ip)) => row(
                "dns",
                "DNS",
                "failed",
                format!(".ztlp names resolve to {ip}, not to ZTLP. Click Fix (needs admin)."),
                Some("repair"),
            ),
            Some(Err(e)) => row(
                "dns",
                "DNS",
                "failed",
                format!(
                    ".ztlp names don't reach ZTLP ({}). Click Fix (needs admin).",
                    short(e)
                ),
                Some("repair"),
            ),
        }
    };

    // 4. HTTPS
    let https_row = if dns_row.state != "ready" {
        row(
            "https",
            "HTTPS",
            "waiting",
            if dns_row.state == "failed" {
                "Waiting for DNS"
            } else {
                dns_row_waiting_text(agent_up, enrolled)
            },
            None,
        )
    } else {
        match &i.https {
            None => row("https", "HTTPS", "waiting", "Checking…", None),
            Some(Ok(())) => row(
                "https",
                "HTTPS",
                "ready",
                "Browsers trust ZTLP certificates",
                None,
            ),
            Some(Err(e)) => row(
                "https",
                "HTTPS",
                "failed",
                format!(
                    "Certificates not trusted ({}). Click Fix (needs admin).",
                    short(e)
                ),
                Some("repair"),
            ),
        }
    };

    let rows = vec![agent_row, identity_row, dns_row, https_row];
    let all_ready = rows.iter().all(|r| r.state == "ready");
    HealthReport {
        per_user: true,
        rows,
        all_ready,
        enrolled,
        zone,
        frozen,
        in_use_by_other,
    }
}

fn dns_row_waiting_text(agent_up: bool, enrolled: bool) -> &'static str {
    if !agent_up {
        "Waiting for the agent"
    } else if !enrolled {
        "Waiting for enrollment"
    } else {
        "Waiting for DNS"
    }
}

fn short(s: &str) -> String {
    let s = s.lines().next().unwrap_or_default().trim();
    if s.chars().count() > 140 {
        let mut t: String = s.chars().take(140).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

// ── device name (pure) ────────────────────────────────────────────────

/// Default device name for a per-user enrollment: `<computer>-<user>`, as
/// a DNS label (lowercase a-z 0-9 '-', max 63). Each Windows user on a PC
/// has their own identity, so the computer name alone is not unique (and
/// may still be held by the old service-era identity).
pub fn default_device_name(host: &str, user: &str) -> String {
    fn label(s: &str) -> String {
        let mut out = String::new();
        for c in s.trim().to_ascii_lowercase().chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c);
            } else if !out.ends_with('-') {
                out.push('-');
            }
        }
        out.trim_matches('-').to_string()
    }
    let h = label(host);
    let u = label(user);
    let mut name = match (h.is_empty(), u.is_empty()) {
        (false, false) => format!("{h}-{u}"),
        (false, true) => h,
        (true, false) => u,
        (true, true) => "ztlp-device".to_string(),
    };
    if name.len() > 63 {
        name.truncate(63);
        name = name.trim_end_matches('-').to_string();
    }
    name
}

/// This PC + user's default device name (Windows env vars).
pub fn this_device_name() -> String {
    default_device_name(
        &std::env::var("COMPUTERNAME").unwrap_or_default(),
        &std::env::var("USERNAME").unwrap_or_default(),
    )
}

// ── supervisor policy (pure) ──────────────────────────────────────────

/// Delay before restart attempt `n` (1-based consecutive failures):
/// 1 s, 2 s, 4 s, … capped at 30 s.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn restart_backoff(failures: u32) -> Duration {
    let secs = 1u64 << failures.saturating_sub(1).min(5);
    Duration::from_secs(secs.min(30))
}

/// Retry interval while another user's agent holds the ports.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const IN_USE_RETRY: Duration = Duration::from_secs(30);

/// An agent that stayed up this long resets the failure counter.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const HEALTHY_UPTIME: Duration = Duration::from_secs(60);

/// What to send the agent when the session lock state changes. `prev` =
/// last state we told it (None = never told).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn lock_command(prev: Option<bool>, locked: bool) -> Option<&'static str> {
    match (prev, locked) {
        (Some(p), l) if p == l => None,
        (_, true) => Some("freeze"),
        (None, false) => None,
        (Some(true), false) => Some("thaw"),
        (Some(false), false) => None,
    }
}

// ── probes ────────────────────────────────────────────────────────────

/// Resolve the health name through the normal OS resolver (on Windows:
/// Dnscache -> NRPT -> the agent's stub).
pub fn probe_dns() -> Result<Ipv4Addr, String> {
    use std::net::ToSocketAddrs;
    let addrs = (HEALTH_NAME, HEALTH_PORT)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?;
    addrs
        .filter_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .next()
        .ok_or_else(|| "no IPv4 answer".to_string())
}

/// TLS to the health responder, validated against the OS trust store
/// (Windows: the same Root store Edge/Chrome use).
pub fn probe_https(ip: Ipv4Addr) -> Result<(), String> {
    let roots = native_roots()?;
    probe_https_with_roots(std::net::SocketAddr::new(ip.into(), HEALTH_PORT), roots)
}

fn native_roots() -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    let res = rustls_native_certs::load_native_certs();
    for c in res.certs {
        let _ = roots.add(c);
    }
    if roots.is_empty() {
        return Err("could not read the system trust store".into());
    }
    Ok(roots)
}

/// TLS + one HTTP request against `addr` with SNI = the health name,
/// trusting only `roots`. Split out so tests can use their own root.
pub fn probe_https_with_roots(
    addr: std::net::SocketAddr,
    roots: rustls::RootCertStore,
) -> Result<(), String> {
    use std::io::{Read, Write};
    ztlp_proto::agent::ensure_rustls_crypto_provider();
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(HEALTH_NAME)
        .map_err(|e| e.to_string())?
        .to_owned();
    let conn =
        rustls::ClientConnection::new(std::sync::Arc::new(cfg), name).map_err(|e| e.to_string())?;
    let tcp = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("connect: {e}"))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(3)));
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {HEALTH_NAME}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .map_err(|e| tls_error_text(&e))?;
    let mut buf = Vec::new();
    match tls.read_to_end(&mut buf) {
        Ok(_) => {}
        // Some peers close without close_notify; what we read still counts.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) if buf.is_empty() => return Err(tls_error_text(&e)),
        Err(_) => {}
    }
    let text = String::from_utf8_lossy(&buf);
    if text.contains(HEALTH_BODY) {
        Ok(())
    } else {
        Err("unexpected reply from the agent".into())
    }
}

fn tls_error_text(e: &std::io::Error) -> String {
    let s = e.to_string();
    if s.contains("UnknownIssuer") {
        "the ZTLP root certificate is not trusted on this PC".into()
    } else {
        s
    }
}

// ── Tauri commands ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfo {
    /// Windows: the app runs the agent per user and Home shows the four
    /// checks; the service/CA/DNS setup UI is hidden.
    pub per_user_agent: bool,
    pub os: &'static str,
}

#[tauri::command]
pub fn platform_info() -> PlatformInfo {
    PlatformInfo {
        per_user_agent: PER_USER_AGENT,
        os: std::env::consts::OS,
    }
}

/// Gather the four checks (agent, identity, DNS, HTTPS). Off the window
/// thread: it does IPC, a DNS lookup and a TLS handshake.
#[tauri::command]
pub async fn health_report() -> HealthReport {
    tauri::async_runtime::spawn_blocking(health_report_sync)
        .await
        .unwrap_or_else(|e| {
            compute_health(&HealthInputs {
                agent: AgentProbe::Down(format!("background task failed: {e}")),
                supervisor_note: None,
                dns: None,
                https: None,
            })
        })
}

fn health_report_sync() -> HealthReport {
    let status = crate::ipc::ipc_request_with_addr(IPC_ADDR, "status", None);
    let setup = if status.is_ok() {
        crate::ipc::ipc_request_with_addr(IPC_ADDR, "setup_status", None).ok()
    } else {
        None
    };
    let agent = AgentProbe::from_status_result(status, setup);
    let (dns, https) = if should_probe_network(&agent) {
        let d = probe_dns();
        let h = match &d {
            Ok(ip) if *ip == HEALTH_VIP => Some(probe_https(*ip)),
            _ => None,
        };
        (Some(d), h)
    } else {
        (None, None)
    };
    compute_health(&HealthInputs {
        agent,
        supervisor_note: supervisor_note(),
        dns,
        https,
    })
}

#[cfg(target_os = "windows")]
static SUPERVISOR: std::sync::OnceLock<win::Supervisor> = std::sync::OnceLock::new();

/// Start the per-user agent supervisor + session-lock watch (Windows).
pub fn start_background() {
    #[cfg(target_os = "windows")]
    {
        let sup = SUPERVISOR.get_or_init(win::Supervisor::default);
        sup.start();
        win::start_lock_watch();
    }
}

/// Stop the agent with the app (tray Quit).
pub fn stop_background() {
    #[cfg(target_os = "windows")]
    if let Some(s) = SUPERVISOR.get() {
        s.stop();
    }
}

fn supervisor_note() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        SUPERVISOR.get().and_then(|s| s.note())
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// "Fix" on a red DNS / HTTPS row: run `ztlp agent machine-setup` elevated
/// (one UAC prompt). Returns right away; the UI re-checks until green.
#[tauri::command]
pub async fn repair_machine() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let r = tauri::async_runtime::spawn_blocking(|| {
            crate::setup::runas_ztlp(&["agent", "machine-setup"])
        })
        .await
        .map_err(|e| e.to_string())?;
        if let Some(s) = SUPERVISOR.get() {
            s.kick();
        }
        r
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("repair is only needed on Windows".into())
    }
}

// ── Windows: supervisor, session lock, repair ─────────────────────────

#[cfg(target_os = "windows")]
pub mod win {
    use super::*;
    use std::process::{Child, Command};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[derive(Default)]
    struct SupState {
        child: Option<Child>,
        started_at: Option<Instant>,
        failures: u32,
        next_try: Option<Instant>,
        note: Option<String>,
    }

    /// Owns the per-user agent child process.
    #[derive(Clone, Default)]
    pub struct Supervisor {
        inner: Arc<Mutex<SupState>>,
    }

    fn ztlp_exe() -> std::path::PathBuf {
        std::env::current_exe()
            .map(|p| crate::setup::ztlp_sibling_exe_path(&p))
            .unwrap_or_else(|_| "ztlp.exe".into())
    }

    fn log_path() -> std::path::PathBuf {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        base.join("ZTLP").join("agent.log")
    }

    impl Supervisor {
        /// Note for the Agent row while it is not up.
        pub fn note(&self) -> Option<String> {
            self.inner.lock().ok().and_then(|s| s.note.clone())
        }

        /// Try again now (e.g. after a repair), skipping any backoff.
        pub fn kick(&self) {
            if let Ok(mut s) = self.inner.lock() {
                s.next_try = None;
            }
        }

        /// Start the supervision thread.
        pub fn start(&self) {
            let me = self.clone();
            let _ = std::thread::Builder::new()
                .name("ztlp-agent-supervisor".into())
                .spawn(move || loop {
                    me.tick();
                    std::thread::sleep(Duration::from_secs(1));
                });
        }

        fn tick(&self) {
            let Ok(mut s) = self.inner.lock() else { return };
            // Reap / watch our child.
            if let Some(child) = s.child.as_mut() {
                match child.try_wait() {
                    Ok(None) => {
                        if s.started_at
                            .map(|t| t.elapsed() >= HEALTHY_UPTIME)
                            .unwrap_or(false)
                        {
                            s.failures = 0;
                            s.note = None;
                        }
                        return;
                    }
                    Ok(Some(status)) => {
                        s.child = None;
                        s.failures += 1;
                        let wait = restart_backoff(s.failures);
                        s.note = Some(format!(
                            "agent exited ({status}); restarting in {}s, see {}",
                            wait.as_secs(),
                            log_path().display()
                        ));
                        s.next_try = Some(Instant::now() + wait);
                        return;
                    }
                    Err(e) => {
                        s.note = Some(format!("cannot watch the agent: {e}"));
                        return;
                    }
                }
            }
            if let Some(t) = s.next_try {
                if Instant::now() < t {
                    return;
                }
            }
            // Something already answering? Our own agent from an earlier
            // app instance (fine, adopt it) or another user's (wait).
            match crate::ipc::ipc_request_with_addr(IPC_ADDR, "status", None) {
                Ok(_) => {
                    s.note = None;
                    s.next_try = Some(Instant::now() + Duration::from_secs(5));
                    return;
                }
                Err(e) if e.to_ascii_lowercase().contains("unauthorized") => {
                    s.note = Some("in use by another Windows user".into());
                    s.next_try = Some(Instant::now() + IN_USE_RETRY);
                    return;
                }
                Err(_) => {}
            }
            match spawn_agent() {
                Ok(child) => {
                    s.child = Some(child);
                    s.started_at = Some(Instant::now());
                    s.note = None;
                }
                Err(e) => {
                    s.failures += 1;
                    let wait = restart_backoff(s.failures);
                    s.note = Some(format!("could not start the agent: {e}"));
                    s.next_try = Some(Instant::now() + wait);
                }
            }
        }

        /// Stop the agent (app quit): ask nicely, then kill.
        pub fn stop(&self) {
            let _ = crate::ipc::ipc_request_with_addr(IPC_ADDR, "shutdown", None);
            if let Ok(mut s) = self.inner.lock() {
                if let Some(mut c) = s.child.take() {
                    for _ in 0..20 {
                        if matches!(c.try_wait(), Ok(Some(_))) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
        }
    }

    fn spawn_agent() -> std::io::Result<Child> {
        use std::os::windows::process::CommandExt;
        let log = log_path();
        if let Some(dir) = log.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Keep the log bounded: start fresh when it passes 5 MB.
        let truncate = std::fs::metadata(&log)
            .map(|m| m.len() > 5 * 1024 * 1024)
            .unwrap_or(false);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(!truncate)
            .write(true)
            .truncate(truncate)
            .open(&log)?;
        let err = file.try_clone()?;
        Command::new(ztlp_exe())
            .args([
                "agent",
                "start",
                "--foreground",
                "--parent-pid",
                &std::process::id().to_string(),
            ])
            // ZTLP_HOME means "I am the LocalSystem service" to the agent.
            .env_remove("ZTLP_HOME")
            .stdin(std::process::Stdio::null())
            .stdout(file)
            .stderr(err)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
    }

    // ── session lock watch ────────────────────────────────────────────

    /// Is the current session locked (or disconnected)?
    pub fn session_locked() -> Option<bool> {
        use std::ffi::c_void;
        #[link(name = "wtsapi32")]
        extern "system" {
            fn WTSQuerySessionInformationW(
                h_server: *mut c_void,
                session_id: u32,
                info_class: i32,
                buffer: *mut *mut u16,
                bytes_returned: *mut u32,
            ) -> i32;
            fn WTSFreeMemory(memory: *mut c_void);
        }
        const WTS_CURRENT_SESSION: u32 = 0xFFFF_FFFF;
        const WTS_SESSION_INFO_EX: i32 = 25;
        let mut buf: *mut u16 = std::ptr::null_mut();
        let mut len: u32 = 0;
        // SAFETY: documented WTS API; null server handle = local server;
        // on success `buf` points to a WTSINFOEXW of `len` bytes which we
        // read as u32 words (Level, SessionId, SessionState, SessionFlags)
        // after checking the length, then free with WTSFreeMemory.
        unsafe {
            let ok = WTSQuerySessionInformationW(
                std::ptr::null_mut(),
                WTS_CURRENT_SESSION,
                WTS_SESSION_INFO_EX,
                &mut buf,
                &mut len,
            );
            if ok == 0 || buf.is_null() {
                return None;
            }
            let words = buf as *const u32;
            let result = if len >= 16 && *words == 1 {
                let state = *words.add(2);
                let flags = *words.add(3);
                // WTS_SESSIONSTATE_LOCK = 0, UNLOCK = 1; WTSDisconnected = 4.
                Some(flags == 0 || state == 4)
            } else {
                None
            };
            WTSFreeMemory(buf as *mut c_void);
            result
        }
    }

    /// Poll the lock state every 2 s and tell the agent on each change
    /// (re-sent every 30 s while locked, in case the agent restarted).
    pub fn start_lock_watch() {
        let _ = std::thread::Builder::new()
            .name("ztlp-lock-watch".into())
            .spawn(|| {
                let mut told: Option<bool> = None;
                let mut since_resend = 0u32;
                loop {
                    if let Some(locked) = session_locked() {
                        let mut cmd = lock_command(told, locked);
                        since_resend += 1;
                        if cmd.is_none() && locked && since_resend >= 15 {
                            cmd = Some("freeze");
                        }
                        if let Some(c) = cmd {
                            since_resend = 0;
                            if crate::ipc::ipc_request_with_addr(IPC_ADDR, c, None).is_ok() {
                                told = Some(locked);
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn up(status: Value, setup: Value) -> AgentProbe {
        AgentProbe::Up { status, setup }
    }

    fn enrolled_status(checkin: Value) -> Value {
        json!({"version":"0.37.0","frozen":false,"ns_checkin":checkin})
    }

    fn setup_enrolled() -> Value {
        json!({"identity_enrolled":true,"zone":"trs.ztlp"})
    }

    fn states(r: &HealthReport) -> Vec<&'static str> {
        r.rows.iter().map(|r| r.state).collect()
    }

    #[test]
    fn all_green_when_every_check_passes() {
        let r = compute_health(&HealthInputs {
            agent: up(
                enrolled_status(json!({"state":"ok","detail":"pc.trs.ztlp","at":1})),
                setup_enrolled(),
            ),
            supervisor_note: None,
            dns: Some(Ok(HEALTH_VIP)),
            https: Some(Ok(())),
        });
        assert_eq!(states(&r), vec!["ready"; 4]);
        assert!(r.all_ready);
        assert_eq!(r.zone, "trs.ztlp");
        assert_eq!(r.rows[1].detail, "pc.trs.ztlp");
        assert_eq!(
            r.rows.iter().map(|r| r.key).collect::<Vec<_>>(),
            vec!["agent", "identity", "dns", "https"]
        );
    }

    #[test]
    fn standby_agent_asks_to_enroll_and_skips_network_checks() {
        let agent = up(
            json!({"standby":true,"version":"0.37.0"}),
            json!({"standby":true}),
        );
        assert!(!should_probe_network(&agent));
        let r = compute_health(&HealthInputs {
            agent,
            supervisor_note: None,
            dns: None,
            https: None,
        });
        assert_eq!(states(&r), vec!["ready", "action", "waiting", "waiting"]);
        assert_eq!(r.rows[1].action, Some("enroll"));
        assert!(!r.enrolled);
    }

    #[test]
    fn agent_down_puts_everything_else_in_waiting_with_the_reason() {
        let r = compute_health(&HealthInputs {
            agent: AgentProbe::Down("connection refused".into()),
            supervisor_note: Some("agent exited (exit code: 1)".into()),
            dns: None,
            https: None,
        });
        assert_eq!(states(&r), vec!["waiting"; 4]);
        assert!(r.rows[0].detail.contains("agent exited"));
    }

    #[test]
    fn unauthorized_means_another_user_owns_the_agent() {
        let p = AgentProbe::from_status_result(Err("unauthorized".into()), None);
        assert!(matches!(p, AgentProbe::Unauthorized));
        let r = compute_health(&HealthInputs {
            agent: p,
            supervisor_note: None,
            dns: None,
            https: None,
        });
        assert!(r.in_use_by_other);
        assert_eq!(r.rows[0].state, "failed");
        assert!(r.rows[0].detail.contains("another Windows user"));
    }

    #[test]
    fn dns_failure_offers_repair_and_https_waits() {
        let r = compute_health(&HealthInputs {
            agent: up(
                enrolled_status(json!({"state":"ok","detail":"pc","at":1})),
                setup_enrolled(),
            ),
            supervisor_note: None,
            dns: Some(Err("No such host is known".into())),
            https: None,
        });
        assert_eq!(states(&r), vec!["ready", "ready", "failed", "waiting"]);
        assert_eq!(r.rows[2].action, Some("repair"));
        assert_eq!(r.rows[3].action, None);
    }

    #[test]
    fn dns_answer_from_somewhere_else_is_a_failure() {
        let r = compute_health(&HealthInputs {
            agent: up(
                enrolled_status(json!({"state":"ok","detail":"pc","at":1})),
                setup_enrolled(),
            ),
            supervisor_note: None,
            dns: Some(Ok(Ipv4Addr::new(10, 0, 0, 1))),
            https: None,
        });
        assert_eq!(r.rows[2].state, "failed");
        assert!(r.rows[2].detail.contains("10.0.0.1"));
    }

    #[test]
    fn untrusted_certificate_offers_repair() {
        let r = compute_health(&HealthInputs {
            agent: up(
                enrolled_status(json!({"state":"ok","detail":"pc","at":1})),
                setup_enrolled(),
            ),
            supervisor_note: None,
            dns: Some(Ok(HEALTH_VIP)),
            https: Some(Err(
                "the ZTLP root certificate is not trusted on this PC".into()
            )),
        });
        assert_eq!(states(&r), vec!["ready", "ready", "ready", "failed"]);
        assert_eq!(r.rows[3].action, Some("repair"));
    }

    #[test]
    fn identity_states_follow_the_ns_checkin() {
        let mk = |ci: Value| {
            compute_health(&HealthInputs {
                agent: up(enrolled_status(ci), setup_enrolled()),
                supervisor_note: None,
                dns: Some(Ok(HEALTH_VIP)),
                https: Some(Ok(())),
            })
            .rows[1]
                .clone()
        };
        assert_eq!(mk(Value::Null).state, "waiting");
        assert_eq!(
            mk(json!({"state":"failed","detail":"timeout","at":1})).state,
            "waiting"
        );
        let gone = mk(json!({"state":"revoked","detail":"this device has been revoked","at":1}));
        assert_eq!((gone.state, gone.action), ("failed", Some("enroll")));
        assert_eq!(
            mk(json!({"state":"not_renewable","detail":"pc","at":1})).state,
            "ready"
        );
    }

    #[test]
    fn frozen_agent_says_so_but_stays_green() {
        let mut s = enrolled_status(json!({"state":"ok","detail":"pc","at":1}));
        s["frozen"] = json!(true);
        let r = compute_health(&HealthInputs {
            agent: up(s, setup_enrolled()),
            supervisor_note: None,
            dns: Some(Ok(HEALTH_VIP)),
            https: Some(Ok(())),
        });
        assert!(r.frozen);
        assert_eq!(r.rows[0].state, "ready");
        assert!(r.rows[0].detail.contains("locked"));
    }

    #[test]
    fn device_name_is_computer_dash_user_as_a_dns_label() {
        assert_eq!(
            default_device_name("DESKTOP-CBSQDNE", "trs"),
            "desktop-cbsqdne-trs"
        );
        assert_eq!(
            default_device_name("Front Desk PC", "Mary.O'Neil"),
            "front-desk-pc-mary-o-neil"
        );
        assert_eq!(default_device_name("", "bob"), "bob");
        assert_eq!(default_device_name("pc", ""), "pc");
        assert_eq!(default_device_name("--", "__"), "ztlp-device");
        let long = default_device_name(&"a".repeat(60), "user");
        assert!(long.len() <= 63 && !long.ends_with('-'), "{long}");
    }

    #[test]
    fn backoff_doubles_and_caps_at_30s() {
        let s: Vec<u64> = (1..=8).map(|n| restart_backoff(n).as_secs()).collect();
        assert_eq!(s, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(restart_backoff(0).as_secs(), 1);
    }

    #[test]
    fn lock_transitions_send_freeze_and_thaw_once() {
        assert_eq!(lock_command(None, false), None);
        assert_eq!(lock_command(None, true), Some("freeze"));
        assert_eq!(lock_command(Some(false), true), Some("freeze"));
        assert_eq!(lock_command(Some(true), true), None);
        assert_eq!(lock_command(Some(true), false), Some("thaw"));
        assert_eq!(lock_command(Some(false), false), None);
    }

    /// The HTTPS probe validates a leaf minted from a REAL name-constrained
    /// (`.ztlp`) machine chain — the same constraints the installer's CA
    /// carries — through the agent's own health responder.
    #[test]
    fn https_probe_accepts_the_machine_chain_and_rejects_a_stranger() {
        use ztlp_proto::agent::machine_setup::{generate_ca_chain, write_ca_chain};
        ztlp_proto::agent::ensure_rustls_crypto_provider();
        let dir = std::env::temp_dir().join(format!("ztlp-desk-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let chain = generate_ca_chain("Root (test)", "Int (test)").unwrap();
        write_ca_chain(&dir, &chain, "Root (test)", "Int (test)").unwrap();
        let ca = ztlp_proto::agent::cert_mint::IntermediateCa::load_from_dir(&dir).unwrap();
        let resolver =
            std::sync::Arc::new(ztlp_proto::agent::local_tls::SniCertResolver::with_mint_ca(
                dir.join("certs"),
                std::sync::Arc::new(ca),
            ));
        let acceptor = ztlp_proto::agent::local_tls::create_tls_acceptor(resolver).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let addr = rt.block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            tokio::spawn(ztlp_proto::agent::local_tls::run_health_responder(
                l, acceptor,
            ));
            a
        });

        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut chain.root_cert.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        assert_eq!(probe_https_with_roots(addr, roots), Ok(()));

        // A different root: must fail with the friendly "not trusted" text.
        let other = generate_ca_chain("Other", "Other int").unwrap();
        let mut wrong = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut other.root_cert.as_bytes()) {
            wrong.add(c.unwrap()).unwrap();
        }
        let err = probe_https_with_roots(addr, wrong).unwrap_err();
        assert!(err.contains("not trusted"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
