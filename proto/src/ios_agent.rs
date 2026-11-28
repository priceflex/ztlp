//! C interface for hosting the ZTLP agent inside an iOS app and its Network
//! Extension (`proto/include/ztlp_ios.h`).
//!
//! The extension runs the SAME agent as the desktop (`agent::daemon`), in
//! process, on its own small tokio runtime. This module is the thin layer
//! around it: relocate `~/.ztlp` into the App Group container, enroll
//! without a CLI, create the device-local CA, write the agent config for the
//! tunnel addresses the extension assigned, start/stop the daemon and report
//! status.
//!
//! The module is compiled on every target so its logic is unit-tested on
//! Linux; nothing here is iOS-only code, the iOS-specific behaviour lives in
//! `cfg!(target_os = "ios")` branches of the agent itself.
//!
//! Memory: the extension has a hard 50 MiB limit. Nothing here buffers
//! without a bound: the log goes straight to a size-capped file, the
//! runtime has two worker threads, and the agent is started with the
//! `mobile` transport profile.

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::agent::config::AgentConfig;
use crate::agent::daemon::{self, DaemonHooks, DaemonReady};
use crate::agent::enroll::{self, EnrollUi, SetupOpts};
use crate::agent::machine_setup;

// ── Return codes (mirrored in ztlp_ios.h) ───────────────────────────────

/// Success.
pub const ZTLP_IOS_OK: i32 = 0;
/// Failure; `ztlp_ios_last_error()` has the text.
pub const ZTLP_IOS_ERR: i32 = -1;
/// The caller's buffer is too small for the result plus its NUL.
pub const ZTLP_IOS_ERR_BUFFER_TOO_SMALL: i32 = -2;
/// A NULL pointer, invalid UTF-8 or an unusable value was passed.
pub const ZTLP_IOS_ERR_INVALID_ARGUMENT: i32 = -3;
/// `ztlp_ios_init` has not been called (successfully) in this process.
pub const ZTLP_IOS_ERR_NOT_INITIALIZED: i32 = -4;
/// The operation needs a complete enrollment and there is none.
pub const ZTLP_IOS_ERR_NOT_ENROLLED: i32 = -5;
/// `ztlp_ios_enroll` was called on a device that is already enrolled.
pub const ZTLP_IOS_ERR_ALREADY_ENROLLED: i32 = -6;

/// Port of the agent's resolver on the tunnel address.
const DNS_PORT: u16 = 53;
/// Port of the agent's control endpoint on the tunnel address (the desktop
/// default, `[ipc] listen = 127.100.255.1:4433`).
const CONTROL_PORT: u16 = 4433;

/// Common names of the device-local CA (shown by iOS when the user installs
/// and trusts the root).
const ROOT_CN: &str = "ZTLP Root CA (this device)";
const INTERMEDIATE_CN: &str = "ZTLP Intermediate CA (this device)";

/// File in `.ztlp` holding the name this device enrolled as (the desktop
/// does not persist it; the app shows it).
const ENROLLED_NAME_FILE: &str = "enrolled_name";

/// How long `ztlp_ios_agent_start` waits for the listeners to bind.
const START_TIMEOUT: Duration = Duration::from_secs(20);
/// How long `ztlp_ios_agent_stop` waits for the daemon to wind down.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

// ── Errors ──────────────────────────────────────────────────────────────

/// An error code plus its text.
#[derive(Debug)]
struct IosError {
    code: i32,
    msg: String,
}

impl IosError {
    fn new(code: i32, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }
    fn general(msg: impl Into<String>) -> Self {
        Self::new(ZTLP_IOS_ERR, msg)
    }
    fn invalid(msg: impl Into<String>) -> Self {
        Self::new(ZTLP_IOS_ERR_INVALID_ARGUMENT, msg)
    }
}

type IosResult<T> = Result<T, IosError>;

thread_local! {
    /// Text of the last error on this thread, NUL-terminated for C.
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_thread_error(msg: &str) {
    // An interior NUL cannot be represented; replace it rather than lose
    // the whole message.
    let clean = msg.replace('\0', " ");
    LAST_ERROR.with(|e| *e.borrow_mut() = CString::new(clean).unwrap_or_default());
}

fn clear_thread_error() {
    LAST_ERROR.with(|e| *e.borrow_mut() = CString::default());
}

/// Run one FFI call: clear this thread's error, catch panics (unwinding
/// into Swift is undefined behaviour), record the error text on failure.
fn ffi_call(f: impl FnOnce() -> IosResult<i32>) -> i32 {
    clear_thread_error();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_thread_error(&e.msg);
            e.code
        }
        Err(_) => {
            set_thread_error("internal error (panic) in the ZTLP agent library");
            ZTLP_IOS_ERR
        }
    }
}

// ── C string / buffer helpers ───────────────────────────────────────────

/// Borrow a C string argument as `&str`. NULL and invalid UTF-8 are
/// argument errors, never a crash.
#[allow(unsafe_code)]
fn arg_str<'a>(ptr: *const c_char, what: &str) -> IosResult<&'a str> {
    if ptr.is_null() {
        return Err(IosError::invalid(format!("{what} is NULL")));
    }
    // SAFETY: the caller promises a NUL-terminated string that outlives
    // the call (the C contract); NULL was excluded above.
    let c = unsafe { CStr::from_ptr(ptr) };
    c.to_str()
        .map_err(|_| IosError::invalid(format!("{what} is not valid UTF-8")))
}

/// Copy `s` plus a NUL into the caller's buffer. Returns the byte count
/// without the NUL, or the too-small / invalid-argument error.
#[allow(unsafe_code)]
fn write_out(buf: *mut c_char, buf_len: u32, s: &str) -> IosResult<i32> {
    if buf.is_null() {
        return Err(IosError::invalid("output buffer is NULL"));
    }
    let bytes = s.as_bytes();
    if bytes.len() > i32::MAX as usize {
        return Err(IosError::general("result too large"));
    }
    if (buf_len as usize) < bytes.len() + 1 {
        return Err(IosError::new(
            ZTLP_IOS_ERR_BUFFER_TOO_SMALL,
            format!(
                "buffer too small: need {} bytes, have {}",
                bytes.len() + 1,
                buf_len
            ),
        ));
    }
    // SAFETY: `buf` is non-NULL and the caller promises `buf_len` writable
    // bytes; we write `bytes.len() + 1 <= buf_len` of them.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, bytes.len());
        *buf.add(bytes.len()) = 0;
    }
    Ok(bytes.len() as i32)
}

// ── Process state ───────────────────────────────────────────────────────

/// The agent while it runs in this process.
struct RunningAgent {
    runtime: tokio::runtime::Runtime,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<Result<(), String>>,
    dns_state: Arc<tokio::sync::Mutex<crate::agent::dns::DnsResolverState>>,
}

#[derive(Default)]
struct Global {
    /// The App Group container (parent of `.ztlp`), set by `ztlp_ios_init`.
    home: Option<PathBuf>,
    agent: Option<RunningAgent>,
    /// Last agent-level failure, reported by `ztlp_ios_status_json`.
    last_error: String,
}

fn global() -> std::sync::MutexGuard<'static, Global> {
    static GLOBAL: std::sync::OnceLock<Mutex<Global>> = std::sync::OnceLock::new();
    GLOBAL
        .get_or_init(|| Mutex::new(Global::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Last VIP count read from the running agent (kept so a status call that
/// cannot take the resolver lock right now still reports something).
static LAST_VIPS: AtomicUsize = AtomicUsize::new(0);

/// The home directory, with the state-home override (re)applied for the
/// calling thread.
fn require_home(g: &Global) -> IosResult<PathBuf> {
    let home = g.home.clone().ok_or_else(|| {
        IosError::new(
            ZTLP_IOS_ERR_NOT_INITIALIZED,
            "ztlp_ios_init has not been called",
        )
    })?;
    crate::state_home::set_override(Some(home.clone()));
    Ok(home)
}

fn ztlp_dir(home: &Path) -> PathBuf {
    home.join(".ztlp")
}

fn identity_path(home: &Path) -> PathBuf {
    ztlp_dir(home).join("identity.json")
}

fn ca_dir(home: &Path) -> PathBuf {
    ztlp_dir(home).join("ca")
}

fn is_enrolled(home: &Path) -> bool {
    daemon::enrollment_is_complete(&identity_path(home))
}

fn ca_ready(home: &Path) -> bool {
    let dir = ca_dir(home);
    dir.join("root.pem").exists() && crate::agent::peruser::ca_dir_can_mint(&dir)
}

fn agent_is_running(g: &Global) -> bool {
    g.agent
        .as_ref()
        .map(|a| !a.join.is_finished())
        .unwrap_or(false)
}

// ── Logging: <home>/.ztlp/agent.log, size-capped ────────────────────────

/// Size at which `agent.log` is rotated to `agent.log.1` (one generation
/// kept, so the log never uses more than twice this on disk).
pub const LOG_MAX_BYTES: u64 = 1024 * 1024;

/// An append-only log file that rotates itself at a size cap. Every write
/// goes straight to the file: nothing is buffered in memory.
pub struct CappedLogFile {
    path: PathBuf,
    max_bytes: u64,
    file: Option<std::fs::File>,
    written: u64,
}

impl CappedLogFile {
    pub fn new(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes,
            file: None,
            written: 0,
        }
    }

    fn rotated_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".1");
        PathBuf::from(name)
    }

    fn open(&mut self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&self.path)?;
        self.written = file.metadata().map(|m| m.len()).unwrap_or(0);
        self.file = Some(file);
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.file = None;
        // rename replaces an older generation in one step
        std::fs::rename(&self.path, self.rotated_path())?;
        self.open()
    }

    /// Append `buf`, rotating first when it would push the file past the
    /// cap.
    pub fn append(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.file.is_none() {
            self.open()?;
        }
        if self.written > 0 && self.written + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        if let Some(f) = self.file.as_mut() {
            f.write_all(buf)?;
            self.written += buf.len() as u64;
        }
        Ok(())
    }
}

/// `tracing` writer over a shared [`CappedLogFile`]. Write errors are
/// swallowed: logging must never take the agent down.
#[derive(Clone)]
pub struct LogWriter(Arc<Mutex<CappedLogFile>>);

impl LogWriter {
    pub fn new(path: PathBuf, max_bytes: u64) -> Self {
        Self(Arc::new(Mutex::new(CappedLogFile::new(path, max_bytes))))
    }
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut f = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let _ = f.append(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Send the process's `tracing` output to `<home>/.ztlp/agent.log`. Once
/// per process; a later call (or a subscriber someone else installed) is
/// left alone.
fn install_logging(home: &Path) {
    // Unit tests share one process: a global subscriber installed by one
    // test would capture every other test's output into a temp directory.
    if cfg!(test) {
        return;
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    let path = ztlp_dir(home).join("agent.log");
    ONCE.call_once(|| {
        let writer = LogWriter::new(path, LOG_MAX_BYTES);
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(writer)
            .try_init();
    });
}

/// Enrollment progress lines go to the log (plain, no colours).
struct LogUi;

impl EnrollUi for LogUi {
    fn say(&self, line: &str) {
        let line = line.trim();
        if !line.is_empty() {
            tracing::info!(target: "enroll", "{}", line);
        }
    }
}

// ── File descriptors ────────────────────────────────────────────────────

/// Descriptors the agent wants available: every resolved name gets a
/// listener per VIP port (8 by default), on top of client connections,
/// tunnel sockets and files.
const WANTED_OPEN_FILES: u64 = 4096;

/// Raise this process's soft open-file limit towards
/// [`WANTED_OPEN_FILES`] (never above the hard limit, never lowering it).
/// iOS starts processes at 256, which a /27 VIP pool can exhaust. Returns
/// the soft limit now in force, or `None` when it could not be read.
#[cfg(unix)]
#[allow(unsafe_code)]
fn raise_open_file_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain libc call writing into a local struct.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return None;
    }
    let hard = lim.rlim_max as u64;
    let cur = lim.rlim_cur as u64;
    let want = WANTED_OPEN_FILES.min(hard);
    if cur >= want {
        return Some(cur);
    }
    let new = libc::rlimit {
        rlim_cur: want as libc::rlim_t,
        rlim_max: lim.rlim_max,
    };
    // SAFETY: as above; a refused change leaves the old limit in place.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } != 0 {
        return Some(cur);
    }
    Some(want)
}

#[cfg(not(unix))]
fn raise_open_file_limit() -> Option<u64> {
    None
}

// ── Pure helpers (unit-tested) ──────────────────────────────────────────

/// Turn a device name the user sees ("Steve's iPhone 15") into the DNS
/// label the name server registers ("steves-iphone-15"): lower-case ASCII
/// letters, digits and single hyphens, at most 63 bytes, never empty.
pub fn sanitize_device_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '\'' || ch == '\u{2019}' {
            // apostrophes vanish ("steve's" -> "steves")
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let mut out: String = out.trim_matches('-').chars().take(63).collect();
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "iphone".to_string()
    } else {
        out
    }
}

/// How sites get a local address, decided by the prefix length of the
/// `vip_cidr` argument of `ztlp_ios_agent_start`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SitePlan {
    /// A pool of addresses, one per site (`[dns] vip_range`).
    Pool(String),
    /// `a.b.c.d/32`: one address for every site, told apart by name
    /// (`[dns] single_address`).
    Single(Ipv4Addr),
}

impl std::fmt::Display for SitePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SitePlan::Pool(cidr) => write!(f, "VIP pool {cidr}"),
            SitePlan::Single(addr) => write!(f, "all sites on {addr} (by name)"),
        }
    }
}

/// Validate the tunnel addresses the extension passes to
/// `ztlp_ios_agent_start`: an IPv4 resolver address, and either an IPv4
/// CIDR pool that does not contain it or a single `/32` address (which may
/// be the resolver's own: the ports differ).
fn validate_tunnel_addrs(dns_ip: &str, vip_cidr: &str) -> IosResult<(Ipv4Addr, SitePlan)> {
    let ip: Ipv4Addr = dns_ip
        .trim()
        .parse()
        .map_err(|_| IosError::invalid(format!("dns_ip '{dns_ip}' is not an IPv4 address")))?;
    let cidr = vip_cidr.trim().to_string();
    if let Some(addr) = cidr.strip_suffix("/32") {
        let addr: Ipv4Addr = addr.parse().map_err(|_| {
            IosError::invalid(format!("vip_cidr '{vip_cidr}' is not an IPv4 address/32"))
        })?;
        return Ok((ip, SitePlan::Single(addr)));
    }
    crate::agent::vip_pool::VipPool::new(&cidr)
        .map_err(|e| IosError::invalid(format!("vip_cidr '{vip_cidr}' is not usable: {e}")))?;
    let (base, prefix) = cidr
        .split_once('/')
        .and_then(|(b, p)| Some((b.parse::<Ipv4Addr>().ok()?, p.parse::<u32>().ok()?)))
        .ok_or_else(|| IosError::invalid(format!("vip_cidr '{vip_cidr}' is not a CIDR")))?;
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    if u32::from(ip) & mask == u32::from(base) & mask {
        return Err(IosError::invalid(format!(
            "dns_ip {ip} is inside the VIP pool {cidr}; the resolver needs its own address"
        )));
    }
    Ok((ip, SitePlan::Pool(cidr)))
}

/// Ports the agent's own listeners use: resolver and control on `dns_ip`,
/// and in single-address mode HTTPS and HTTP on the shared address.
#[derive(Debug, Clone, Copy)]
struct ListenPorts {
    dns: u16,
    control: u16,
    https: u16,
    http: u16,
}

impl ListenPorts {
    const IOS: Self = Self {
        dns: DNS_PORT,
        control: CONTROL_PORT,
        https: 443,
        http: 80,
    };
}

/// Produce the agent.toml the iOS agent runs with: whatever enrollment (or
/// a previous start) wrote, with the settings the tunnel dictates set on
/// top. Unknown keys are preserved; comments are not (the file is
/// machine-managed on iOS).
fn apply_ios_settings(
    existing_toml: &str,
    home: &Path,
    dns_ip: Ipv4Addr,
    sites: &SitePlan,
    ports: ListenPorts,
) -> Result<String, String> {
    use toml::Value;

    let mut doc: toml::Table = if existing_toml.trim().is_empty() {
        toml::Table::new()
    } else {
        existing_toml
            .parse::<toml::Table>()
            .map_err(|e| format!("agent.toml does not parse: {e}"))?
    };

    fn table<'a>(doc: &'a mut toml::Table, key: &str) -> Result<&'a mut toml::Table, String> {
        let entry = doc
            .entry(key.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        entry
            .as_table_mut()
            .ok_or_else(|| format!("agent.toml: [{key}] is not a table"))
    }

    // The App Group container path is not guaranteed stable across
    // restores: always point at the identity under the current home.
    table(&mut doc, "identity")?.insert(
        "path".into(),
        Value::String(identity_path(home).display().to_string()),
    );

    let dns = table(&mut doc, "dns")?;
    dns.insert("enabled".into(), Value::Boolean(true));
    dns.insert(
        "listen".into(),
        Value::String(SocketAddr::from((dns_ip, ports.dns)).to_string()),
    );
    // Exactly one of the two site plans is in the file, so going from one
    // to the other at the next start leaves nothing of the old one behind.
    for key in [
        "vip_range",
        "single_address",
        "single_address_https_port",
        "single_address_http_port",
    ] {
        dns.remove(key);
    }
    match sites {
        SitePlan::Pool(cidr) => {
            dns.insert("vip_range".into(), Value::String(cidr.clone()));
        }
        SitePlan::Single(addr) => {
            dns.insert("single_address".into(), Value::String(addr.to_string()));
            // Only written when not the defaults (tests).
            if ports.https != ListenPorts::IOS.https {
                dns.insert(
                    "single_address_https_port".into(),
                    Value::Integer(ports.https.into()),
                );
            }
            if ports.http != ListenPorts::IOS.http {
                dns.insert(
                    "single_address_http_port".into(),
                    Value::Integer(ports.http.into()),
                );
            }
        }
    }
    dns.insert("tcp".into(), Value::Boolean(true));

    table(&mut doc, "ipc")?.insert(
        "listen".into(),
        Value::String(SocketAddr::from((dns_ip, ports.control)).to_string()),
    );

    let tls = table(&mut doc, "tls")?;
    tls.insert("enabled".into(), Value::Boolean(true));
    tls.insert("health_ip".into(), Value::String(dns_ip.to_string()));

    let tunnel = table(&mut doc, "tunnel")?;
    tunnel.insert("profile".into(), Value::String("mobile".into()));
    tunnel.insert("reuse_connections".into(), Value::Boolean(true));

    let body = toml::to_string(&doc).map_err(|e| format!("cannot render agent.toml: {e}"))?;
    Ok(format!(
        "# ZTLP agent configuration (iOS). Managed by the app: the [dns], [ipc],\n\
         # [tls] and [tunnel] profile keys are rewritten at every tunnel start.\n\n{body}"
    ))
}

/// Write a file atomically, owner-only (agent.toml holds the relay secret).
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// The enrolled zone, from the `config.toml` enrollment wrote ("" when
/// there is none).
fn enrolled_zone(home: &Path) -> String {
    std::fs::read_to_string(ztlp_dir(home).join("config.toml"))
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .and_then(|t| t.get("zone").and_then(|z| z.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// The name this device enrolled as ("" when unknown).
fn enrolled_name(home: &Path) -> String {
    std::fs::read_to_string(ztlp_dir(home).join(ENROLLED_NAME_FILE))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ── Operations ──────────────────────────────────────────────────────────

fn do_init(home_dir: &str) -> IosResult<i32> {
    let home = PathBuf::from(home_dir.trim());
    if home_dir.trim().is_empty() || !home.is_absolute() {
        return Err(IosError::invalid(
            "home_dir must be an absolute directory path",
        ));
    }
    let dir = ztlp_dir(&home);
    std::fs::create_dir_all(&dir)
        .map_err(|e| IosError::general(format!("cannot create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    let mut g = global();
    if agent_is_running(&g) && g.home.as_deref() != Some(home.as_path()) {
        return Err(IosError::general(
            "the agent is running with a different home directory; stop it first",
        ));
    }
    crate::state_home::set_override(Some(home.clone()));
    install_logging(&home);
    // rustls cannot pick a crypto provider by itself (two are in the
    // dependency tree); the CLI does this in main(). Without it the agent's
    // local TLS panics on first use.
    crate::agent::ensure_rustls_crypto_provider();
    g.home = Some(home.clone());
    let open_files = raise_open_file_limit();
    tracing::info!(
        "ZTLP iOS agent library v{} initialised (home {}, open-file limit {})",
        env!("CARGO_PKG_VERSION"),
        home.display(),
        open_files
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    Ok(ZTLP_IOS_OK)
}

fn do_enroll(enrollment_uri: &str, device_name: Option<&str>) -> IosResult<i32> {
    let home = require_home(&global())?;
    if is_enrolled(&home) {
        return Err(IosError::new(
            ZTLP_IOS_ERR_ALREADY_ENROLLED,
            "this device is already enrolled; remove the enrollment first",
        ));
    }
    let dir = ztlp_dir(&home);
    // A previous attempt that died after writing identity.json would make
    // this one fail as "already enrolled".
    daemon::remove_orphan_identity(&identity_path(&home));

    let name = sanitize_device_name(device_name.unwrap_or(""));
    let uri = enrollment_uri.trim().to_string();

    // Enrollment is a handful of UDP exchanges: a current-thread runtime on
    // the caller's thread, dropped when done.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| IosError::general(format!("cannot start runtime: {e}")))?;
    let result: Result<enroll::EnrollOutcome, String> = rt.block_on(async {
        let token = enroll::parse_enrollment_token(&uri).map_err(|e| e.to_string())?;
        let opts = SetupOpts {
            force: false,
            relay_secret: None,
            relay: None,
        };
        enroll::enroll_with_token(&token, &name, &dir, false, &opts, &LogUi)
            .await
            .map_err(|e| e.to_string())
    });
    drop(rt);

    match result {
        Ok(outcome) => {
            if let Err(e) = std::fs::write(dir.join(ENROLLED_NAME_FILE), &outcome.full_name) {
                tracing::warn!("could not record the enrolled name: {e}");
            }
            tracing::info!("enrolled as {} (zone {})", outcome.full_name, outcome.zone);
            Ok(ZTLP_IOS_OK)
        }
        Err(e) => {
            // Same clean-up the desktop daemon does after a failed setup.
            daemon::remove_orphan_identity(&identity_path(&home));
            tracing::warn!("enrollment failed: {e}");
            Err(IosError::general(format!("enrollment failed: {e}")))
        }
    }
}

fn do_ensure_ca() -> IosResult<i32> {
    let home = require_home(&global())?;
    if ca_ready(&home) {
        return Ok(ZTLP_IOS_OK);
    }
    let dir = ca_dir(&home);
    if dir.join("root.key").exists() {
        // write_ca_chain writes root.key last, so this is a complete chain
        // that has since lost files. Never silently replace a root the user
        // may already have trusted.
        return Err(IosError::general(format!(
            "the CA at {} is incomplete (root key present, other files missing)",
            dir.display()
        )));
    }
    let chain = machine_setup::generate_ca_chain(ROOT_CN, INTERMEDIATE_CN)
        .map_err(|e| IosError::general(format!("cannot generate the CA: {e}")))?;
    machine_setup::write_ca_chain(&dir, &chain, ROOT_CN, INTERMEDIATE_CN)
        .map_err(|e| IosError::general(format!("cannot write the CA: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // One sandboxed user on iOS: no group needs the signing key.
        let _ = std::fs::set_permissions(
            dir.join("intermediate.key"),
            std::fs::Permissions::from_mode(0o600),
        );
    }
    tracing::info!("device-local CA created at {}", dir.display());
    Ok(ZTLP_IOS_OK)
}

fn read_ca_root_pem() -> IosResult<String> {
    let home = require_home(&global())?;
    let path = ca_dir(&home).join("root.pem");
    std::fs::read_to_string(&path).map_err(|e| {
        IosError::general(format!(
            "no CA root certificate at {} ({e}); call ztlp_ios_ensure_ca first",
            path.display()
        ))
    })
}

/// Stop and discard an agent (running or already finished).
fn teardown(agent: RunningAgent) {
    let RunningAgent {
        runtime,
        shutdown,
        join,
        dns_state,
    } = agent;
    drop(dns_state);
    if let Some(tx) = shutdown {
        let _ = tx.send(());
    }
    let _ = runtime.block_on(async { tokio::time::timeout(STOP_TIMEOUT, join).await });
    // Dropping the runtime cancels every remaining task (per-VIP listeners,
    // bridges), which is what frees the sockets.
    runtime.shutdown_timeout(Duration::from_secs(2));
    daemon::close_shared_tunnels();
    LAST_VIPS.store(0, Ordering::Relaxed);
}

fn do_agent_start(dns_ip: &str, vip_cidr: &str, ports: ListenPorts) -> IosResult<i32> {
    let mut g = global();
    let home = require_home(&g)?;
    if agent_is_running(&g) {
        return Ok(ZTLP_IOS_OK);
    }
    // A daemon that exited on its own leaves its runtime behind.
    if let Some(old) = g.agent.take() {
        teardown(old);
    }
    match start_agent(&home, dns_ip, vip_cidr, ports) {
        Ok(agent) => {
            g.agent = Some(agent);
            g.last_error.clear();
            Ok(ZTLP_IOS_OK)
        }
        Err(e) => {
            tracing::error!("agent start failed: {}", e.msg);
            g.last_error = e.msg.clone();
            Err(e)
        }
    }
}

fn start_agent(
    home: &Path,
    dns_ip: &str,
    vip_cidr: &str,
    ports: ListenPorts,
) -> IosResult<RunningAgent> {
    let (ip, sites) = validate_tunnel_addrs(dns_ip, vip_cidr)?;
    if !is_enrolled(home) {
        return Err(IosError::new(
            ZTLP_IOS_ERR_NOT_ENROLLED,
            "this device is not enrolled",
        ));
    }

    // agent.toml for these tunnel addresses.
    let dir = ztlp_dir(home);
    let agent_toml = dir.join("agent.toml");
    let existing = match std::fs::read_to_string(&agent_toml) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(IosError::general(format!(
                "cannot read {}: {e}",
                agent_toml.display()
            )))
        }
    };
    let updated =
        apply_ios_settings(&existing, home, ip, &sites, ports).map_err(IosError::general)?;
    write_private(&agent_toml, &updated)
        .map_err(|e| IosError::general(format!("cannot write {}: {e}", agent_toml.display())))?;
    let config = AgentConfig::load_merged(&agent_toml, &dir.join("config.toml"))
        .map_err(|e| IosError::general(format!("agent config: {e}")))?;

    // Two workers: the agent is I/O bound and every thread costs stack and
    // allocator arenas the extension cannot spare.
    let thread_home = home.to_path_buf();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_name("ztlp-agent")
        .on_thread_start(move || {
            crate::state_home::set_override(Some(thread_home.clone()));
        })
        .enable_all()
        .build()
        .map_err(|e| IosError::general(format!("cannot start runtime: {e}")))?;

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<DaemonReady>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let hooks = DaemonHooks {
        ready: Some(ready_tx),
        shutdown: Some(shutdown_rx),
    };
    let mut join = runtime.spawn(async move {
        let result = daemon::run_daemon_with_hooks(&config, false, hooks)
            .await
            .map_err(|e| e.to_string());
        match &result {
            Ok(()) => tracing::info!("agent task finished"),
            Err(e) => {
                tracing::error!("agent stopped with an error: {e}");
                global_note_error(e);
            }
        }
        result
    });

    enum Startup {
        Ready(DaemonReady),
        Exited(String),
        TimedOut,
    }
    let startup = runtime.block_on(async {
        tokio::select! {
            r = ready_rx => match r {
                Ok(ready) => Startup::Ready(ready),
                // sender dropped: the daemon failed before it was ready
                Err(_) => match (&mut join).await {
                    Ok(Err(e)) => Startup::Exited(e),
                    Ok(Ok(())) => Startup::Exited("the agent exited during startup".into()),
                    Err(e) => Startup::Exited(format!("the agent task failed: {e}")),
                },
            },
            _ = tokio::time::sleep(START_TIMEOUT) => Startup::TimedOut,
        }
    });

    let fail = |runtime: tokio::runtime::Runtime,
                shutdown: tokio::sync::oneshot::Sender<()>,
                msg: String| {
        let _ = shutdown.send(());
        runtime.shutdown_timeout(Duration::from_secs(2));
        daemon::close_shared_tunnels();
        IosError::general(msg)
    };

    let ready = match startup {
        Startup::Ready(r) => r,
        Startup::Exited(e) => return Err(fail(runtime, shutdown_tx, e)),
        Startup::TimedOut => {
            return Err(fail(
                runtime,
                shutdown_tx,
                format!("the agent did not finish starting within {START_TIMEOUT:?}"),
            ))
        }
    };

    // The OS resolver can only be pointed at port 53 on dns_ip: a resolver
    // that fell back to another port is a failed start, not a success.
    let want_dns = SocketAddr::from((ip, ports.dns));
    if ready.dns_listen != Some(want_dns) {
        let got = ready
            .dns_listen
            .map(|a| a.to_string())
            .unwrap_or_else(|| "nothing".to_string());
        return Err(fail(
            runtime,
            shutdown_tx,
            format!("the resolver could not bind {want_dns} (bound {got})"),
        ));
    }
    if !ready.tls_ready {
        tracing::warn!("local TLS is not active: https names will not work until the CA exists");
    }
    if !ready.control_bound {
        tracing::warn!(
            "control endpoint {} did not bind; the agent runs without it",
            SocketAddr::from((ip, ports.control))
        );
    }
    if let SitePlan::Single(addr) = &sites {
        // The daemon refuses to start without the HTTPS listener; HTTP is
        // optional and its failure is already in the log.
        tracing::info!(
            "single address {addr}: https on {}, http on {}",
            ready
                .single_https_listen
                .map_or_else(|| "nothing".to_string(), |a| a.to_string()),
            ready
                .single_http_listen
                .map_or_else(|| "nothing".to_string(), |a| a.to_string()),
        );
    }
    tracing::info!(
        "agent started: resolver {want_dns}, {sites}, TLS {}",
        if ready.tls_ready { "on" } else { "off" }
    );

    Ok(RunningAgent {
        runtime,
        shutdown: Some(shutdown_tx),
        join,
        dns_state: ready.dns_state,
    })
}

/// An agent-level error reported from inside the agent task, picked up by
/// the next status call. Kept apart from [`Global`] because the FFI thread
/// may hold that lock while it waits for this very task.
static PENDING_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn global_note_error(msg: &str) {
    *PENDING_ERROR.lock().unwrap_or_else(|p| p.into_inner()) = Some(msg.to_string());
}

fn do_agent_stop() -> IosResult<i32> {
    let mut g = global();
    if let Some(agent) = g.agent.take() {
        tracing::info!("stopping the agent");
        teardown(agent);
        tracing::info!("agent stopped");
    }
    Ok(ZTLP_IOS_OK)
}

fn status_json() -> String {
    let mut g = global();
    // Fold in an error the agent task reported since the last call.
    if let Some(text) = PENDING_ERROR
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
    {
        g.last_error = text;
    }
    let running = agent_is_running(&g);
    let home = g.home.clone();
    if let Some(h) = &home {
        crate::state_home::set_override(Some(h.clone()));
    }
    let vips = match (&g.agent, running) {
        (Some(agent), true) => {
            if let Ok(st) = agent.dns_state.try_lock() {
                // Single-address mode has no VIPs: count the sites known
                // by name instead (resolved in the last five minutes).
                let sites = st
                    .single
                    .as_ref()
                    .map_or(0, |s| s.live_sites(std::time::Instant::now()));
                LAST_VIPS.store(st.vip_pool.allocated_count() + sites, Ordering::Relaxed);
            }
            LAST_VIPS.load(Ordering::Relaxed)
        }
        _ => 0,
    };
    let tunnels = if running {
        daemon::shared_tunnel_count()
    } else {
        0
    };
    let (enrolled, node_name, zone, ca) = match &home {
        Some(h) => {
            let enrolled = is_enrolled(h);
            (
                enrolled,
                if enrolled {
                    enrolled_name(h)
                } else {
                    String::new()
                },
                if enrolled {
                    enrolled_zone(h)
                } else {
                    String::new()
                },
                ca_ready(h),
            )
        }
        None => (false, String::new(), String::new(), false),
    };
    let last_error = if home.is_none() && g.last_error.is_empty() {
        "ztlp_ios_init has not been called".to_string()
    } else {
        g.last_error.clone()
    };
    serde_json::json!({
        "running": running,
        "enrolled": enrolled,
        "node_name": node_name,
        "zone": zone,
        "vips": vips,
        "tunnels": tunnels,
        "ca_ready": ca,
        "last_error": last_error,
    })
    .to_string()
}

// ── The C functions ─────────────────────────────────────────────────────

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_init(home_dir: *const c_char) -> i32 {
    ffi_call(|| do_init(arg_str(home_dir, "home_dir")?))
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_is_enrolled() -> i32 {
    let r = ffi_call(|| {
        let home = require_home(&global())?;
        Ok(i32::from(is_enrolled(&home)))
    });
    // Contract: 1 or 0, never negative (the error text is still recorded).
    r.max(0)
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_enroll(
    enrollment_uri: *const c_char,
    device_name: *const c_char,
) -> i32 {
    ffi_call(|| {
        let uri = arg_str(enrollment_uri, "enrollment_uri")?;
        if uri.trim().is_empty() {
            return Err(IosError::invalid("enrollment_uri is empty"));
        }
        // device_name may be NULL: a default name is used.
        let name = if device_name.is_null() {
            None
        } else {
            Some(arg_str(device_name, "device_name")?)
        };
        do_enroll(uri, name)
    })
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_ensure_ca() -> i32 {
    ffi_call(do_ensure_ca)
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_ca_root_pem(buf: *mut c_char, buf_len: u32) -> i32 {
    ffi_call(|| {
        if buf.is_null() {
            return Err(IosError::invalid("output buffer is NULL"));
        }
        let pem = read_ca_root_pem()?;
        write_out(buf, buf_len, &pem)
    })
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_agent_start(dns_ip: *const c_char, vip_cidr: *const c_char) -> i32 {
    ffi_call(|| {
        let dns_ip = arg_str(dns_ip, "dns_ip")?;
        let vip_cidr = arg_str(vip_cidr, "vip_cidr")?;
        do_agent_start(dns_ip, vip_cidr, ListenPorts::IOS)
    })
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_agent_stop() -> i32 {
    ffi_call(do_agent_stop)
}

/// See `ztlp_ios.h`. Deliberately does not take the FFI state lock (a
/// start or stop in progress holds it for seconds) and does not touch this
/// thread's last error: it only raises a flag the running agent acts on.
#[no_mangle]
pub extern "C" fn ztlp_ios_network_changed() -> i32 {
    let _ = std::panic::catch_unwind(daemon::notify_network_changed);
    ZTLP_IOS_OK
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_status_json(buf: *mut c_char, buf_len: u32) -> i32 {
    ffi_call(|| {
        if buf.is_null() {
            return Err(IosError::invalid("output buffer is NULL"));
        }
        write_out(buf, buf_len, &status_json())
    })
}

/// See `ztlp_ios.h`.
#[no_mangle]
pub extern "C" fn ztlp_ios_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// The FFI layer keeps process-wide state (home, running agent): tests
    /// that go through it run one at a time, each from a clean slate.
    static FFI_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Fixture {
        _guard: std::sync::MutexGuard<'static, ()>,
        // A started agent turns shared connections on for the process.
        _shared_mode: tokio::sync::MutexGuard<'static, ()>,
        dir: tempfile::TempDir,
    }

    impl Fixture {
        /// Clean state, NOT initialised.
        fn uninitialised() -> Self {
            let guard = FFI_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let shared_mode = daemon::SHARED_MODE_TEST_LOCK.blocking_lock();
            reset();
            Self {
                _guard: guard,
                _shared_mode: shared_mode,
                dir: tempfile::tempdir().unwrap(),
            }
        }

        /// Clean state, `ztlp_ios_init` called on a fresh temp directory.
        fn initialised() -> Self {
            let f = Self::uninitialised();
            let home = CString::new(f.home().to_str().unwrap()).unwrap();
            assert_eq!(
                ztlp_ios_init(home.as_ptr()),
                ZTLP_IOS_OK,
                "{}",
                last_error()
            );
            f
        }

        fn home(&self) -> &Path {
            self.dir.path()
        }

        fn ztlp(&self) -> PathBuf {
            self.home().join(".ztlp")
        }

        /// Files a successful enrollment leaves behind (no network).
        fn fake_enrollment(&self) {
            let dir = self.ztlp();
            let key = dir.join("identity.json");
            crate::identity::NodeIdentity::generate()
                .unwrap()
                .save(&key)
                .unwrap();
            enroll::write_config_file(
                &dir.join("config.toml"),
                &key,
                "office.example.ztlp",
                "127.0.0.1:1",
                &[],
                &[],
            )
            .unwrap();
            enroll::write_agent_config_file(
                &dir.join("agent.toml"),
                &key,
                "office.example.ztlp",
                "127.0.0.1:1",
                &[],
                Some("test-relay-secret"),
            )
            .unwrap();
            std::fs::write(dir.join(ENROLLED_NAME_FILE), "phone.office.example.ztlp").unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            reset();
        }
    }

    fn reset() {
        let _ = ztlp_ios_agent_stop();
        let mut g = global();
        g.home = None;
        g.last_error.clear();
        drop(g);
        *PENDING_ERROR.lock().unwrap_or_else(|p| p.into_inner()) = None;
        crate::state_home::set_override(None);
        clear_thread_error();
    }

    fn last_error() -> String {
        let p = ztlp_ios_last_error();
        assert!(!p.is_null());
        #[allow(unsafe_code)]
        unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string()
    }

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Call a buffer-returning function with a buffer of `cap` bytes.
    fn call_buf(f: extern "C" fn(*mut c_char, u32) -> i32, cap: usize) -> (i32, String) {
        let mut buf = vec![0x7f_u8; cap.max(1)];
        let rc = f(buf.as_mut_ptr() as *mut c_char, cap as u32);
        let text = if rc >= 0 {
            assert_eq!(buf[rc as usize], 0, "result must be NUL-terminated");
            String::from_utf8(buf[..rc as usize].to_vec()).unwrap()
        } else {
            String::new()
        };
        (rc, text)
    }

    fn status() -> serde_json::Value {
        let (rc, text) = call_buf(ztlp_ios_status_json, 4096);
        assert!(rc > 0, "status_json failed: {}", last_error());
        serde_json::from_str(&text).expect("status is JSON")
    }

    // ── pointers and arguments ──────────────────────────────────────────

    #[test]
    fn null_pointers_are_errors_not_crashes() {
        let _f = Fixture::initialised();
        let ok = c("x");

        assert_eq!(
            ztlp_ios_init(std::ptr::null()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert!(last_error().contains("home_dir"), "{}", last_error());
        assert_eq!(
            ztlp_ios_enroll(std::ptr::null(), ok.as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            ztlp_ios_agent_start(std::ptr::null(), ok.as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            ztlp_ios_agent_start(ok.as_ptr(), std::ptr::null()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            ztlp_ios_ca_root_pem(std::ptr::null_mut(), 4096),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            ztlp_ios_status_json(std::ptr::null_mut(), 4096),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert!(last_error().contains("NULL"), "{}", last_error());
    }

    #[test]
    fn invalid_utf8_is_an_argument_error() {
        let _f = Fixture::uninitialised();
        let bad: [u8; 4] = [0xff, 0xfe, b'x', 0];
        assert_eq!(
            ztlp_ios_init(bad.as_ptr() as *const c_char),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert!(last_error().contains("UTF-8"), "{}", last_error());
    }

    #[test]
    fn init_rejects_empty_and_relative_paths() {
        let _f = Fixture::uninitialised();
        assert_eq!(ztlp_ios_init(c("").as_ptr()), ZTLP_IOS_ERR_INVALID_ARGUMENT);
        assert_eq!(
            ztlp_ios_init(c("relative/dir").as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert!(global().home.is_none());
    }

    #[test]
    fn init_creates_the_state_dir_and_relocates_ztlp_state() {
        let f = Fixture::initialised();
        assert!(f.ztlp().is_dir());
        // every "~/.ztlp" lookup now lands under home_dir
        assert_eq!(crate::agent::config::ztlp_state_dir(), f.home());
        assert!(crate::ns_cache::default_dir().starts_with(f.ztlp()));
        assert!(crate::agent::config::default_token_path().starts_with(f.ztlp()));
        assert!(AgentConfig::default().identity_path().starts_with(f.ztlp()));
        // calling it again is fine
        assert_eq!(ztlp_ios_init(c(f.home().to_str().unwrap()).as_ptr()), 0);
    }

    // ── before init ─────────────────────────────────────────────────────

    #[test]
    fn everything_reports_not_initialised_before_init() {
        let _f = Fixture::uninitialised();
        assert_eq!(ztlp_ios_is_enrolled(), 0);
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_ERR_NOT_INITIALIZED);
        assert!(last_error().contains("ztlp_ios_init"), "{}", last_error());
        assert_eq!(
            ztlp_ios_enroll(c("ztlp://enroll/x").as_ptr(), c("phone").as_ptr()),
            ZTLP_IOS_ERR_NOT_INITIALIZED
        );
        assert_eq!(
            ztlp_ios_agent_start(c("100.64.77.1").as_ptr(), c("100.64.77.32/27").as_ptr()),
            ZTLP_IOS_ERR_NOT_INITIALIZED
        );
        let (rc, _) = call_buf(ztlp_ios_ca_root_pem, 4096);
        assert_eq!(rc, ZTLP_IOS_ERR_NOT_INITIALIZED);
        // stop is always safe, status always answers
        assert_eq!(ztlp_ios_agent_stop(), ZTLP_IOS_OK);
        let st = status();
        assert_eq!(st["running"], false);
        assert_eq!(st["enrolled"], false);
        assert!(st["last_error"].as_str().unwrap().contains("ztlp_ios_init"));
    }

    // ── enrollment state ────────────────────────────────────────────────

    #[test]
    fn is_enrolled_needs_identity_and_a_zone() {
        let f = Fixture::initialised();
        assert_eq!(ztlp_ios_is_enrolled(), 0);

        // identity.json alone is an orphan of a failed enrollment
        let key = f.ztlp().join("identity.json");
        crate::identity::NodeIdentity::generate()
            .unwrap()
            .save(&key)
            .unwrap();
        assert_eq!(ztlp_ios_is_enrolled(), 0);

        std::fs::write(
            f.ztlp().join("config.toml"),
            "zone = \"office.example.ztlp\"\n",
        )
        .unwrap();
        assert_eq!(ztlp_ios_is_enrolled(), 1);
    }

    #[test]
    fn enroll_with_a_bad_token_fails_cleanly_and_leaves_nothing_behind() {
        let f = Fixture::initialised();
        let rc = ztlp_ios_enroll(
            c("ztlp://enroll/this-is-not-a-token").as_ptr(),
            c("Test Phone").as_ptr(),
        );
        assert_eq!(rc, ZTLP_IOS_ERR);
        let err = last_error();
        assert!(err.contains("enrollment failed"), "{err}");
        assert!(err.contains("invalid enrollment token"), "{err}");
        assert!(!f.ztlp().join("identity.json").exists());
        assert_eq!(ztlp_ios_is_enrolled(), 0);
        // empty URI is an argument error
        assert_eq!(
            ztlp_ios_enroll(c("  ").as_ptr(), std::ptr::null()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
    }

    #[test]
    fn enroll_refuses_an_already_enrolled_device() {
        let f = Fixture::initialised();
        f.fake_enrollment();
        let before = std::fs::read(f.ztlp().join("identity.json")).unwrap();
        let rc = ztlp_ios_enroll(c("ztlp://enroll/whatever").as_ptr(), c("phone").as_ptr());
        assert_eq!(rc, ZTLP_IOS_ERR_ALREADY_ENROLLED);
        assert!(last_error().contains("already enrolled"));
        assert_eq!(
            std::fs::read(f.ztlp().join("identity.json")).unwrap(),
            before,
            "the existing identity must not be touched"
        );
    }

    // ── CA ──────────────────────────────────────────────────────────────

    #[test]
    fn ensure_ca_creates_a_mintable_chain_once() {
        let f = Fixture::initialised();
        assert_eq!(status()["ca_ready"], false);
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK, "{}", last_error());

        let ca = f.ztlp().join("ca");
        let root = std::fs::read(ca.join("root.pem")).unwrap();
        let int_key = std::fs::read(ca.join("intermediate.key")).unwrap();
        assert!(crate::agent::cert_mint::IntermediateCa::load_from_dir(&ca).is_ok());
        assert_eq!(status()["ca_ready"], true);

        // idempotent: nothing is regenerated
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK);
        assert_eq!(std::fs::read(ca.join("root.pem")).unwrap(), root);
        assert_eq!(std::fs::read(ca.join("intermediate.key")).unwrap(), int_key);
    }

    #[test]
    fn ensure_ca_does_not_replace_a_damaged_ca() {
        let f = Fixture::initialised();
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK);
        let ca = f.ztlp().join("ca");
        let root = std::fs::read(ca.join("root.pem")).unwrap();
        std::fs::remove_file(ca.join("intermediate.key")).unwrap();
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_ERR);
        assert!(last_error().contains("incomplete"), "{}", last_error());
        assert_eq!(std::fs::read(ca.join("root.pem")).unwrap(), root);
    }

    #[test]
    fn ca_root_pem_returns_the_certificate_and_checks_the_buffer() {
        let f = Fixture::initialised();
        // before the CA exists
        let (rc, _) = call_buf(ztlp_ios_ca_root_pem, 8192);
        assert_eq!(rc, ZTLP_IOS_ERR);
        assert!(
            last_error().contains("ztlp_ios_ensure_ca"),
            "{}",
            last_error()
        );

        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK);
        let (rc, pem) = call_buf(ztlp_ios_ca_root_pem, 8192);
        assert!(rc > 0, "{}", last_error());
        assert_eq!(rc as usize, pem.len());
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        assert_eq!(
            pem,
            std::fs::read_to_string(f.ztlp().join("ca").join("root.pem")).unwrap()
        );
        // the root is the certificate only, never a key
        assert!(!pem.contains("PRIVATE KEY"));

        // exactly len bytes is one short (no room for the NUL) ...
        let (rc, _) = call_buf(ztlp_ios_ca_root_pem, pem.len());
        assert_eq!(rc, ZTLP_IOS_ERR_BUFFER_TOO_SMALL);
        let (rc, _) = call_buf(ztlp_ios_ca_root_pem, 0);
        assert_eq!(rc, ZTLP_IOS_ERR_BUFFER_TOO_SMALL);
        // ... len + 1 fits
        let (rc, again) = call_buf(ztlp_ios_ca_root_pem, pem.len() + 1);
        assert_eq!(rc as usize, pem.len());
        assert_eq!(again, pem);
    }

    // ── status ──────────────────────────────────────────────────────────

    #[test]
    fn status_json_has_the_contract_shape() {
        let f = Fixture::initialised();
        let st = status();
        let obj = st.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "ca_ready",
                "enrolled",
                "last_error",
                "node_name",
                "running",
                "tunnels",
                "vips",
                "zone"
            ]
        );
        assert!(st["running"].is_boolean());
        assert!(st["enrolled"].is_boolean());
        assert!(st["ca_ready"].is_boolean());
        assert!(st["node_name"].is_string());
        assert!(st["zone"].is_string());
        assert!(st["last_error"].is_string());
        assert!(st["vips"].is_u64());
        assert!(st["tunnels"].is_u64());
        assert_eq!(st["running"], false);
        assert_eq!(st["enrolled"], false);
        assert_eq!(st["node_name"], "");
        assert_eq!(st["last_error"], "");

        f.fake_enrollment();
        let st = status();
        assert_eq!(st["enrolled"], true);
        assert_eq!(st["node_name"], "phone.office.example.ztlp");
        assert_eq!(st["zone"], "office.example.ztlp");

        // too-small buffer
        let (rc, _) = call_buf(ztlp_ios_status_json, 8);
        assert_eq!(rc, ZTLP_IOS_ERR_BUFFER_TOO_SMALL);
    }

    #[test]
    fn last_error_is_per_call_and_empty_after_success() {
        let _f = Fixture::initialised();
        assert_eq!(last_error(), "");
        assert_eq!(
            ztlp_ios_agent_start(c("not-an-ip").as_ptr(), c("100.64.77.32/27").as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert!(last_error().contains("not-an-ip"), "{}", last_error());
        // a successful call clears it
        assert_eq!(ztlp_ios_agent_stop(), ZTLP_IOS_OK);
        assert_eq!(last_error(), "");
    }

    #[test]
    fn last_error_is_thread_local() {
        let _f = Fixture::initialised();
        assert_eq!(
            ztlp_ios_agent_start(c("not-an-ip").as_ptr(), c("100.64.77.32/27").as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        let other = std::thread::spawn(last_error).join().unwrap();
        assert_eq!(other, "");
        assert!(!last_error().is_empty());
    }

    // ── agent start: argument and state checks (no agent runs) ──────────

    #[test]
    fn agent_start_checks_its_arguments_and_enrollment() {
        let f = Fixture::initialised();
        let pool = c("100.64.77.32/27");
        // not an IPv4 address
        assert_eq!(
            ztlp_ios_agent_start(c("fd00::1").as_ptr(), pool.as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        // not a CIDR / host bits set
        assert_eq!(
            ztlp_ios_agent_start(c("100.64.77.1").as_ptr(), c("100.64.77.33").as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            ztlp_ios_agent_start(c("100.64.77.1").as_ptr(), c("100.64.77.33/27").as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        // resolver address inside the pool
        assert_eq!(
            ztlp_ios_agent_start(c("100.64.77.40").as_ptr(), pool.as_ptr()),
            ZTLP_IOS_ERR_INVALID_ARGUMENT
        );
        assert!(
            last_error().contains("inside the VIP pool"),
            "{}",
            last_error()
        );
        // valid addresses, but not enrolled
        assert_eq!(
            ztlp_ios_agent_start(c("100.64.77.1").as_ptr(), pool.as_ptr()),
            ZTLP_IOS_ERR_NOT_ENROLLED
        );
        assert_eq!(status()["last_error"], "this device is not enrolled");
        assert!(!f.ztlp().join("agent.toml").exists());
    }

    // ── pure helpers ────────────────────────────────────────────────────

    #[test]
    fn device_names_become_dns_labels() {
        assert_eq!(
            sanitize_device_name("Steve's iPhone 15"),
            "steves-iphone-15"
        );
        assert_eq!(
            sanitize_device_name("Steve\u{2019}s iPhone"),
            "steves-iphone"
        );
        assert_eq!(sanitize_device_name("  iPad_Pro (2)  "), "ipad-pro-2");
        assert_eq!(sanitize_device_name("already-fine-01"), "already-fine-01");
        assert_eq!(sanitize_device_name("a.b.c"), "a-b-c");
        assert_eq!(sanitize_device_name(""), "iphone");
        assert_eq!(sanitize_device_name("\u{1F4F1}"), "iphone");
        assert_eq!(sanitize_device_name("---"), "iphone");
        let long = sanitize_device_name(&"x".repeat(200));
        assert_eq!(long.len(), 63);
        let trimmed = sanitize_device_name(&format!("{}-{}", "x".repeat(62), "y"));
        assert!(!trimmed.ends_with('-') && trimmed.len() <= 63, "{trimmed}");
    }

    #[test]
    fn ios_settings_are_applied_on_top_of_the_enrollment_config() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let agent_toml = home.join("agent.toml");
        enroll::write_agent_config_file(
            &agent_toml,
            &home.join("old-location").join("identity.json"),
            "office.example.ztlp",
            "192.0.2.10:23096",
            &["192.0.2.20:23095".to_string()],
            Some("test-relay-secret"),
        )
        .unwrap();
        let before = std::fs::read_to_string(&agent_toml).unwrap();

        let out = apply_ios_settings(
            &before,
            home,
            "100.64.77.1".parse().unwrap(),
            &SitePlan::Pool("100.64.77.32/27".into()),
            ListenPorts::IOS,
        )
        .unwrap();
        let cfg: AgentConfig = toml::from_str(&out).expect("result must load as AgentConfig");

        // what the tunnel dictates
        assert_eq!(cfg.dns.listen, "100.64.77.1:53");
        assert!(cfg.dns.enabled);
        assert_eq!(cfg.dns.vip_range, "100.64.77.32/27");
        assert!(cfg.dns.tcp);
        assert_eq!(cfg.ipc.listen, "100.64.77.1:4433");
        assert!(cfg.tls.enabled);
        assert_eq!(cfg.tls.health_ip.as_deref(), Some("100.64.77.1"));
        assert_eq!(
            cfg.tunnel.profile,
            crate::agent::config::TunnelProfile::Mobile
        );
        assert!(cfg.tunnel.reuse_connections_enabled());
        assert_eq!(
            cfg.tunnel.transport_windows(),
            crate::quic_transport::TransportWindows::MOBILE
        );
        assert_eq!(
            cfg.identity_path(),
            home.join(".ztlp").join("identity.json")
        );
        // what enrollment wrote survives
        assert_eq!(cfg.ns.servers, vec!["192.0.2.10:23096".to_string()]);
        assert_eq!(cfg.tunnel.relays.0, vec!["192.0.2.20:23095".to_string()]);
        assert_eq!(
            cfg.tunnel.relay_secret.as_deref(),
            Some("test-relay-secret")
        );
        assert_eq!(cfg.dns.zones, vec!["office.example.ztlp".to_string()]);

        // applying again (next tunnel start, new addresses) only moves the
        // tunnel keys
        let again = apply_ios_settings(
            &out,
            home,
            "100.64.80.1".parse().unwrap(),
            &SitePlan::Pool("100.64.80.32/27".into()),
            ListenPorts::IOS,
        )
        .unwrap();
        let cfg2: AgentConfig = toml::from_str(&again).unwrap();
        assert_eq!(cfg2.dns.listen, "100.64.80.1:53");
        assert_eq!(cfg2.dns.vip_range, "100.64.80.32/27");
        assert_eq!(cfg2.tls.health_ip.as_deref(), Some("100.64.80.1"));
        assert_eq!(
            cfg2.tunnel.relay_secret.as_deref(),
            Some("test-relay-secret")
        );
        assert_eq!(cfg2.ns.servers, cfg.ns.servers);
    }

    #[test]
    fn ios_settings_work_from_an_empty_config_and_reject_a_broken_one() {
        let dir = tempfile::tempdir().unwrap();
        let out = apply_ios_settings(
            "",
            dir.path(),
            "100.64.77.1".parse().unwrap(),
            &SitePlan::Pool("100.64.77.32/27".into()),
            ListenPorts::IOS,
        )
        .unwrap();
        let cfg: AgentConfig = toml::from_str(&out).unwrap();
        assert_eq!(cfg.dns.listen, "100.64.77.1:53");
        assert!(cfg.tls.enabled);

        let err = apply_ios_settings(
            "[dns\nlisten = ",
            dir.path(),
            "100.64.77.1".parse().unwrap(),
            &SitePlan::Pool("100.64.77.32/27".into()),
            ListenPorts::IOS,
        )
        .unwrap_err();
        assert!(err.contains("does not parse"), "{err}");
    }

    #[test]
    fn tunnel_addresses_are_validated() {
        assert!(validate_tunnel_addrs("100.64.77.1", "100.64.77.32/27").is_ok());
        assert!(validate_tunnel_addrs(" 100.64.77.1 ", " 100.64.77.32/27 ").is_ok());
        for (ip, cidr) in [
            ("", "100.64.77.32/27"),
            ("100.64.77", "100.64.77.32/27"),
            ("100.64.77.1", ""),
            ("100.64.77.1", "100.64.77.32"),
            ("100.64.77.1", "100.64.77.32/40"),
            ("100.64.77.33", "100.64.77.32/27"),
            ("100.64.77.63", "100.64.77.32/27"),
        ] {
            let e = validate_tunnel_addrs(ip, cidr).unwrap_err();
            assert_eq!(e.code, ZTLP_IOS_ERR_INVALID_ARGUMENT, "{ip} {cidr}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_file_limit_is_raised_towards_the_target_and_never_lowered() {
        #[allow(unsafe_code)]
        fn limits() -> (u64, u64) {
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
            (lim.rlim_cur as u64, lim.rlim_max as u64)
        }
        let (before, hard) = limits();
        let got = raise_open_file_limit().expect("limit readable");
        let (after, hard_after) = limits();
        assert_eq!(got, after);
        assert_eq!(hard, hard_after, "the hard limit is never touched");
        assert!(after >= before, "never lowered");
        assert!(after >= WANTED_OPEN_FILES.min(hard));
        // idempotent
        assert_eq!(raise_open_file_limit(), Some(after));
    }

    // ── log file ────────────────────────────────────────────────────────

    #[test]
    fn log_file_is_capped_with_one_rotated_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("agent.log");
        let mut log = CappedLogFile::new(path.clone(), 1000);
        let line = [b'x'; 100];
        for _ in 0..95 {
            log.append(&line).unwrap();
        }
        let cur = std::fs::metadata(&path).unwrap().len();
        let old = std::fs::metadata(dir.path().join("sub").join("agent.log.1"))
            .unwrap()
            .len();
        assert!(cur <= 1000, "current file {cur} bytes");
        assert!(old <= 1000, "rotated file {old} bytes");
        // only the two files exist: old generations are replaced
        assert_eq!(
            std::fs::read_dir(dir.path().join("sub")).unwrap().count(),
            2
        );
    }

    #[test]
    fn log_file_appends_across_reopen_and_counts_existing_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        std::fs::write(&path, vec![b'a'; 900]).unwrap();
        let mut log = CappedLogFile::new(path.clone(), 1000);
        log.append(&[b'b'; 50]).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 950);
        // the next write would pass the cap: rotate first
        log.append(&[b'c'; 100]).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 100);
        assert_eq!(
            std::fs::metadata(dir.path().join("agent.log.1"))
                .unwrap()
                .len(),
            950
        );
    }

    #[test]
    fn log_writer_never_fails_the_caller() {
        // a path that cannot be created
        let mut w = LogWriter::new(PathBuf::from("/proc/ztlp-no-such-dir/agent.log"), 1000);
        assert_eq!(w.write(b"hello").unwrap(), 5);
    }

    // ── the agent itself, on loopback (no name server, no gateway) ──────

    fn free_port() -> u16 {
        // The resolver uses the port for UDP and TCP: another test holding
        // the same number for TCP would make the TCP bind fail (logged, not
        // fatal), and the TCP query below would be refused.
        loop {
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = udp.local_addr().unwrap().port();
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
        }
    }

    /// A DNS A query for `name`.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    #[test]
    fn agent_starts_serves_dns_and_stops_releasing_its_listeners() {
        let f = Fixture::initialised();
        f.fake_enrollment();
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK);
        let ports = ListenPorts {
            dns: free_port(),
            control: {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            },
            ..ListenPorts::IOS
        };

        let rc = ffi_call(|| do_agent_start("127.0.0.1", "127.77.0.32/27", ports));
        assert_eq!(rc, ZTLP_IOS_OK, "{}", last_error());
        // starting again while running is a no-op success
        assert_eq!(
            ffi_call(|| do_agent_start("127.0.0.1", "127.77.0.32/27", ports)),
            ZTLP_IOS_OK
        );

        let st = status();
        assert_eq!(st["running"], true, "{st}");
        assert_eq!(st["enrolled"], true);
        assert_eq!(st["ca_ready"], true);
        assert_eq!(st["vips"], 0);
        assert_eq!(st["tunnels"], 0);
        assert_eq!(st["last_error"], "");

        // the config on disk is what the agent runs with
        let cfg = AgentConfig::load_from_path(&f.ztlp().join("agent.toml")).unwrap();
        assert_eq!(cfg.dns.listen, format!("127.0.0.1:{}", ports.dns));
        assert_eq!(cfg.dns.vip_range, "127.77.0.32/27");
        assert_eq!(cfg.dns.single_address, None, "a pool is not single-address");
        assert!(cfg.tls.enabled);
        assert_eq!(
            cfg.tunnel.profile,
            crate::agent::config::TunnelProfile::Mobile
        );

        // the resolver answers the health name with the tunnel address
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock.send_to(&dns_query("ztlp-health.ztlp"), ("127.0.0.1", ports.dns))
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).expect("DNS answer");
        assert_eq!(&buf[..2], &[0x12, 0x34]);
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1], "A record = health_ip");

        // ... and over TCP on the same port
        {
            use std::io::Read;
            let mut t = std::net::TcpStream::connect(("127.0.0.1", ports.dns)).unwrap();
            t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let q = dns_query("ztlp-health.ztlp");
            t.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
            t.write_all(&q).unwrap();
            let mut len = [0u8; 2];
            t.read_exact(&mut len).unwrap();
            let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
            t.read_exact(&mut resp).unwrap();
            assert_eq!(&resp[resp.len() - 4..], &[127, 0, 0, 1]);
        }

        // the control endpoint is listening
        assert!(std::net::TcpStream::connect(("127.0.0.1", ports.control)).is_ok());

        assert_eq!(ztlp_ios_agent_stop(), ZTLP_IOS_OK);
        assert_eq!(status()["running"], false);
        // listeners are released: the same ports bind again at once
        assert!(std::net::UdpSocket::bind(("127.0.0.1", ports.dns)).is_ok());
        assert!(std::net::TcpListener::bind(("127.0.0.1", ports.dns)).is_ok());
        assert!(std::net::TcpListener::bind(("127.0.0.1", ports.control)).is_ok());
        // stopping twice is fine
        assert_eq!(ztlp_ios_agent_stop(), ZTLP_IOS_OK);

        // run_daemon installed the mobile profile process-wide; put the
        // desktop defaults back for the other tests in this process
        daemon::set_reuse_connections(false);
        daemon::set_dial_windows(crate::quic_transport::TransportWindows::DESKTOP);
    }

    // ── single-address mode (vip_cidr = a.b.c.d/32) ────────────────────

    #[test]
    fn a_slash_32_means_one_address_for_every_site_and_a_wider_prefix_a_pool() {
        assert_eq!(
            validate_tunnel_addrs("127.0.0.1", "127.0.0.1/32").unwrap(),
            (Ipv4Addr::LOCALHOST, SitePlan::Single(Ipv4Addr::LOCALHOST))
        );
        // the shared address need not be the resolver's
        assert_eq!(
            validate_tunnel_addrs("100.64.77.1", " 100.64.77.9/32 ")
                .unwrap()
                .1,
            SitePlan::Single("100.64.77.9".parse().unwrap())
        );
        assert_eq!(
            validate_tunnel_addrs("100.64.77.1", "100.64.77.32/27")
                .unwrap()
                .1,
            SitePlan::Pool("100.64.77.32/27".into())
        );
        for bad in ["/32", "localhost/32", "127.0.0/32", "127.0.0.1/32/32"] {
            let e = validate_tunnel_addrs("127.0.0.1", bad).unwrap_err();
            assert_eq!(e.code, ZTLP_IOS_ERR_INVALID_ARGUMENT, "{bad}");
        }
    }

    #[test]
    fn single_address_settings_are_written_for_a_slash_32_and_replaced_by_a_pool() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let agent_toml = home.join("agent.toml");
        enroll::write_agent_config_file(
            &agent_toml,
            &home.join("identity.json"),
            "office.example.ztlp",
            "192.0.2.10:23096",
            &["192.0.2.20:23095".to_string()],
            Some("test-relay-secret"),
        )
        .unwrap();
        let before = std::fs::read_to_string(&agent_toml).unwrap();

        let single = apply_ios_settings(
            &before,
            home,
            Ipv4Addr::LOCALHOST,
            &SitePlan::Single(Ipv4Addr::LOCALHOST),
            ListenPorts::IOS,
        )
        .unwrap();
        let cfg: AgentConfig = toml::from_str(&single).unwrap();
        assert_eq!(cfg.dns.single_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            cfg.dns.single_address_ip().unwrap(),
            Some(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(cfg.dns.single_address_https_port, 443);
        assert_eq!(cfg.dns.single_address_http_port, 80);
        assert!(
            !single.contains("vip_range") && !single.contains("_port"),
            "no pool and no port keys in single-address mode:\n{single}"
        );
        // resolver, control and health on dns_ip, as with a pool
        assert_eq!(cfg.dns.listen, "127.0.0.1:53");
        assert!(cfg.dns.enabled && cfg.dns.tcp);
        assert_eq!(cfg.ipc.listen, "127.0.0.1:4433");
        assert!(cfg.tls.enabled);
        assert_eq!(cfg.tls.health_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            cfg.tunnel.profile,
            crate::agent::config::TunnelProfile::Mobile
        );
        assert!(cfg.tunnel.reuse_connections_enabled());
        // what enrollment wrote survives
        assert_eq!(cfg.ns.servers, vec!["192.0.2.10:23096".to_string()]);
        assert_eq!(
            cfg.tunnel.relay_secret.as_deref(),
            Some("test-relay-secret")
        );

        // the next start gets a pool: nothing of single-address mode stays
        let pool = apply_ios_settings(
            &single,
            home,
            "100.64.77.1".parse().unwrap(),
            &SitePlan::Pool("100.64.77.32/27".into()),
            ListenPorts::IOS,
        )
        .unwrap();
        let cfg: AgentConfig = toml::from_str(&pool).unwrap();
        assert_eq!(cfg.dns.single_address, None);
        assert!(!pool.contains("single_address"), "{pool}");
        assert_eq!(cfg.dns.vip_range, "100.64.77.32/27");

        // ... and back, with non-default ports (tests only)
        let again = apply_ios_settings(
            &pool,
            home,
            Ipv4Addr::LOCALHOST,
            &SitePlan::Single(Ipv4Addr::LOCALHOST),
            ListenPorts {
                https: 18443,
                http: 18080,
                ..ListenPorts::IOS
            },
        )
        .unwrap();
        let cfg: AgentConfig = toml::from_str(&again).unwrap();
        assert_eq!(cfg.dns.single_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(cfg.dns.single_address_https_port, 18443);
        assert_eq!(cfg.dns.single_address_http_port, 18080);
        assert_eq!(cfg.dns.vip_range, "127.100.0.0/16", "the unused default");
    }

    fn free_tcp_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    /// Can the port be bound again? Retried for a moment: the kernel may
    /// finish closing a socket slightly after `close` returns when another
    /// thread (the runtime's I/O driver) was polling it (seen about once in
    /// 300 runs as a few microseconds of "address in use").
    fn released(bind: impl Fn() -> bool) -> bool {
        let until = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if bind() {
                return true;
            }
            if std::time::Instant::now() > until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Send `request` to 127.0.0.1:`port` and return what comes back
    /// before the agent closes the connection.
    fn http_exchange(port: u16, request: &[u8]) -> String {
        use std::io::Read;
        let mut t = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        t.write_all(request).unwrap();
        let mut out = Vec::new();
        let _ = t.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn a_slash_32_start_runs_the_name_routed_listeners_and_no_vip_proxy() {
        let f = Fixture::initialised();
        f.fake_enrollment();
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK);
        let ports = ListenPorts {
            dns: free_port(),
            control: free_tcp_port(),
            https: free_tcp_port(),
            http: free_tcp_port(),
        };

        let rc = ffi_call(|| do_agent_start("127.0.0.1", "127.0.0.1/32", ports));
        assert_eq!(rc, ZTLP_IOS_OK, "{}", last_error());

        // the config on disk is single-address mode on that address
        let cfg = AgentConfig::load_from_path(&f.ztlp().join("agent.toml")).unwrap();
        assert_eq!(cfg.dns.single_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(cfg.dns.single_address_https_port, ports.https);
        assert_eq!(cfg.dns.single_address_http_port, ports.http);
        assert_eq!(cfg.dns.listen, format!("127.0.0.1:{}", ports.dns));
        assert_eq!(cfg.tls.health_ip.as_deref(), Some("127.0.0.1"));
        assert!(cfg.tls.enabled);

        let st = status();
        assert_eq!(st["running"], true, "{st}");
        assert_eq!(st["vips"], 0);

        // the health name still resolves (to dns_ip)
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock.send_to(&dns_query("ztlp-health.ztlp"), ("127.0.0.1", ports.dns))
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).expect("DNS answer");
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1]);

        // port 80: no Host, and a Host that is not a ZTLP name, get a short
        // plain 4xx; nothing is dialed
        let missing = http_exchange(ports.http, b"GET / HTTP/1.0\r\n\r\n");
        assert!(missing.starts_with("HTTP/1.1 400 "), "{missing:?}");
        let foreign = http_exchange(
            ports.http,
            b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        );
        assert!(foreign.starts_with("HTTP/1.1 421 "), "{foreign:?}");
        // port 443: bytes that are not a TLS ClientHello are closed
        let not_tls = http_exchange(
            ports.https,
            b"GET / HTTP/1.1\r\nHost: a.example.ztlp\r\n\r\n",
        );
        assert_eq!(not_tls, "");

        assert_eq!(ztlp_ios_agent_stop(), ZTLP_IOS_OK);
        // both listeners are released
        assert!(released(|| std::net::TcpListener::bind((
            "127.0.0.1",
            ports.https
        ))
        .is_ok()));
        assert!(released(|| std::net::TcpListener::bind((
            "127.0.0.1",
            ports.http
        ))
        .is_ok()));

        daemon::set_reuse_connections(false);
        daemon::set_dial_windows(crate::quic_transport::TransportWindows::DESKTOP);
    }

    #[test]
    fn a_slash_32_start_fails_when_the_https_port_is_taken() {
        let f = Fixture::initialised();
        f.fake_enrollment();
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK);
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ports = ListenPorts {
            dns: free_port(),
            control: free_tcp_port(),
            https: blocker.local_addr().unwrap().port(),
            http: free_tcp_port(),
        };
        let rc = ffi_call(|| do_agent_start("127.0.0.1", "127.0.0.1/32", ports));
        assert_eq!(rc, ZTLP_IOS_ERR);
        assert!(
            last_error().contains("cannot listen on") && last_error().contains("HTTPS"),
            "{}",
            last_error()
        );
        assert_eq!(status()["running"], false);
        // nothing else is left listening
        assert!(released(|| std::net::UdpSocket::bind((
            "127.0.0.1",
            ports.dns
        ))
        .is_ok()));
        assert!(released(|| std::net::TcpListener::bind((
            "127.0.0.1",
            ports.http
        ))
        .is_ok()));

        daemon::set_reuse_connections(false);
        daemon::set_dial_windows(crate::quic_transport::TransportWindows::DESKTOP);
    }

    #[test]
    fn network_changed_is_a_no_op_until_the_agent_runs_and_a_burst_is_one_event() {
        // before init, and initialised but stopped: returns 0, does nothing
        let f = Fixture::uninitialised();
        let runs = daemon::network_change_runs();
        assert_eq!(ztlp_ios_network_changed(), ZTLP_IOS_OK);
        let home = CString::new(f.home().to_str().unwrap()).unwrap();
        assert_eq!(ztlp_ios_init(home.as_ptr()), ZTLP_IOS_OK);
        for _ in 0..10 {
            assert_eq!(ztlp_ios_network_changed(), ZTLP_IOS_OK);
        }
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(daemon::network_change_runs(), runs);

        f.fake_enrollment();
        assert_eq!(ztlp_ios_ensure_ca(), ZTLP_IOS_OK);
        let ports = ListenPorts {
            dns: free_port(),
            control: free_tcp_port(),
            https: free_tcp_port(),
            http: free_tcp_port(),
        };
        let rc = ffi_call(|| do_agent_start("127.0.0.1", "127.0.0.1/32", ports));
        assert_eq!(rc, ZTLP_IOS_OK, "{}", last_error());

        // running: a burst from several threads is acted on once at once
        // and, for everything else in the burst, once more
        let started = std::time::Instant::now();
        let threads: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..250 {
                        assert_eq!(ztlp_ios_network_changed(), ZTLP_IOS_OK);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let burst = started.elapsed();
        assert!(
            burst < Duration::from_millis(200),
            "1000 calls took {burst:?}"
        );
        std::thread::sleep(Duration::from_millis(700));
        let acted = daemon::network_change_runs() - runs;
        assert!((1..=2).contains(&acted), "{acted} runs for 1000 calls");
        // the call does not disturb the error text of the calling thread
        assert_eq!(last_error(), "");

        // listeners, resolver and status are as they were
        let st = status();
        assert_eq!(st["running"], true, "{st}");
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock.send_to(&dns_query("ztlp-health.ztlp"), ("127.0.0.1", ports.dns))
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).expect("DNS answer");
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1]);
        assert!(std::net::TcpStream::connect(("127.0.0.1", ports.https)).is_ok());

        // a later, separate change acts again
        let before = daemon::network_change_runs();
        assert_eq!(ztlp_ios_network_changed(), ZTLP_IOS_OK);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(daemon::network_change_runs(), before + 1);

        // stopped again: back to a no-op
        assert_eq!(ztlp_ios_agent_stop(), ZTLP_IOS_OK);
        let before = daemon::network_change_runs();
        assert_eq!(ztlp_ios_network_changed(), ZTLP_IOS_OK);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(daemon::network_change_runs(), before);

        daemon::set_reuse_connections(false);
        daemon::set_dial_windows(crate::quic_transport::TransportWindows::DESKTOP);
    }

    #[test]
    fn agent_start_fails_when_the_resolver_port_is_taken() {
        let f = Fixture::initialised();
        f.fake_enrollment();
        // hold the DNS port so the daemon falls back to another one
        let blocker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let ports = ListenPorts {
            dns: blocker.local_addr().unwrap().port(),
            control: {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            },
            ..ListenPorts::IOS
        };
        let rc = ffi_call(|| do_agent_start("127.0.0.1", "127.77.0.32/27", ports));
        assert_eq!(rc, ZTLP_IOS_ERR);
        assert!(last_error().contains("could not bind"), "{}", last_error());
        let st = status();
        assert_eq!(st["running"], false);
        assert!(st["last_error"]
            .as_str()
            .unwrap()
            .contains("could not bind"));
        // nothing is left listening on the control port
        assert!(std::net::TcpListener::bind(("127.0.0.1", ports.control)).is_ok());

        daemon::set_reuse_connections(false);
        daemon::set_dial_windows(crate::quic_transport::TransportWindows::DESKTOP);
    }
}
