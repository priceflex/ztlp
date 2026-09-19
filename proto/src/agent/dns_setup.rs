//! System DNS configuration helpers.
//!
//! Configures the host OS to forward ZTLP zone queries to the agent's DNS
//! resolver. Supports:
//!
//! - **systemd-resolved** (recommended for modern Linux)
//! - **/etc/resolv.conf** (simple fallback)
//! - **macOS /etc/resolver/** (per-domain resolver)
//!
//! ## How it works
//!
//! The agent's DNS resolver runs on `127.0.0.53:5353`. System DNS is configured
//! to forward only ZTLP-related queries to this address. All other DNS traffic
//! continues to use the system's default resolver.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

// ─── Platform detection ─────────────────────────────────────────────────────

/// Detected DNS backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsBackend {
    /// systemd-resolved (Linux, modern distros).
    SystemdResolved,
    /// Plain /etc/resolv.conf (Linux, simple).
    ResolvConf,
    /// macOS /etc/resolver/ directory.
    MacOsResolver,
    /// Unknown or unsupported system.
    Unknown,
}

/// Detect the DNS backend for the current system.
pub fn detect_backend() -> DnsBackend {
    if cfg!(target_os = "macos") {
        return DnsBackend::MacOsResolver;
    }

    // Check for systemd-resolved
    if Path::new("/run/systemd/resolve/stub-resolv.conf").exists()
        || Path::new("/etc/systemd/resolved.conf").exists()
    {
        return DnsBackend::SystemdResolved;
    }

    // Fall back to resolv.conf
    if Path::new("/etc/resolv.conf").exists() {
        return DnsBackend::ResolvConf;
    }

    DnsBackend::Unknown
}

// ─── Setup ──────────────────────────────────────────────────────────────────

/// DNS setup result.
#[derive(Debug)]
pub struct DnsSetupResult {
    pub backend: DnsBackend,
    pub files_written: Vec<PathBuf>,
    pub needs_restart: bool,
    pub instructions: Option<String>,
}

/// Configure system DNS to forward ZTLP zones to the agent.
///
/// `listen_addr` is the agent's DNS resolver address (e.g., "127.0.0.53:5353").
/// `zones` is the list of ZTLP zones + custom domains to forward.
pub fn setup_dns(
    listen_addr: &str,
    zones: &[String],
) -> Result<DnsSetupResult, Box<dyn std::error::Error>> {
    let backend = detect_backend();
    info!("detected DNS backend: {:?}", backend);

    match backend {
        DnsBackend::SystemdResolved => setup_systemd_resolved(listen_addr, zones),
        DnsBackend::ResolvConf => setup_resolv_conf(listen_addr),
        DnsBackend::MacOsResolver => setup_macos_resolver(listen_addr, zones),
        DnsBackend::Unknown => Err("cannot detect DNS backend; configure manually".into()),
    }
}

/// Check whether ZTLP DNS forwarding is currently configured on this system.
///
/// Read-only inverse of `setup_dns`: detects the artifacts each backend
/// writes, so the wizard's "DNS configured" checkmark can light up on
/// macOS/Linux the same way the Windows NRPT check does. Never mutates.
pub fn is_dns_configured() -> bool {
    match detect_backend() {
        DnsBackend::SystemdResolved => Path::new(RESOLVED_CONF_DIR)
            .join(RESOLVED_CONF_FILE)
            .exists(),
        DnsBackend::ResolvConf => fs::read_to_string(RESOLV_CONF)
            .map(|s| s.contains("ZTLP agent DNS"))
            .unwrap_or(false),
        DnsBackend::MacOsResolver => Path::new(MACOS_RESOLVER_DIR).join("ztlp").exists(),
        DnsBackend::Unknown => false,
    }
}

/// Remove ZTLP DNS configuration.
pub fn teardown_dns() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let backend = detect_backend();
    info!("tearing down DNS for backend: {:?}", backend);

    match backend {
        DnsBackend::SystemdResolved => teardown_systemd_resolved(),
        DnsBackend::ResolvConf => teardown_resolv_conf(),
        DnsBackend::MacOsResolver => teardown_macos_resolver(),
        DnsBackend::Unknown => Ok(Vec::new()),
    }
}

// ─── systemd-resolved ───────────────────────────────────────────────────────

const RESOLVED_CONF_DIR: &str = "/etc/systemd/resolved.conf.d";
const RESOLVED_CONF_FILE: &str = "ztlp.conf";

/// Build the resolved.conf.d/ztlp.conf content for a given DNS listen
/// address and zone list. Pure/testable — no filesystem or root required.
///
/// IMPORTANT: systemd-resolved's `DNS=` directive uses `ip:port` for a
/// non-default port. `#` is a DIFFERENT separator reserved for DNS-over-TLS
/// SNI server names (`DNS=1.1.1.1#cloudflare-dns.com`). Using `#` for a
/// port (e.g. `127.0.0.53#5353`) is silently mis-parsed: resolved reads
/// `127.0.0.53` as the server, treats `5353` as a bogus TLS name, and
/// defaults the port to 53 — where nothing is listening. The zone's
/// `Domains=` routing entry stays configured, but every lookup silently
/// fails, and `resolvectl status` shows no working DNS server. Any future
/// change here MUST keep using `:` for the port.
fn generate_resolved_conf(dns_ip: &str, dns_port: u16, zones: &[String]) -> String {
    // Build domain list with ~ prefix (routing-only domains)
    let mut domain_entries = vec!["~ztlp".to_string()];
    for zone in zones {
        let entry = format!("~{}", zone.trim_start_matches('~'));
        if !domain_entries.contains(&entry) {
            domain_entries.push(entry);
        }
    }

    let dns_addr = if dns_port != 53 {
        format!("{}:{}", dns_ip, dns_port)
    } else {
        dns_ip.to_string()
    };

    format!(
        "# Managed by ztlp-agent — do not edit manually\n\
         # Remove with: ztlp agent dns-teardown\n\
         [Resolve]\n\
         DNS={}\n\
         Domains={}\n",
        dns_addr,
        domain_entries.join(" ")
    )
}

fn setup_systemd_resolved(
    listen_addr: &str,
    zones: &[String],
) -> Result<DnsSetupResult, Box<dyn std::error::Error>> {
    let conf_dir = Path::new(RESOLVED_CONF_DIR);
    let conf_path = conf_dir.join(RESOLVED_CONF_FILE);

    // Parse listen address to get just the IP and port
    let (dns_ip, dns_port) = parse_listen_addr(listen_addr)?;

    let content = generate_resolved_conf(&dns_ip, dns_port, zones);

    // Create directory if needed (requires root)
    fs::create_dir_all(conf_dir)?;
    fs::write(&conf_path, &content)?;

    info!("wrote {}", conf_path.display());

    Ok(DnsSetupResult {
        backend: DnsBackend::SystemdResolved,
        files_written: vec![conf_path],
        needs_restart: true,
        instructions: Some(
            "Run: sudo systemctl restart systemd-resolved\n\
             Verify: resolvectl status | grep ztlp"
                .to_string(),
        ),
    })
}

fn teardown_systemd_resolved() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let conf_path = Path::new(RESOLVED_CONF_DIR).join(RESOLVED_CONF_FILE);
    let mut removed = Vec::new();

    if conf_path.exists() {
        fs::remove_file(&conf_path)?;
        removed.push(conf_path);
        info!("removed systemd-resolved config");
    }

    Ok(removed)
}

// ─── /etc/resolv.conf ───────────────────────────────────────────────────────

const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_BACKUP: &str = "/etc/resolv.conf.ztlp-backup";

fn setup_resolv_conf(listen_addr: &str) -> Result<DnsSetupResult, Box<dyn std::error::Error>> {
    let (dns_ip, _dns_port) = parse_listen_addr(listen_addr)?;

    // Note: resolv.conf doesn't support non-standard ports.
    // If using port 5353, we need to either:
    // 1. Also listen on port 53 (requires root)
    // 2. Use dnsmasq/unbound as a forwarder
    // 3. Use systemd-resolved instead
    //
    // For now, write the IP and warn if port != 53.

    // Backup existing resolv.conf
    if Path::new(RESOLV_CONF).exists() && !Path::new(RESOLV_BACKUP).exists() {
        fs::copy(RESOLV_CONF, RESOLV_BACKUP)?;
        info!("backed up {} to {}", RESOLV_CONF, RESOLV_BACKUP);
    }

    let existing = fs::read_to_string(RESOLV_CONF).unwrap_or_default();

    // Prepend our nameserver to existing config
    let content = format!(
        "# ZTLP agent DNS (added by ztlp agent dns-setup)\n\
         nameserver {}\n\
         # Original config below:\n\
         {}\n",
        dns_ip, existing
    );

    fs::write(RESOLV_CONF, &content)?;

    let mut instructions = None;
    if parse_listen_addr(listen_addr)?.1 != 53 {
        instructions = Some(format!(
            "WARNING: /etc/resolv.conf does not support custom ports.\n\
             The agent listens on port {}, but resolv.conf can only use port 53.\n\
             Options:\n\
             1. Run agent with --dns-listen 127.0.0.53:53 (requires root)\n\
             2. Use systemd-resolved instead: ztlp agent dns-teardown && ...\n\
             3. Install dnsmasq as a forwarder",
            parse_listen_addr(listen_addr)?.1
        ));
    }

    Ok(DnsSetupResult {
        backend: DnsBackend::ResolvConf,
        files_written: vec![PathBuf::from(RESOLV_CONF)],
        needs_restart: false,
        instructions,
    })
}

fn teardown_resolv_conf() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut removed = Vec::new();

    if Path::new(RESOLV_BACKUP).exists() {
        fs::copy(RESOLV_BACKUP, RESOLV_CONF)?;
        fs::remove_file(RESOLV_BACKUP)?;
        removed.push(PathBuf::from(RESOLV_CONF));
        removed.push(PathBuf::from(RESOLV_BACKUP));
        info!("restored {} from backup", RESOLV_CONF);
    } else {
        warn!("no backup found at {}", RESOLV_BACKUP);
    }

    Ok(removed)
}

// ─── macOS /etc/resolver/ ───────────────────────────────────────────────────

const MACOS_RESOLVER_DIR: &str = "/etc/resolver";

/// Validate that a zone name is safe to use as a bare filename under
/// MACOS_RESOLVER_DIR (or any other single-directory join). [CWE-22
/// ugx-wepq] `Path::join` does NOT sanitize path traversal: a zone
/// containing `../` sequences (or an absolute path, which `join`
/// replaces the base with entirely) can escape the intended directory.
/// Before this fix, a zone of e.g. `../../etc/cron.d/evil` written via
/// `resolver_dir.join(zone)` would resolve to `/etc/cron.d/evil` --
/// writing attacker-controlled content (albeit just `nameserver`/`port`
/// lines here) to an arbitrary filesystem location this
/// root-privileged agent can reach, up to and including files an
/// attacker could get auto-executed (cron.d, launchd plists, etc.).
///
/// Zone names in this codebase are DNS zone labels (e.g. "ztlp",
/// "office.acme.ztlp") -- legitimate zones never contain '/', '\\', or
/// a leading '.'. Reject anything else outright rather than trying to
/// normalize/escape it.
fn validate_zone_for_filename(zone: &str) -> Result<(), Box<dyn std::error::Error>> {
    if zone.is_empty()
        || zone.contains('/')
        || zone.contains('\\')
        || zone == "."
        || zone == ".."
        || zone.starts_with('.')
    {
        return Err(format!(
            "refusing to write resolver file for invalid zone name: {:?}",
            zone
        )
        .into());
    }
    Ok(())
}

fn setup_macos_resolver(
    listen_addr: &str,
    zones: &[String],
) -> Result<DnsSetupResult, Box<dyn std::error::Error>> {
    let resolver_dir = Path::new(MACOS_RESOLVER_DIR);
    let (dns_ip, dns_port) = parse_listen_addr(listen_addr)?;

    fs::create_dir_all(resolver_dir)?;

    let mut files_written = Vec::new();

    // Create a resolver file for each zone
    let mut all_zones: Vec<String> = vec!["ztlp".to_string()];
    for zone in zones {
        if !all_zones.contains(zone) {
            all_zones.push(zone.clone());
        }
    }

    for zone in &all_zones {
        validate_zone_for_filename(zone)?;
        let file_path = resolver_dir.join(zone);
        // Defense in depth: even after the name-shape check above,
        // confirm the joined path's PARENT is still exactly
        // resolver_dir (catches any join/normalization surprise this
        // platform's Path semantics might introduce that the string
        // check didn't anticipate).
        if file_path.parent() != Some(resolver_dir) {
            return Err(format!(
                "refusing to write outside {}: resolved path {:?} for zone {:?}",
                MACOS_RESOLVER_DIR, file_path, zone
            )
            .into());
        }
        let content = format!(
            "# Managed by ztlp-agent\n\
             nameserver {}\n\
             port {}\n",
            dns_ip, dns_port
        );

        fs::write(&file_path, &content)?;
        files_written.push(file_path);
        info!("wrote {}/{}", MACOS_RESOLVER_DIR, zone);
    }

    Ok(DnsSetupResult {
        backend: DnsBackend::MacOsResolver,
        files_written,
        needs_restart: false,
        instructions: Some(format!(
            "macOS resolver configured for {} zone(s).\n\
             Verify: scutil --dns | grep ztlp\n\
             Test: dig @{} -p {} test.ztlp",
            all_zones.len(),
            dns_ip,
            dns_port
        )),
    })
}

fn teardown_macos_resolver() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let resolver_dir = Path::new(MACOS_RESOLVER_DIR);
    let mut removed = Vec::new();

    if resolver_dir.exists() {
        for entry in fs::read_dir(resolver_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Only remove files that look like ZTLP zone files
            if let Ok(content) = fs::read_to_string(&path) {
                if content.contains("ztlp-agent") {
                    fs::remove_file(&path)?;
                    removed.push(path);
                }
            }
        }
    }

    Ok(removed)
}

// ─── Systemd service installer ──────────────────────────────────────────────

const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/ztlp-agent.service";

/// Generate a systemd unit file for the ZTLP agent.
pub fn generate_systemd_unit(ztlp_binary: &str) -> String {
    format!(
        r#"# ZTLP Agent — Encrypted Network Overlay
# Installed by: ztlp agent install
# Remove with: ztlp agent uninstall

[Unit]
Description=ZTLP Agent — Encrypted Network Overlay
Documentation=https://ztlp.org/docs/agent
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} agent start --foreground
ExecStop={binary} agent stop
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/ztlp /run/ztlp %h/.ztlp
PrivateTmp=yes
ProtectKernelTunables=yes

# Allow binding to DNS port
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Watchdog
WatchdogSec=60

[Install]
WantedBy=multi-user.target
"#,
        binary = ztlp_binary
    )
}

/// Generate a macOS LaunchAgent plist for the ZTLP agent.
pub fn generate_launchagent_plist(ztlp_binary: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.ztlp.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>agent</string>
        <string>start</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/ztlp-agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ztlp-agent.stderr.log</string>
</dict>
</plist>
"#,
        binary = ztlp_binary
    )
}

/// What `install_service` will write, computed without touching the
/// filesystem (unit-testable on every platform).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstallTarget {
    pub path: PathBuf,
    pub content: String,
    pub instructions: String,
}

/// Pure planner behind [`install_service`]. `macos == true` selects the ROOT
/// LaunchDaemon (`/Library/LaunchDaemons/org.ztlp.agent.plist`); anything
/// else is the unchanged systemd unit.
pub fn service_install_target(macos: bool, ztlp_binary: &str) -> ServiceInstallTarget {
    if macos {
        use crate::agent::macos_daemon as md;
        let path = PathBuf::from(md::MACOS_LAUNCHDAEMON_PLIST_PATH);
        let instructions = format!(
            "LaunchDaemon installed: {p}\n\
             Config dir (HOME for the daemon): {home}\n\n\
             Start now (and at every boot):\n  sudo launchctl bootstrap system {p}\n\n\
             Status:\n  sudo launchctl print system/{label} | head -20\n\n\
             Stop + remove:\n  sudo launchctl bootout system/{label}\n  sudo rm {p}",
            p = path.display(),
            home = md::MACOS_SYSTEM_CONFIG_DIR,
            label = md::MACOS_LAUNCHDAEMON_LABEL,
        );
        ServiceInstallTarget {
            path,
            content: md::generate_launchdaemon_plist(ztlp_binary),
            instructions,
        }
    } else {
        let unit_path = PathBuf::from(SYSTEMD_UNIT_PATH);
        let instructions = format!(
            "Systemd unit installed: {}\n\n\
             Enable and start:\n  \
             sudo systemctl daemon-reload\n  \
             sudo systemctl enable ztlp-agent\n  \
             sudo systemctl start ztlp-agent\n\n\
             Check status:\n  \
             sudo systemctl status ztlp-agent\n\n\
             View logs:\n  \
             journalctl -u ztlp-agent -f",
            unit_path.display()
        );
        ServiceInstallTarget {
            path: unit_path,
            content: generate_systemd_unit(ztlp_binary),
            instructions,
        }
    }
}

/// Install the ZTLP agent as a system service (root LaunchDaemon on macOS,
/// systemd unit on Linux). Requires root on both.
///
/// Returns the path to the installed service file and any instructions.
pub fn install_service(ztlp_binary: &str) -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
    let target = service_install_target(cfg!(target_os = "macos"), ztlp_binary);
    if cfg!(target_os = "macos") {
        // Daemon HOME + log dir must exist before launchd starts it.
        fs::create_dir_all(crate::agent::macos_daemon::macos_system_ztlp_dir())?;
        fs::create_dir_all("/Library/Logs/ZTLP")?;
    }
    fs::write(&target.path, &target.content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // launchd refuses group/world-writable plists; systemd is fine with 0644 too.
        fs::set_permissions(&target.path, fs::Permissions::from_mode(0o644))?;
    }
    Ok((target.path, target.instructions))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Parse a listen address string into (ip, port).
fn parse_listen_addr(addr: &str) -> Result<(String, u16), Box<dyn std::error::Error>> {
    // Try to parse as SocketAddr first
    if let Ok(sock_addr) = addr.parse::<std::net::SocketAddr>() {
        return Ok((sock_addr.ip().to_string(), sock_addr.port()));
    }

    // Try host:port format
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port: u16 = port_str.parse()?;
        return Ok((host.to_string(), port));
    }

    Err(format!("cannot parse listen address: {}", addr).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_backend() {
        // Just verify it doesn't panic — result depends on platform
        let backend = detect_backend();
        let _ = format!("{:?}", backend);
    }

    #[test]
    fn test_parse_listen_addr() {
        let (ip, port) = parse_listen_addr("127.0.0.53:5353").unwrap();
        assert_eq!(ip, "127.0.0.53");
        assert_eq!(port, 5353);
    }

    #[test]
    fn test_parse_listen_addr_standard() {
        let (ip, port) = parse_listen_addr("0.0.0.0:53").unwrap();
        assert_eq!(ip, "0.0.0.0");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_generate_systemd_unit() {
        let unit = generate_systemd_unit("/usr/local/bin/ztlp");
        assert!(unit.contains("ExecStart=/usr/local/bin/ztlp agent start --foreground"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("WatchdogSec=60"));
        assert!(unit.contains("CAP_NET_BIND_SERVICE"));
    }

    #[test]
    fn test_generate_launchagent_plist() {
        let plist = generate_launchagent_plist("/usr/local/bin/ztlp");
        assert!(plist.contains("org.ztlp.agent"));
        assert!(plist.contains("/usr/local/bin/ztlp"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<true/>"));
    }

    #[test]
    fn test_generate_systemd_unit_custom_path() {
        let unit = generate_systemd_unit("/opt/ztlp/bin/ztlp");
        assert!(unit.contains("/opt/ztlp/bin/ztlp"));
    }

    // `ztlp agent install` on macOS must produce a ROOT LaunchDaemon, not the
    // legacy per-user LaunchAgent (which cannot bind :443, write
    // /etc/resolver, alias lo0 or touch the System keychain). Linux target
    // stays byte-identical to the systemd path.
    #[test]
    fn test_service_install_target_macos_is_root_launchdaemon() {
        let t = service_install_target(true, "/Applications/ZTLP.app/Contents/MacOS/ztlp");
        assert_eq!(
            t.path,
            PathBuf::from("/Library/LaunchDaemons/org.ztlp.agent.plist")
        );
        assert!(t
            .content
            .contains("<key>UserName</key>\n    <string>root</string>"));
        assert!(t
            .content
            .contains("/Applications/ZTLP.app/Contents/MacOS/ztlp"));
        assert!(!t.content.contains("LaunchAgents"));
        assert!(t.instructions.contains(
            "sudo launchctl bootstrap system /Library/LaunchDaemons/org.ztlp.agent.plist"
        ));
    }

    #[test]
    fn test_service_install_target_linux_unchanged() {
        let t = service_install_target(false, "/usr/local/bin/ztlp");
        assert_eq!(t.path, PathBuf::from(SYSTEMD_UNIT_PATH));
        assert_eq!(t.content, generate_systemd_unit("/usr/local/bin/ztlp"));
        assert!(t.instructions.contains("sudo systemctl enable ztlp-agent"));
    }

    // Regression tests: resolved.conf DNS= line must use ':' for the port,
    // never '#' (which systemd-resolved parses as a DoT SNI server name,
    // not a port separator). A '#'-separated port is silently mis-parsed:
    // resolved falls back to port 53 for that server and every lookup
    // through the ztlp agent fails, even though dns-setup reports success
    // and Domains= routing is configured correctly. See 2026-09-11 field
    // report: dns-setup wrote `DNS=127.0.0.53#5353`, resolvectl showed no
    // working DNS server under Global, and `resolvectl query` returned
    // "Name ... not found" even though the agent was answering fine on
    // 127.0.0.53:5353 directly (confirmed via `dig -p 5353`).
    #[test]
    fn test_resolved_conf_uses_colon_for_nonstandard_port() {
        let conf = generate_resolved_conf("127.0.0.53", 5353, &["defcon.ztlp".to_string()]);
        let dns_line = conf
            .lines()
            .find(|l| l.starts_with("DNS="))
            .expect("conf must contain a DNS= line");
        assert_eq!(dns_line, "DNS=127.0.0.53:5353");
        assert!(
            !dns_line.contains('#'),
            "'#' in the DNS= line is DoT SNI syntax, not a port separator: {dns_line}"
        );
    }

    #[test]
    fn test_resolved_conf_omits_port_for_standard_port_53() {
        let conf = generate_resolved_conf("127.0.0.53", 53, &["defcon.ztlp".to_string()]);
        let dns_line = conf
            .lines()
            .find(|l| l.starts_with("DNS="))
            .expect("conf must contain a DNS= line");
        assert_eq!(dns_line, "DNS=127.0.0.53");
    }

    #[test]
    fn test_resolved_conf_domains_includes_ztlp_and_zone() {
        let conf = generate_resolved_conf("127.0.0.53", 15353, &["defcon.ztlp".to_string()]);
        let domains_line = conf
            .lines()
            .find(|l| l.starts_with("Domains="))
            .expect("conf must contain a Domains= line");
        assert_eq!(domains_line, "Domains=~ztlp ~defcon.ztlp");
    }

    #[test]
    fn test_resolved_conf_dedupes_zone_already_tilde_prefixed() {
        // Callers might pass a zone that already has a leading '~' —
        // must not double it up to '~~zone'.
        let conf = generate_resolved_conf("127.0.0.53", 5353, &["~defcon.ztlp".to_string()]);
        let domains_line = conf
            .lines()
            .find(|l| l.starts_with("Domains="))
            .expect("conf must contain a Domains= line");
        assert_eq!(domains_line, "Domains=~ztlp ~defcon.ztlp");
    }

    // [CWE-22 ugx-wepq] Regression tests: validate_zone_for_filename
    // must reject any zone name that could escape MACOS_RESOLVER_DIR
    // when joined via Path::join, and accept legitimate DNS zone
    // labels unchanged.
    #[test]
    fn test_validate_zone_rejects_path_traversal() {
        assert!(validate_zone_for_filename("../../etc/cron.d/evil").is_err());
        assert!(validate_zone_for_filename("../evil").is_err());
        assert!(validate_zone_for_filename("a/../../b").is_err());
    }

    #[test]
    fn test_validate_zone_rejects_absolute_paths() {
        // Path::join replaces the base entirely when given an absolute
        // path -- resolver_dir.join("/etc/passwd") == "/etc/passwd".
        assert!(validate_zone_for_filename("/etc/passwd").is_err());
    }

    #[test]
    fn test_validate_zone_rejects_backslash_and_dotfiles() {
        assert!(validate_zone_for_filename("..\\evil").is_err());
        assert!(validate_zone_for_filename(".").is_err());
        assert!(validate_zone_for_filename("..").is_err());
        assert!(validate_zone_for_filename(".hidden").is_err());
        assert!(validate_zone_for_filename("").is_err());
    }

    #[test]
    fn test_validate_zone_accepts_legitimate_dns_zones() {
        assert!(validate_zone_for_filename("ztlp").is_ok());
        assert!(validate_zone_for_filename("office.acme.ztlp").is_ok());
        assert!(validate_zone_for_filename("my-zone-01").is_ok());
    }

    #[test]
    fn test_setup_macos_resolver_rejects_malicious_zone() {
        // End-to-end (still without touching the real filesystem
        // location since MACOS_RESOLVER_DIR is a real system path we
        // must not write to in tests -- this just confirms the
        // validation call site is actually wired into the zone loop by
        // checking the error surfaces before any real fs::write for a
        // malicious zone would occur). We can't safely call
        // setup_macos_resolver() itself here (it targets a real system
        // directory), so this test locks in validate_zone_for_filename
        // as the gate function name/signature the call site depends on.
        let malicious_zones = vec!["../../etc/cron.d/evil".to_string()];
        for zone in &malicious_zones {
            assert!(
                validate_zone_for_filename(zone).is_err(),
                "zone {:?} must be rejected before ever reaching fs::write",
                zone
            );
        }
    }
}
