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

fn setup_systemd_resolved(
    listen_addr: &str,
    zones: &[String],
) -> Result<DnsSetupResult, Box<dyn std::error::Error>> {
    let conf_dir = Path::new(RESOLVED_CONF_DIR);
    let conf_path = conf_dir.join(RESOLVED_CONF_FILE);

    // Parse listen address to get just the IP and port
    let (dns_ip, dns_port) = parse_listen_addr(listen_addr)?;

    // Build domain list with ~ prefix (routing-only domains)
    let mut domain_entries = vec!["~ztlp".to_string()];
    for zone in zones {
        let entry = format!("~{}", zone.trim_start_matches('~'));
        if !domain_entries.contains(&entry) {
            domain_entries.push(entry);
        }
    }

    let dns_addr = if dns_port != 53 {
        format!("{}#{}", dns_ip, dns_port)
    } else {
        dns_ip.to_string()
    };

    let content = format!(
        "# Managed by ztlp-agent — do not edit manually\n\
         # Remove with: ztlp agent dns-teardown\n\
         [Resolve]\n\
         DNS={}\n\
         Domains={}\n",
        dns_addr,
        domain_entries.join(" ")
    );

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
        let file_path = resolver_dir.join(zone);
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

/// Install the ZTLP agent as a system service.
///
/// Returns the path to the installed service file and any instructions.
pub fn install_service(ztlp_binary: &str) -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
    if cfg!(target_os = "macos") {
        let plist_dir = dirs::home_dir()
            .map(|h| h.join("Library/LaunchAgents"))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let plist_path = plist_dir.join("org.ztlp.agent.plist");

        fs::create_dir_all(&plist_dir)?;
        let content = generate_launchagent_plist(ztlp_binary);
        fs::write(&plist_path, &content)?;

        let instructions = format!(
            "LaunchAgent installed: {}\n\n\
             Load now:\n  launchctl load {}\n\n\
             Unload:\n  launchctl unload {}",
            plist_path.display(),
            plist_path.display(),
            plist_path.display()
        );

        Ok((plist_path, instructions))
    } else {
        // Linux systemd
        let unit_path = PathBuf::from(SYSTEMD_UNIT_PATH);
        let content = generate_systemd_unit(ztlp_binary);
        fs::write(&unit_path, &content)?;

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

        Ok((unit_path, instructions))
    }
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
}
