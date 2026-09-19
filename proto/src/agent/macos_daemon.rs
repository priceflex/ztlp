//! macOS root-LaunchDaemon support for the ZTLP agent.
//!
//! On macOS the agent must run as root (bind VIP :80/:443, write
//! `/etc/resolver/<zone>`, add `lo0` aliases, add the ZTLP root CA to the
//! System keychain). Windows gets the equivalents from NRPT + the elevated
//! service; Linux gets loopback /8 for free and uses systemd. This module is
//! the macOS analogue and is deliberately split into:
//!
//! - **pure planning** (`macos_startup_plan`, `generate_launchdaemon_plist`,
//!   `vip_needs_loopback_alias`) — no I/O, unit-tested on every platform;
//! - **execution** (`MacosAction::command`, `execute`) — shells out to
//!   `ifconfig` / `security` / `chgrp`; only ever *invoked* from
//!   `daemon.rs` behind `cfg!(target_os = "macos")`.
//!
//! Nothing here is reachable from the Windows NRPT block or the Linux
//! systemd installer; their behavior is byte-identical to before.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{info, warn};

// ─── Locations ──────────────────────────────────────────────────────────────

/// Root-owned config home for the LaunchDaemon. The plist sets `HOME` to
/// this dir, so every existing `~/.ztlp/...` lookup in the agent (agent.toml,
/// identity.json, ca/, agent.token, vip_state.json) lands under
/// `/Library/Application Support/ZTLP/.ztlp/` with NO code changes elsewhere.
/// macOS analogue of Windows `C:\ProgramData\ZTLP`.
pub const MACOS_SYSTEM_CONFIG_DIR: &str = "/Library/Application Support/ZTLP";

/// System-wide LaunchDaemon plist (runs as root at boot).
pub const MACOS_LAUNCHDAEMON_PLIST_PATH: &str = "/Library/LaunchDaemons/org.ztlp.agent.plist";

/// launchd label.
pub const MACOS_LAUNCHDAEMON_LABEL: &str = "org.ztlp.agent";

const MACOS_LOG_DIR: &str = "/Library/Logs/ZTLP";

/// `$HOME/.ztlp` as seen by the root daemon.
pub fn macos_system_ztlp_dir() -> PathBuf {
    Path::new(MACOS_SYSTEM_CONFIG_DIR).join(".ztlp")
}

/// Where the non-root GUI reads the control-API bearer token from.
pub fn macos_system_token_path() -> PathBuf {
    macos_system_ztlp_dir().join("agent.token")
}

// ─── LaunchDaemon plist ─────────────────────────────────────────────────────

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Generate the root LaunchDaemon plist for the ZTLP agent.
///
/// Differences from the legacy per-user LaunchAgent (`generate_launchagent_plist`):
/// runs as root (`UserName`), pins `HOME` to [`MACOS_SYSTEM_CONFIG_DIR`],
/// logs under `/Library/Logs/ZTLP`, and XML-escapes the binary path.
pub fn generate_launchdaemon_plist(ztlp_binary: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>agent</string>
        <string>start</string>
        <string>--foreground</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>{home}</string>
    </dict>
    <key>UserName</key>
    <string>root</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{logs}/agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{logs}/agent.stderr.log</string>
</dict>
</plist>
"#,
        label = MACOS_LAUNCHDAEMON_LABEL,
        binary = xml_escape(ztlp_binary),
        home = xml_escape(MACOS_SYSTEM_CONFIG_DIR),
        logs = MACOS_LOG_DIR,
    )
}

// ─── Startup plan (pure) ────────────────────────────────────────────────────

/// Everything the planner needs; gathered by `daemon.rs` at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosStartupInputs {
    pub is_root: bool,
    /// EFFECTIVE DNS listen (post-fallback), e.g. "127.0.0.55:15353".
    pub dns_listen: String,
    /// Control API listen, e.g. "127.100.255.1:4433".
    pub control_listen: String,
    pub zones: Vec<String>,
    pub ca_root_pem: PathBuf,
    pub ca_root_pem_exists: bool,
    pub ca_already_trusted: bool,
    pub token_path: PathBuf,
}

impl MacosStartupInputs {
    /// Build from the loaded agent config + live facts.
    pub fn from_config(
        cfg: &crate::agent::config::AgentConfig,
        is_root: bool,
        effective_dns_listen: &str,
    ) -> Self {
        let ca_root_pem = crate::agent::ca_trust::default_ca_cert_path();
        let ca_root_pem_exists = ca_root_pem.exists();
        Self {
            is_root,
            dns_listen: effective_dns_listen.to_string(),
            control_listen: cfg.ipc.listen.clone(),
            zones: cfg.dns.zones.clone(),
            ca_root_pem_exists,
            ca_already_trusted: ca_root_pem_exists && crate::agent::ca_trust::is_ca_installed(),
            ca_root_pem,
            token_path: crate::agent::config::default_token_path(),
        }
    }
}

/// One privileged, idempotent step of the macOS root startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacosAction {
    /// `ifconfig lo0 alias <ip>` — macOS lo0 only carries 127.0.0.1.
    LoopbackAlias(Ipv4Addr),
    /// `/etc/resolver/<zone>` via `dns_setup::setup_dns` (existing, proven).
    WriteResolver { listen: String, zones: Vec<String> },
    /// `security add-trusted-cert` via `ca_trust::install_ca_cert` (existing).
    InstallCaCert(PathBuf),
    /// `chgrp staff` + `chmod 0640` so the non-root GUI can read the token.
    TokenGuiReadable(PathBuf),
}

/// A loopback IP other than 127.0.0.1 is unbindable on macOS until aliased.
pub fn vip_needs_loopback_alias(ip: Ipv4Addr) -> bool {
    ip.is_loopback() && ip != Ipv4Addr::LOCALHOST
}

fn loopback_ip_of(listen: &str) -> Option<Ipv4Addr> {
    let host = listen.rsplit_once(':').map(|(h, _)| h).unwrap_or(listen);
    let ip: Ipv4Addr = host.parse().ok()?;
    vip_needs_loopback_alias(ip).then_some(ip)
}

/// Compute the ordered list of privileged steps. Empty when not root — a
/// non-root `ztlp agent start` on macOS behaves exactly as before.
pub fn macos_startup_plan(i: &MacosStartupInputs) -> Vec<MacosAction> {
    if !i.is_root {
        return Vec::new();
    }
    let mut plan = Vec::new();
    let mut aliased: Vec<Ipv4Addr> = Vec::new();
    for listen in [&i.dns_listen, &i.control_listen] {
        if let Some(ip) = loopback_ip_of(listen) {
            if !aliased.contains(&ip) {
                aliased.push(ip);
                plan.push(MacosAction::LoopbackAlias(ip));
            }
        }
    }
    plan.push(MacosAction::WriteResolver {
        listen: i.dns_listen.clone(),
        zones: i.zones.clone(),
    });
    if i.ca_root_pem_exists && !i.ca_already_trusted {
        plan.push(MacosAction::InstallCaCert(i.ca_root_pem.clone()));
    }
    plan.push(MacosAction::TokenGuiReadable(i.token_path.clone()));
    plan
}

/// Same plan split into (pre-DNS-bind, post-DNS-bind) phases. Loopback
/// aliases must exist before `UdpSocket::bind(127.0.0.55)` can succeed on
/// macOS; everything else needs the EFFECTIVE bound port, so it runs after.
pub fn macos_startup_phases(i: &MacosStartupInputs) -> (Vec<MacosAction>, Vec<MacosAction>) {
    macos_startup_plan(i)
        .into_iter()
        .partition(|a| matches!(a, MacosAction::LoopbackAlias(_)))
}

// ─── Execution ──────────────────────────────────────────────────────────────

impl MacosAction {
    /// Shell rendering for single-command actions; `None` for actions that
    /// call into the crate instead.
    pub fn command(&self) -> Option<Vec<String>> {
        match self {
            MacosAction::LoopbackAlias(ip) => Some(vec![
                "ifconfig".into(),
                "lo0".into(),
                "alias".into(),
                ip.to_string(),
            ]),
            _ => None,
        }
    }

    /// All shell commands this action runs, in order.
    pub fn commands(&self) -> Vec<Vec<String>> {
        match self {
            MacosAction::TokenGuiReadable(p) => {
                let p = p.to_string_lossy().to_string();
                vec![
                    vec!["chgrp".into(), "staff".into(), p.clone()],
                    vec!["chmod".into(), "0640".into(), p],
                ]
            }
            other => other.command().into_iter().collect(),
        }
    }

    /// Run the action. Log-and-continue: every step is best-effort because
    /// the bind that follows is the real gate and fails loudly on its own.
    pub fn execute(&self) {
        match self {
            MacosAction::WriteResolver { listen, zones } => {
                match crate::agent::dns_setup::setup_dns(listen, zones) {
                    Ok(r) => info!("macOS: resolver files written: {:?}", r.files_written),
                    Err(e) => warn!("macOS: resolver setup failed (continuing): {e}"),
                }
                run_cmd(&["killall", "-HUP", "mDNSResponder"]);
            }
            MacosAction::InstallCaCert(pem) => match crate::agent::ca_trust::install_ca_cert(pem) {
                Ok(()) => info!("macOS: ZTLP root CA trusted in System keychain"),
                Err(e) => warn!("macOS: CA trust install failed (continuing): {e}"),
            },
            other => {
                for cmd in other.commands() {
                    let argv: Vec<&str> = cmd.iter().map(String::as_str).collect();
                    run_cmd(&argv);
                }
            }
        }
    }
}

fn run_cmd(argv: &[&str]) {
    match Command::new(argv[0]).args(&argv[1..]).output() {
        Ok(o) if o.status.success() => info!("macOS: ran `{}`", argv.join(" ")),
        Ok(o) => warn!(
            "macOS: `{}` exited {} (continuing): {}",
            argv.join(" "),
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => warn!("macOS: could not run `{}`: {e}", argv.join(" ")),
    }
}

/// Add an lo0 alias for a freshly allocated VIP (idempotent; ifconfig
/// re-alias of an existing address is a harmless no-op). Only meaningful as
/// root on macOS; callers gate on both.
pub fn ensure_vip_alias(ip: Ipv4Addr) {
    if vip_needs_loopback_alias(ip) {
        MacosAction::LoopbackAlias(ip).execute();
    }
}

/// Phase 1 (before the DNS bind): lo0 aliases. Returns the inputs so the
/// caller can re-plan phase 2 with the effective DNS listen.
pub fn run_startup_pre_bind(i: &MacosStartupInputs) {
    let (pre, _) = macos_startup_phases(i);
    if !i.is_root {
        info!("macOS: not running as root — skipping privileged startup (lo0 aliases, /etc/resolver, CA trust)");
        return;
    }
    info!(
        "macOS: root startup phase 1: {} lo0 alias step(s)",
        pre.len()
    );
    for a in &pre {
        a.execute();
    }
}

/// Phase 2 (after the DNS bind, with the EFFECTIVE listen): resolver files,
/// CA trust, token readability.
pub fn run_startup_post_bind(i: &MacosStartupInputs) {
    let (_, post) = macos_startup_phases(i);
    if post.is_empty() {
        return;
    }
    info!("macOS: root startup phase 2: {} step(s)", post.len());
    for a in &post {
        a.execute();
    }
}

/// Effective UID == 0 (unix). Always false elsewhere.
#[allow(unsafe_code)] // single libc call, no pointers; crate is otherwise deny(unsafe_code)
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    // ── LaunchDaemon plist ─────────────────────────────────────────────

    #[test]
    fn launchdaemon_plist_runs_agent_start_foreground_as_root() {
        let plist = generate_launchdaemon_plist("/Applications/ZTLP.app/Contents/MacOS/ztlp");
        assert!(plist.contains("<key>Label</key>\n    <string>org.ztlp.agent</string>"));
        assert!(plist.contains(
            "<string>/Applications/ZTLP.app/Contents/MacOS/ztlp</string>\n        \
             <string>agent</string>\n        \
             <string>start</string>\n        \
             <string>--foreground</string>"
        ));
        assert!(plist.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
        assert!(plist.contains("<key>UserName</key>\n    <string>root</string>"));
    }

    #[test]
    fn launchdaemon_plist_points_home_at_system_config_dir() {
        // Every `~/.ztlp/...` path in the agent resolves via $HOME. The
        // daemon must NOT use /var/root — the GUI needs a fixed, known dir.
        let plist = generate_launchdaemon_plist("/usr/local/bin/ztlp");
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains(&format!(
            "<key>HOME</key>\n        <string>{}</string>",
            MACOS_SYSTEM_CONFIG_DIR
        )));
        assert_eq!(MACOS_SYSTEM_CONFIG_DIR, "/Library/Application Support/ZTLP");
        assert_eq!(
            macos_system_ztlp_dir(),
            PathBuf::from("/Library/Application Support/ZTLP/.ztlp")
        );
        assert_eq!(
            macos_system_token_path(),
            PathBuf::from("/Library/Application Support/ZTLP/.ztlp/agent.token")
        );
    }

    #[test]
    fn launchdaemon_plist_logs_to_library_logs_not_tmp() {
        let plist = generate_launchdaemon_plist("/usr/local/bin/ztlp");
        assert!(plist.contains("<string>/Library/Logs/ZTLP/agent.stdout.log</string>"));
        assert!(plist.contains("<string>/Library/Logs/ZTLP/agent.stderr.log</string>"));
        assert!(!plist.contains("/tmp/"));
    }

    #[test]
    fn launchdaemon_plist_xml_escapes_binary_path() {
        let plist = generate_launchdaemon_plist("/Volumes/A&B <x>/ztlp");
        assert!(plist.contains("<string>/Volumes/A&amp;B &lt;x&gt;/ztlp</string>"));
        assert!(!plist.contains("A&B"));
    }

    #[test]
    fn launchdaemon_plist_path_is_system_wide() {
        assert_eq!(
            MACOS_LAUNCHDAEMON_PLIST_PATH,
            "/Library/LaunchDaemons/org.ztlp.agent.plist"
        );
    }

    // ── Startup plan ──────────────────────────────────────────────────

    fn inputs() -> MacosStartupInputs {
        MacosStartupInputs {
            is_root: true,
            dns_listen: "127.0.0.55:15353".to_string(),
            control_listen: "127.100.255.1:4433".to_string(),
            zones: vec!["defcon.ztlp".to_string()],
            ca_root_pem: PathBuf::from("/Library/Application Support/ZTLP/.ztlp/ca/root.pem"),
            ca_root_pem_exists: true,
            ca_already_trusted: false,
            token_path: PathBuf::from("/Library/Application Support/ZTLP/.ztlp/agent.token"),
        }
    }

    #[test]
    fn plan_is_empty_when_not_root() {
        let mut i = inputs();
        i.is_root = false;
        assert!(macos_startup_plan(&i).is_empty());
    }

    #[test]
    fn plan_aliases_dns_and_control_ips_before_anything_else() {
        let plan = macos_startup_plan(&inputs());
        assert_eq!(
            plan[0],
            MacosAction::LoopbackAlias(Ipv4Addr::new(127, 0, 0, 55))
        );
        assert_eq!(
            plan[1],
            MacosAction::LoopbackAlias(Ipv4Addr::new(127, 100, 255, 1))
        );
    }

    #[test]
    fn plan_skips_alias_for_127_0_0_1_and_dedupes() {
        let mut i = inputs();
        i.dns_listen = "127.0.0.1:15353".to_string();
        i.control_listen = "127.0.0.1:4433".to_string();
        let plan = macos_startup_plan(&i);
        assert!(!plan
            .iter()
            .any(|a| matches!(a, MacosAction::LoopbackAlias(_))));

        let mut i = inputs();
        i.control_listen = "127.0.0.55:4433".to_string();
        let plan = macos_startup_plan(&i);
        let aliases = plan
            .iter()
            .filter(|a| matches!(a, MacosAction::LoopbackAlias(_)))
            .count();
        assert_eq!(aliases, 1);
    }

    #[test]
    fn plan_skips_alias_for_non_loopback_listen() {
        let mut i = inputs();
        i.dns_listen = "0.0.0.0:53".to_string();
        let plan = macos_startup_plan(&i);
        assert!(!plan
            .iter()
            .any(|a| *a == MacosAction::LoopbackAlias(Ipv4Addr::new(0, 0, 0, 0))));
    }

    #[test]
    fn plan_writes_resolver_for_dns_listen_and_zones() {
        let plan = macos_startup_plan(&inputs());
        assert!(plan.contains(&MacosAction::WriteResolver {
            listen: "127.0.0.55:15353".to_string(),
            zones: vec!["defcon.ztlp".to_string()],
        }));
    }

    #[test]
    fn plan_installs_ca_only_when_pem_exists_and_not_yet_trusted() {
        let plan = macos_startup_plan(&inputs());
        assert!(plan.contains(&MacosAction::InstallCaCert(inputs().ca_root_pem)));

        let mut i = inputs();
        i.ca_already_trusted = true;
        assert!(!macos_startup_plan(&i)
            .iter()
            .any(|a| matches!(a, MacosAction::InstallCaCert(_))));

        let mut i = inputs();
        i.ca_root_pem_exists = false;
        assert!(!macos_startup_plan(&i)
            .iter()
            .any(|a| matches!(a, MacosAction::InstallCaCert(_))));
    }

    #[test]
    fn plan_makes_token_readable_by_gui_user_last() {
        let plan = macos_startup_plan(&inputs());
        assert_eq!(
            plan.last().unwrap(),
            &MacosAction::TokenGuiReadable(inputs().token_path)
        );
    }

    #[test]
    fn plan_splits_into_pre_bind_aliases_and_post_bind_rest() {
        // daemon.rs must alias lo0 BEFORE binding the DNS socket (os error 49
        // otherwise) but write /etc/resolver AFTER, with the effective port.
        let (pre, post) = macos_startup_phases(&inputs());
        assert_eq!(pre.len(), 2);
        assert!(pre
            .iter()
            .all(|a| matches!(a, MacosAction::LoopbackAlias(_))));
        assert!(!post
            .iter()
            .any(|a| matches!(a, MacosAction::LoopbackAlias(_))));
        assert_eq!(post.len(), 3);
        let mut joined = pre.clone();
        joined.extend(post);
        assert_eq!(joined, macos_startup_plan(&inputs()));
    }

    // ── VIP alias on lazy allocation ──────────────────────────────────

    #[test]
    fn vip_needs_alias_for_loopback_other_than_127_0_0_1() {
        assert!(vip_needs_loopback_alias(Ipv4Addr::new(127, 100, 0, 1)));
        assert!(vip_needs_loopback_alias(Ipv4Addr::new(127, 0, 0, 55)));
        assert!(!vip_needs_loopback_alias(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!vip_needs_loopback_alias(Ipv4Addr::new(10, 0, 0, 1)));
    }

    // ── Command rendering (what the executor will actually run) ───────

    #[test]
    fn loopback_alias_renders_ifconfig_lo0_alias() {
        let a = MacosAction::LoopbackAlias(Ipv4Addr::new(127, 0, 0, 55));
        assert_eq!(
            a.command(),
            Some(vec![
                "ifconfig".to_string(),
                "lo0".to_string(),
                "alias".to_string(),
                "127.0.0.55".to_string(),
            ])
        );
    }

    #[test]
    fn token_gui_readable_renders_chgrp_staff_and_chmod_0640() {
        let a = MacosAction::TokenGuiReadable(PathBuf::from("/x/agent.token"));
        assert_eq!(
            a.commands(),
            vec![
                vec![
                    "chgrp".to_string(),
                    "staff".to_string(),
                    "/x/agent.token".to_string()
                ],
                vec![
                    "chmod".to_string(),
                    "0640".to_string(),
                    "/x/agent.token".to_string()
                ],
            ]
        );
    }

    #[test]
    fn resolver_and_ca_actions_have_no_shell_command_they_call_into_crate() {
        // These reuse dns_setup::setup_dns and ca_trust::install_ca_cert
        // (already tested + proven live); no separate shell rendering.
        let r = MacosAction::WriteResolver {
            listen: "127.0.0.55:15353".to_string(),
            zones: vec![],
        };
        assert_eq!(r.command(), None);
        let c = MacosAction::InstallCaCert(PathBuf::from("/x/root.pem"));
        assert_eq!(c.command(), None);
    }

    #[test]
    fn plan_from_config_reads_dns_and_ipc_listen_and_zones() {
        // Integration with the real AgentConfig shape so daemon.rs wiring
        // can't silently pass the wrong field.
        let mut cfg = crate::agent::config::AgentConfig::default();
        cfg.dns.listen = "127.0.0.77:15353".to_string();
        cfg.ipc.listen = "127.100.255.9:4433".to_string();
        cfg.dns.zones = vec!["a.ztlp".to_string(), "b.ztlp".to_string()];
        let i = MacosStartupInputs::from_config(&cfg, true, "127.0.0.77:15353");
        assert_eq!(i.dns_listen, "127.0.0.77:15353");
        assert_eq!(i.control_listen, "127.100.255.9:4433");
        assert_eq!(i.zones, vec!["a.ztlp".to_string(), "b.ztlp".to_string()]);
        assert!(i.is_root);
    }
}
