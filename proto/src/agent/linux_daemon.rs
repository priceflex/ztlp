//! Linux system-service token sharing (PR #112 review fix).
//!
//! The Linux systemd unit runs the agent as root with
//! `Environment=HOME=/var/lib/ztlp`, so the control-plane bearer token lives
//! at `/var/lib/ztlp/.ztlp/agent.token`, root-owned, mode 0600. The desktop
//! GUI runs as the logged-in user and looked for `~/.ztlp/agent.token`, a
//! file the service never writes, so on Linux the GUI could never
//! authenticate to the service.
//!
//! This is the Linux analogue of `macos_daemon::TokenGuiReadable` and the
//! Windows `icacls` grant:
//! * the root service makes the token readable by exactly the active
//!   graphical-session user (`chown <user> + chmod 0600`), and makes the
//!   state dirs traversable (0711, no listing) so that user can reach it;
//! * the GUI looks for the service token first, then its own path.
//!
//! Pure planners here are unit-tested on every platform; the executor only
//! runs for a root agent whose HOME is the system dir.

use std::path::{Path, PathBuf};

/// HOME the Linux systemd unit pins (see `dns_setup::generate_systemd_unit`).
pub const LINUX_SYSTEM_HOME: &str = "/var/lib/ztlp";

/// The Linux service's control-plane token path.
pub fn linux_system_token_path() -> PathBuf {
    PathBuf::from(LINUX_SYSTEM_HOME)
        .join(".ztlp")
        .join("agent.token")
}

/// Candidate token paths for a NON-service Linux caller (desktop GUI, CLI):
/// the service's token first, then the caller's own. Deduped. Pure.
pub fn gui_token_candidates(own_default: PathBuf) -> Vec<PathBuf> {
    let system = linux_system_token_path();
    if system == own_default {
        vec![system]
    } else {
        vec![system, own_default]
    }
}

/// Whether this process is the root Linux system service (root, and HOME is
/// the system dir). A developer's foreground `ztlp agent start` is neither,
/// so it never touches ownership. Pure over its inputs.
pub fn is_linux_system_service(euid_is_root: bool, home: Option<&str>) -> bool {
    euid_is_root && home.map(|h| h.trim_end_matches('/')) == Some(LINUX_SYSTEM_HOME)
}

/// Commands that give `user` (and only `user`) read access to the token.
/// `None` (nobody logged in graphically yet) leaves the root-only 0600 ACL
/// in place — the safe default; the grant is re-applied at every startup
/// and after enrollment.
pub fn token_share_commands(user: Option<&str>, token: &Path) -> Vec<Vec<String>> {
    let Some(u) = user else { return Vec::new() };
    let t = token.to_string_lossy().to_string();
    let state = token
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    vec![
        // Traverse-only (no listing) on /var/lib/ztlp and /var/lib/ztlp/.ztlp,
        // so the identity key and CA key stay unreadable (they are 0600).
        vec!["chmod".into(), "0711".into(), LINUX_SYSTEM_HOME.into()],
        vec!["chmod".into(), "0711".into(), state],
        vec!["chown".into(), format!("{u}:root"), t.clone()],
        vec!["chmod".into(), "0600".into(), t],
    ]
}

/// Pure parser for `loginctl list-sessions --no-legend` rows combined with
/// per-session `loginctl show-session <id> -p Name -p Type -p Active -p
/// Remote` blocks, fed in as `(name, type, active, remote)` tuples. Picks
/// the first active, local, graphical (x11/wayland/mir) session's user.
pub fn pick_graphical_user(sessions: &[(String, String, bool, bool)]) -> Option<String> {
    sessions
        .iter()
        .find(|(name, ty, active, remote)| {
            *active
                && !*remote
                && matches!(ty.as_str(), "x11" | "wayland" | "mir")
                && !name.is_empty()
                && name != "root"
        })
        .map(|(name, ..)| name.clone())
}

/// Parse `loginctl show-session <id> -p Name -p Type -p Active -p Remote`
/// output (`Key=value` lines) into the tuple `pick_graphical_user` takes.
pub fn parse_show_session(text: &str) -> (String, String, bool, bool) {
    let mut name = String::new();
    let mut ty = String::new();
    let mut active = false;
    let mut remote = false;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("Name", v)) => name = v.trim().to_string(),
            Some(("Type", v)) => ty = v.trim().to_string(),
            Some(("Active", v)) => active = v.trim() == "yes",
            Some(("Remote", v)) => remote = v.trim() == "yes",
            _ => {}
        }
    }
    (name, ty, active, remote)
}

#[cfg(target_os = "linux")]
fn graphical_session_user() -> Option<String> {
    let list = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
        .ok()?;
    let ids: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect();
    let sessions: Vec<_> = ids
        .iter()
        .filter_map(|id| {
            let o = std::process::Command::new("loginctl")
                .args([
                    "show-session",
                    id,
                    "-p",
                    "Name",
                    "-p",
                    "Type",
                    "-p",
                    "Active",
                    "-p",
                    "Remote",
                ])
                .output()
                .ok()?;
            Some(parse_show_session(&String::from_utf8_lossy(&o.stdout)))
        })
        .collect();
    pick_graphical_user(&sessions)
}

/// Apply the token grant if (and only if) this is the root system service.
/// Best-effort, log-and-continue, like the macOS/Windows equivalents.
#[cfg(target_os = "linux")]
pub fn share_token_with_gui_if_service(token: &Path) {
    use tracing::{info, warn};
    // SAFETY-free root check: `id -u` avoids pulling in libc for one call.
    let is_root = std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false);
    let home = std::env::var("HOME").ok();
    if !is_linux_system_service(is_root, home.as_deref()) {
        return;
    }
    let user = graphical_session_user();
    let cmds = token_share_commands(user.as_deref(), token);
    if cmds.is_empty() {
        warn!("Linux: no active graphical session user — agent.token stays root-only (0600)");
        return;
    }
    for c in cmds {
        match std::process::Command::new(&c[0]).args(&c[1..]).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => warn!(
                "Linux: `{}` failed (continuing): {}",
                c.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("Linux: failed to spawn `{}` (continuing): {e}", c[0]),
        }
    }
    info!(
        "Linux: agent.token shared with graphical user `{}`",
        user.unwrap_or_default()
    );
}

#[cfg(not(target_os = "linux"))]
pub fn share_token_with_gui_if_service(_token: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_token_path_is_under_var_lib_ztlp() {
        assert_eq!(
            linux_system_token_path(),
            PathBuf::from("/var/lib/ztlp/.ztlp/agent.token")
        );
    }

    #[test]
    fn gui_candidates_put_service_first_and_dedupe() {
        let own = PathBuf::from("/home/steven/.ztlp/agent.token");
        assert_eq!(
            gui_token_candidates(own.clone()),
            vec![linux_system_token_path(), own]
        );
        assert_eq!(
            gui_token_candidates(linux_system_token_path()),
            vec![linux_system_token_path()]
        );
    }

    #[test]
    fn only_root_with_system_home_is_the_service() {
        assert!(is_linux_system_service(true, Some("/var/lib/ztlp")));
        assert!(is_linux_system_service(true, Some("/var/lib/ztlp/")));
        assert!(!is_linux_system_service(false, Some("/var/lib/ztlp")));
        assert!(!is_linux_system_service(true, Some("/root")));
        assert!(!is_linux_system_service(true, None));
    }

    #[test]
    fn share_commands_grant_one_user_and_keep_dirs_unlistable() {
        let t = linux_system_token_path();
        let cmds = token_share_commands(Some("steven"), &t);
        assert!(cmds.contains(&vec![
            "chown".to_string(),
            "steven:root".into(),
            t.to_string_lossy().into()
        ]));
        assert!(cmds.contains(&vec![
            "chmod".to_string(),
            "0600".into(),
            t.to_string_lossy().into()
        ]));
        // Dirs are traverse-only, never world-readable/listable.
        for c in cmds
            .iter()
            .filter(|c| c[0] == "chmod" && c[2] != t.to_string_lossy())
        {
            assert_eq!(c[1], "0711");
        }
        // Nobody logged in => no change (root-only stays).
        assert!(token_share_commands(None, &t).is_empty());
    }

    #[test]
    fn picks_active_local_graphical_user_only() {
        let s = |n: &str, t: &str, a: bool, r: bool| (n.to_string(), t.to_string(), a, r);
        let sessions = vec![
            s("admin", "tty", true, false),
            s("remote", "x11", true, true),
            s("root", "wayland", true, false),
            s("idle", "wayland", false, false),
            s("steven", "wayland", true, false),
        ];
        assert_eq!(pick_graphical_user(&sessions).as_deref(), Some("steven"));
        assert_eq!(pick_graphical_user(&[s("admin", "tty", true, false)]), None);
    }

    #[test]
    fn parses_loginctl_show_session() {
        let out = "Name=steven\nType=wayland\nActive=yes\nRemote=no\n";
        assert_eq!(
            parse_show_session(out),
            ("steven".into(), "wayland".into(), true, false)
        );
    }
}
