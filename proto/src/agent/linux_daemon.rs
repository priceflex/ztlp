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

/// Commands that give `user` (and only `user`) READ access to the token while
/// root stays the owner (PR #112 review: chowning the file to the user let
/// them overwrite the service's bearer, not just read it).
/// `None` (nobody logged in graphically yet) leaves the root-only 0600 file
/// as is; the refresher re-applies the grant once someone logs in.
pub fn token_share_commands(user: Option<&str>, token: &Path) -> Vec<Vec<String>> {
    let Some(u) = user else { return Vec::new() };
    let t = token.to_string_lossy().to_string();
    let state = token
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    vec![
        // Traverse-only (no listing) on /var/lib/ztlp and /var/lib/ztlp/.ztlp,
        // so the identity key and CA key (0600) stay unreadable.
        vec!["chmod".into(), "0711".into(), LINUX_SYSTEM_HOME.into()],
        vec!["chmod".into(), "0711".into(), state],
        // Owner stays root:root 0600; add a read-only ACL entry for the user.
        vec!["chown".into(), "root:root".into(), t.clone()],
        vec!["chmod".into(), "0600".into(), t.clone()],
        vec!["setfacl".into(), "-m".into(), format!("u:{u}:r"), t],
    ]
}

/// Fallback when `setfacl` is unavailable / the filesystem has no ACLs:
/// root keeps ownership, group = the user's own private group, mode 0640.
/// Only used when that group is the user's private group (name == user), so
/// no other account is granted access.
pub fn token_share_group_fallback(user: &str, token: &Path) -> Vec<Vec<String>> {
    let t = token.to_string_lossy().to_string();
    vec![
        vec!["chown".into(), format!("root:{user}"), t.clone()],
        vec!["chmod".into(), "0640".into(), t],
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
/// Returns the user that was granted access, if any.
#[cfg(target_os = "linux")]
pub fn share_token_with_gui_if_service(token: &Path) -> Option<String> {
    use tracing::{info, warn};
    let is_root = std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false);
    let home = std::env::var("HOME").ok();
    if !is_linux_system_service(is_root, home.as_deref()) {
        return None;
    }
    let user = graphical_session_user()?;
    let run = |c: &Vec<String>| -> bool {
        match std::process::Command::new(&c[0]).args(&c[1..]).output() {
            Ok(o) if o.status.success() => true,
            Ok(o) => {
                warn!(
                    "Linux: `{}` failed: {}",
                    c.join(" "),
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                false
            }
            Err(e) => {
                warn!("Linux: failed to spawn `{}`: {e}", c[0]);
                false
            }
        }
    };
    let mut acl_ok = true;
    for c in token_share_commands(Some(&user), token) {
        if !run(&c) && c[0] == "setfacl" {
            acl_ok = false;
        }
    }
    if !acl_ok {
        let private_group = std::process::Command::new("id")
            .args(["-gn", &user])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == user)
            .unwrap_or(false);
        if private_group {
            for c in token_share_group_fallback(&user, token) {
                run(&c);
            }
        } else {
            warn!("Linux: no ACL support and `{user}` has no private group; agent.token stays root-only");
            return None;
        }
    }
    info!("Linux: agent.token readable by graphical user `{user}` (root remains owner)");
    Some(user)
}

/// Re-apply the grant every 30s so a user who logs in (or switches) AFTER
/// the service started still gets access. No-op unless this is the root
/// system service. Idempotent and cheap (two loginctl calls when nothing
/// changed).
#[cfg(target_os = "linux")]
pub fn spawn_token_share_refresher(token: PathBuf) {
    // Standby and the full daemon both call this in one process; run once.
    static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("ztlp-token-share".into())
        .spawn(move || {
            let mut last: Option<String> = None;
            loop {
                let now = graphical_session_user();
                if now != last {
                    if now.is_some() {
                        share_token_with_gui_if_service(&token);
                    }
                    last = now;
                }
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        });
}

#[cfg(not(target_os = "linux"))]
pub fn share_token_with_gui_if_service(_token: &Path) -> Option<String> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_token_share_refresher(_token: PathBuf) {}

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
        // Root stays the OWNER (the user must not be able to overwrite the
        // bearer); the user gets a read-only ACL entry.
        assert!(cmds.contains(&vec![
            "chown".to_string(),
            "root:root".into(),
            t.to_string_lossy().into()
        ]));
        assert!(cmds.contains(&vec![
            "setfacl".to_string(),
            "-m".into(),
            "u:steven:r".into(),
            t.to_string_lossy().into()
        ]));
        assert!(
            !cmds
                .iter()
                .any(|c| c[0] == "chown" && c[1].starts_with("steven")),
            "must never chown the token to the desktop user"
        );
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
    fn group_fallback_keeps_root_owner_and_is_group_read_only() {
        let t = linux_system_token_path();
        let c = token_share_group_fallback("steven", &t);
        assert_eq!(c[0][1], "root:steven");
        assert_eq!(c[1][1], "0640");
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
