//! macOS: move the enrollment of the old root agent to the per-user agent.
//!
//! Up to desktop 1.3.0 the agent ran as root and kept its enrollment
//! (identity.json, config.toml, agent.toml) in
//! `/Library/Application Support/ZTLP/.ztlp`, readable by root only. The
//! per-user agent reads `~/.ztlp`. After the upgrade it therefore started
//! on whatever old files happened to be in `~/.ztlp` (live on a MacBook: a
//! config from months earlier pointing at a dead name server and a DNS
//! port nothing asked on) while the registered identity sat unused in the
//! root directory. The device looked unenrolled, and re-enrolling would
//! have thrown its registered key away.
//!
//! The agent cannot read the root files, so it asks the root machine
//! service (the port broker socket, verb `MIGRATE`) for them:
//!
//! - agent → service: `MIGRATE <own node id or -> <own config.toml mtime>\n`
//! - service → agent: `OK\n` + the files, or `ERR <reason>\n`
//!
//! Root never writes into the user's home (a user-controlled path); it only
//! reads its own directory and sends the bytes. The agent, as the user,
//! backs up what it has and writes the new files.
//!
//! The service hands the enrollment out only when ALL of these hold:
//! - the root directory holds a complete enrollment that is self-contained
//!   (its config names an identity inside that directory);
//! - it is newer than the asking user's own enrollment, and is not the
//!   identity that user already runs;
//! - the asking account is an administrator (it could read the files with
//!   `sudo` anyway; a standard account must not get the machine's key);
//! - it was not already handed to a different account.
#![cfg(unix)]

use super::port_broker::BrokerError;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Where the root agent (desktop <= 1.3.0) kept its enrollment.
pub const LEGACY_DIR: &str = "/Library/Application Support/ZTLP/.ztlp";

/// Written by the service into [`LEGACY_DIR`] once the enrollment has been
/// handed to an account (holds that account's uid).
pub const MARKER_FILE: &str = "migrated-to-user";

const VERB: &str = "MIGRATE";
const MAX_FILE: usize = 64 * 1024;
const MAX_PINS: usize = 256;
const MAX_BUNDLE: usize = 1024 * 1024;

/// What the agent tells the service about its own state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateRequest {
    /// Node id of the identity in `~/.ztlp`, if there is one.
    pub node_id: Option<String>,
    /// Modification time (Unix seconds) of `~/.ztlp/config.toml`, 0 if none.
    pub config_mtime: u64,
}

impl MigrateRequest {
    pub fn to_line(&self) -> String {
        format!(
            "{VERB} {} {}\n",
            self.node_id.as_deref().unwrap_or("-"),
            self.config_mtime
        )
    }

    /// `None`: not a `MIGRATE` line at all. `Some(Err)`: a malformed one.
    pub fn parse(line: &str) -> Option<Result<Self, String>> {
        let mut it = line.split_whitespace();
        if it.next() != Some(VERB) {
            return None;
        }
        let parsed = match (it.next(), it.next(), it.next()) {
            (Some(id), Some(mtime), None) => {
                let ok_id =
                    id == "-" || (id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit()));
                match (ok_id, mtime.parse::<u64>()) {
                    (true, Ok(config_mtime)) => Ok(MigrateRequest {
                        node_id: (id != "-").then(|| id.to_ascii_lowercase()),
                        config_mtime,
                    }),
                    _ => Err(format!("bad request: {:?}", line.trim())),
                }
            }
            _ => Err(format!("bad request: {:?}", line.trim())),
        };
        Some(parsed)
    }
}

/// The files of one enrollment: (relative name, contents).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bundle {
    pub files: Vec<(String, Vec<u8>)>,
}

impl Bundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in &self.files {
            out.extend_from_slice(format!("FILE {name} {}\n", data.len()).as_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(b"END\n");
        out
    }

    pub fn decode(mut buf: &[u8]) -> Result<Self, String> {
        let mut files = Vec::new();
        loop {
            let nl = buf
                .iter()
                .position(|b| *b == b'\n')
                .ok_or("truncated reply")?;
            let header = std::str::from_utf8(&buf[..nl]).map_err(|_| "bad header")?;
            buf = &buf[nl + 1..];
            if header == "END" {
                return Ok(Bundle { files });
            }
            let mut it = header.split(' ');
            let (name, len) = match (it.next(), it.next(), it.next(), it.next()) {
                (Some("FILE"), Some(name), Some(len), None) => {
                    (name, len.parse::<usize>().map_err(|_| "bad length")?)
                }
                _ => return Err(format!("bad header: {header:?}")),
            };
            if !allowed_name(name) {
                return Err(format!("unexpected file name: {name:?}"));
            }
            if len > MAX_FILE || len > buf.len() {
                return Err(format!("bad length for {name}"));
            }
            files.push((name.to_string(), buf[..len].to_vec()));
            buf = &buf[len..];
        }
    }

    fn get(&self, name: &str) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.as_slice())
    }
}

/// Only these may cross: the three enrollment files and gateway pins.
fn allowed_name(name: &str) -> bool {
    if matches!(name, "identity.json" | "config.toml" | "agent.toml") {
        return true;
    }
    match name.strip_prefix("quic_pins/") {
        Some(pin) => {
            !pin.is_empty()
                && pin.len() <= 128
                && !pin.starts_with('.')
                && pin
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
        None => false,
    }
}

fn node_id_of(identity_json: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(identity_json).ok()?;
    Some(v.get("node_id")?.as_str()?.to_ascii_lowercase())
}

fn mtime_secs(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Every quoted path ending in `identity.json` in a config file.
fn identity_paths_in(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let v = l.split_once('=')?.1.trim().trim_matches('"');
            v.ends_with("identity.json").then(|| v.to_string())
        })
        .collect()
}

// ── service (root) side ─────────────────────────────────────────────────

/// Hook for [`super::port_broker::run_broker_with`].
pub fn broker_hook(uid: u32, line: &str) -> Option<Result<Vec<u8>, String>> {
    let req = match MigrateRequest::parse(line)? {
        Ok(r) => r,
        Err(e) => return Some(Err(e)),
    };
    Some(serve(Path::new(LEGACY_DIR), uid, &req, uid_is_admin).map(|b| b.encode()))
}

/// Decide and, if allowed, read the enrollment out of `legacy_dir`.
pub fn serve(
    legacy_dir: &Path,
    uid: u32,
    req: &MigrateRequest,
    is_admin: impl Fn(u32) -> bool,
) -> Result<Bundle, String> {
    let identity_path = legacy_dir.join("identity.json");
    if !super::daemon::enrollment_is_complete(&identity_path) {
        return Err("no enrollment from the old root agent on this Mac".into());
    }
    let marker = legacy_dir.join(MARKER_FILE);
    if let Ok(owner) = std::fs::read_to_string(&marker) {
        if owner.trim() != uid.to_string() {
            return Err("the old enrollment was already moved to another account".into());
        }
    }
    let read = |name: &str| -> Result<Vec<u8>, String> {
        let data = std::fs::read(legacy_dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
        if data.len() > MAX_FILE {
            return Err(format!("{name} is too large"));
        }
        Ok(data)
    };
    let identity = read("identity.json")?;
    let config = read("config.toml")?;
    let agent = read("agent.toml").ok();
    let legacy_id = node_id_of(&identity).ok_or("the old identity.json has no node id")?;

    // Self-contained: the old agent really used the identity in this
    // directory. (Seen on a build Mac: its config named an identity in a
    // user's home, so this directory was never the live enrollment.)
    let prefix = legacy_dir.to_string_lossy().into_owned();
    for text in [Some(&config), agent.as_ref()].into_iter().flatten() {
        for p in identity_paths_in(&String::from_utf8_lossy(text)) {
            if !p.starts_with(&prefix) {
                return Err("the old agent used an identity outside its own directory".into());
            }
        }
    }
    if req.node_id.as_deref() == Some(legacy_id.as_str()) {
        return Err("this account already runs the old enrollment's identity".into());
    }
    if mtime_secs(&legacy_dir.join("config.toml")) <= req.config_mtime {
        return Err("this account's own enrollment is newer than the old one".into());
    }
    if !is_admin(uid) {
        return Err("only an administrator account can take over this Mac's old enrollment".into());
    }

    let mut files = vec![("config.toml".to_string(), config)];
    if let Some(a) = agent {
        files.push(("agent.toml".to_string(), a));
    }
    if let Ok(dir) = std::fs::read_dir(legacy_dir.join("quic_pins")) {
        let mut pins: Vec<PathBuf> = dir.flatten().map(|e| e.path()).collect();
        pins.sort();
        for p in pins.into_iter().take(MAX_PINS) {
            let Some(base) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let name = format!("quic_pins/{base}");
            if !base.ends_with(".pin") || !allowed_name(&name) {
                continue;
            }
            match std::fs::read(&p) {
                Ok(d) if d.len() <= 4096 => files.push((name, d)),
                _ => continue,
            }
        }
    }
    // The identity goes last: the agent treats identity.json + config.toml
    // as "enrolled", so it must not appear before its config.
    files.push(("identity.json".to_string(), identity));

    // One account only. Written before the reply: if the reply is lost the
    // same account simply asks again.
    std::fs::write(&marker, format!("{uid}\n")).map_err(|e| format!("marker: {e}"))?;
    Ok(Bundle { files })
}

/// Is `uid` an administrator account (member of group `admin`, gid 80)?
pub fn uid_is_admin(uid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    std::process::Command::new("/usr/bin/id")
        .args(["-G", &uid.to_string()])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|g| g == "80")
        })
        .unwrap_or(false)
}

// ── agent (user) side ───────────────────────────────────────────────────

/// Cheap, unprivileged pre-check: is there an old root enrollment that
/// looks newer than ours? (The identity file itself is unreadable, but its
/// presence and the world-readable config.toml are visible.) `None` on
/// every Mac that never ran the root agent, so nothing is asked there.
pub fn candidate(legacy_dir: &Path, user_dir: &Path) -> Option<MigrateRequest> {
    if !super::daemon::enrollment_is_complete(&legacy_dir.join("identity.json")) {
        return None;
    }
    let config_mtime = mtime_secs(&user_dir.join("config.toml"));
    if mtime_secs(&legacy_dir.join("config.toml")) <= config_mtime {
        return None;
    }
    let node_id = std::fs::read(user_dir.join("identity.json"))
        .ok()
        .and_then(|d| node_id_of(&d));
    Some(MigrateRequest {
        node_id,
        config_mtime,
    })
}

/// Ask the machine service at `socket_path` for the old enrollment.
pub fn request(socket_path: &Path, req: &MigrateRequest) -> Result<Bundle, BrokerError> {
    let unavailable =
        |what: &str, e: io::Error| BrokerError::Unavailable(format!("machine service {what}: {e}"));
    let mut conn = UnixStream::connect(socket_path).map_err(|e| unavailable("unavailable", e))?;
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    conn.write_all(req.to_line().as_bytes())
        .map_err(|e| unavailable("write", e))?;
    let mut buf = Vec::new();
    conn.take(MAX_BUNDLE as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| unavailable("read", e))?;
    if buf.len() > MAX_BUNDLE {
        return Err(BrokerError::Refused("reply too large".into()));
    }
    if let Some(rest) = buf.strip_prefix(b"OK\n") {
        return Bundle::decode(rest).map_err(BrokerError::Refused);
    }
    let reply = String::from_utf8_lossy(&buf).trim().to_string();
    if reply == "ERR busy" || reply.is_empty() {
        return Err(BrokerError::Unavailable(format!(
            "machine service busy or gone ({reply:?})"
        )));
    }
    Err(BrokerError::Refused(
        reply.trim_start_matches("ERR ").trim().to_string(),
    ))
}

/// Write the bundle into `user_dir`, keeping what was there as
/// `<name>.<stamp>.pre-migrate.bak`. Paths inside the config files that
/// point into `legacy_dir` are rewritten to `user_dir`. Returns the names
/// written.
pub fn install(
    bundle: &Bundle,
    user_dir: &Path,
    legacy_dir: &Path,
    stamp: u64,
) -> io::Result<Vec<String>> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if bundle.get("identity.json").is_none() || bundle.get("config.toml").is_none() {
        return Err(io::Error::other("incomplete enrollment in the reply"));
    }
    if !user_dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(user_dir)?;
    }
    let from = legacy_dir.to_string_lossy().into_owned();
    let to = user_dir.to_string_lossy().into_owned();
    let mut written = Vec::new();
    for (name, data) in &bundle.files {
        if !allowed_name(name) {
            continue;
        }
        let dest = user_dir.join(name);
        let is_pin = name.starts_with("quic_pins/");
        if is_pin {
            if dest.exists() {
                continue; // a pin this account already learned wins
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let data: Vec<u8> = if name.ends_with(".toml") {
            String::from_utf8_lossy(data)
                .replace(&from, &to)
                .into_bytes()
        } else {
            data.clone()
        };
        let base = dest.file_name().and_then(|n| n.to_str()).unwrap_or("f");
        let tmp = dest.with_file_name(format!(".{base}.migrate-tmp"));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if is_pin { 0o644 } else { 0o600 })
            .open(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
        drop(f);
        if !is_pin && dest.exists() {
            std::fs::rename(
                &dest,
                dest.with_file_name(format!("{base}.{stamp}.pre-migrate.bak")),
            )?;
        }
        std::fs::rename(&tmp, &dest)?;
        written.push(name.clone());
    }
    Ok(written)
}

/// Agent start (macOS, not root): take over the old root agent's
/// enrollment when there is one to take. Waits up to `wait` for the machine
/// service's socket (it may still be starting during the upgrade). Returns
/// a line for the log when something happened or was refused.
pub fn migrate_if_needed(
    legacy_dir: &Path,
    user_dir: &Path,
    socket_path: &Path,
    wait: std::time::Duration,
) -> Option<String> {
    let req = candidate(legacy_dir, user_dir)?;
    let deadline = std::time::Instant::now() + wait;
    let bundle = loop {
        match request(socket_path, &req) {
            Ok(b) => break b,
            Err(e) if e.is_retryable() && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            Err(e) => return Some(format!("old root-agent enrollment not taken over: {e}")),
        }
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some(match install(&bundle, user_dir, legacy_dir, stamp) {
        Ok(names) => format!(
            "took over the old root agent's enrollment ({} file(s) into {}; previous files kept as *.{stamp}.pre-migrate.bak)",
            names.len(),
            user_dir.display()
        ),
        Err(e) => format!("old root-agent enrollment received but not installed: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_ID: &str = "42a52f2ab6dbd2e391707d8715fe6fbc";
    const STRAY_ID: &str = "611c0d19ef920de4e45933368cbdcf2a";

    fn identity(id: &str) -> String {
        format!("{{\n  \"node_id\": \"{id}\",\n  \"static_private_key\": \"00\"\n}}")
    }

    /// A legacy root dir as found on the MacBook.
    fn legacy(root: &Path) -> PathBuf {
        let d = root.join("legacy").join(".ztlp");
        std::fs::create_dir_all(d.join("quic_pins")).unwrap();
        std::fs::write(d.join("identity.json"), identity(LEGACY_ID)).unwrap();
        std::fs::write(
            d.join("config.toml"),
            format!(
                "identity = \"{}/identity.json\"\nns_server = \"192.0.2.1:23096\"\nzone = \"trs.ztlp\"\n",
                d.display()
            ),
        )
        .unwrap();
        std::fs::write(
            d.join("agent.toml"),
            format!(
                "[identity]\npath = \"{}/identity.json\"\n\n[dns]\nlisten = \"127.0.0.55:15353\"\n",
                d.display()
            ),
        )
        .unwrap();
        std::fs::write(d.join("quic_pins").join("localhost_blitz.pin"), "aa").unwrap();
        std::fs::write(d.join("quic_pins").join("..evil"), "x").unwrap();
        d
    }

    fn req(id: Option<&str>, mtime: u64) -> MigrateRequest {
        MigrateRequest {
            node_id: id.map(str::to_string),
            config_mtime: mtime,
        }
    }

    #[test]
    fn request_line_round_trips_and_rejects_garbage() {
        let r = req(Some(STRAY_ID), 1700000000);
        assert_eq!(MigrateRequest::parse(&r.to_line()), Some(Ok(r)));
        let none = req(None, 0);
        assert_eq!(none.to_line(), "MIGRATE - 0\n");
        assert_eq!(MigrateRequest::parse(&none.to_line()), Some(Ok(none)));
        // not ours: left to the BIND parser
        assert_eq!(MigrateRequest::parse("BIND 127.100.0.3 443"), None);
        for bad in [
            "MIGRATE",
            "MIGRATE - x",
            "MIGRATE ../../etc 0",
            "MIGRATE - 0 extra",
        ] {
            assert!(
                matches!(MigrateRequest::parse(bad), Some(Err(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn bundle_round_trips_and_refuses_unexpected_names() {
        let b = Bundle {
            files: vec![
                ("config.toml".into(), b"zone = \"z\"\n".to_vec()),
                ("quic_pins/a_b-1.pin".into(), vec![0, 1, 2, b'\n']),
                ("identity.json".into(), b"{}".to_vec()),
            ],
        };
        assert_eq!(Bundle::decode(&b.encode()), Ok(b));
        for name in [
            "../x",
            "/etc/passwd",
            "quic_pins/../x",
            "quic_pins/.x",
            "agent.token",
        ] {
            let evil = format!("FILE {name} 1\nxEND\n");
            assert!(Bundle::decode(evil.as_bytes()).is_err(), "{name}");
        }
        assert!(Bundle::decode(b"FILE config.toml 99\nshort").is_err());
        assert!(Bundle::decode(b"FILE config.toml 1\nx").is_err(), "no END");
    }

    /// The MacBook case end to end: an old config and identity in ~/.ztlp,
    /// the registered enrollment in the root dir.
    #[test]
    fn stray_user_files_are_replaced_by_the_root_enrollment() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy_dir = legacy(tmp.path());
        let user = tmp.path().join("home").join(".ztlp");
        std::fs::create_dir_all(&user).unwrap();
        std::fs::write(user.join("identity.json"), identity(STRAY_ID)).unwrap();
        std::fs::write(
            user.join("agent.toml"),
            "[dns]\nlisten = \"127.0.0.1:5354\"\n",
        )
        .unwrap();

        let r = candidate(&legacy_dir, &user).expect("root enrollment is a candidate");
        assert_eq!(r.node_id.as_deref(), Some(STRAY_ID));
        let bundle = serve(&legacy_dir, 501, &r, |_| true).expect("served");
        assert_eq!(
            bundle.files.last().map(|f| f.0.as_str()),
            Some("identity.json"),
            "identity must be written last"
        );
        assert!(bundle.get("quic_pins/..evil").is_none());
        let names = install(&bundle, &user, &legacy_dir, 1234).unwrap();
        assert!(names.contains(&"quic_pins/localhost_blitz.pin".to_string()));

        let id = std::fs::read(user.join("identity.json")).unwrap();
        assert_eq!(node_id_of(&id).as_deref(), Some(LEGACY_ID));
        // old files kept
        let bak = std::fs::read(user.join("identity.json.1234.pre-migrate.bak")).unwrap();
        assert_eq!(node_id_of(&bak).as_deref(), Some(STRAY_ID));
        assert!(user.join("agent.toml.1234.pre-migrate.bak").exists());
        // paths now point at the user's directory, nothing at the root one
        for f in ["config.toml", "agent.toml"] {
            let t = std::fs::read_to_string(user.join(f)).unwrap();
            assert!(
                t.contains(&format!("{}/identity.json", user.display())),
                "{f}: {t}"
            );
            assert!(!t.contains(&legacy_dir.display().to_string()), "{f}: {t}");
        }
        assert!(std::fs::read_to_string(user.join("agent.toml"))
            .unwrap()
            .contains("127.0.0.55:15353"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(user.join("identity.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(super::super::daemon::enrollment_is_complete(
            &user.join("identity.json")
        ));

        // Done: the user's config is now the newer one, nothing more to ask.
        assert_eq!(candidate(&legacy_dir, &user), None);
        // The same account asking again (lost reply) is still served...
        assert!(serve(&legacy_dir, 501, &r, |_| true).is_ok());
        // ...another account is not.
        let e = serve(&legacy_dir, 502, &r, |_| true).unwrap_err();
        assert!(e.contains("another account"), "{e}");
    }

    #[test]
    fn nothing_is_asked_without_a_root_enrollment() {
        let tmp = tempfile::tempdir().unwrap();
        let user = tmp.path().join(".ztlp");
        assert_eq!(candidate(&tmp.path().join("none"), &user), None);
        // identity.json alone (failed setup) is not an enrollment
        let d = tmp.path().join("half");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("identity.json"), identity(LEGACY_ID)).unwrap();
        assert_eq!(candidate(&d, &user), None);
        assert!(serve(&d, 501, &req(None, 0), |_| true).is_err());
    }

    /// The build Mac: its user enrolled again after the upgrade, so the
    /// root files are the stale ones. They must not replace the new
    /// enrollment.
    #[test]
    fn a_newer_user_enrollment_is_never_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy_dir = legacy(tmp.path());
        let user = tmp.path().join("home").join(".ztlp");
        std::fs::create_dir_all(&user).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(user.join("config.toml"), "zone = \"trs.ztlp\"\n").unwrap();
        assert_eq!(candidate(&legacy_dir, &user), None);
        let now = mtime_secs(&user.join("config.toml"));
        let e = serve(&legacy_dir, 501, &req(None, now), |_| true).unwrap_err();
        assert!(e.contains("newer"), "{e}");
        assert!(!legacy_dir.join(MARKER_FILE).exists());
    }

    #[test]
    fn service_refusals() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy_dir = legacy(tmp.path());
        // a standard account never gets the machine's key
        let e = serve(&legacy_dir, 502, &req(None, 0), |_| false).unwrap_err();
        assert!(e.contains("administrator"), "{e}");
        // the account already runs that identity (fixed by hand earlier)
        let e = serve(&legacy_dir, 501, &req(Some(LEGACY_ID), 0), |_| true).unwrap_err();
        assert!(e.contains("already runs"), "{e}");
        assert!(
            !legacy_dir.join(MARKER_FILE).exists(),
            "refusals leave no marker"
        );
        // the old agent used an identity elsewhere: this dir was never live
        std::fs::write(
            legacy_dir.join("agent.toml"),
            "[identity]\npath = \"/Users/someone/.ztlp/identity.json\"\n",
        )
        .unwrap();
        let e = serve(&legacy_dir, 501, &req(None, 0), |_| true).unwrap_err();
        assert!(e.contains("outside"), "{e}");
    }

    /// Through a real broker socket, the way the agent does it at start.
    #[test]
    fn migrate_over_the_broker_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy_dir = legacy(tmp.path());
        let user = tmp.path().join("home").join(".ztlp");
        let sock = tmp.path().join("b.sock");
        let (l2, s2) = (legacy_dir.clone(), sock.clone());
        std::thread::spawn(move || {
            let _ = super::super::port_broker::run_broker_with(
                &s2,
                |_| {},
                move |uid, line| {
                    let req = match MigrateRequest::parse(line)? {
                        Ok(r) => r,
                        Err(e) => return Some(Err(e)),
                    };
                    Some(serve(&l2, uid, &req, |_| true).map(|b| b.encode()))
                },
            );
        });
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let msg = migrate_if_needed(&legacy_dir, &user, &sock, std::time::Duration::from_secs(5))
            .expect("something to report");
        assert!(msg.starts_with("took over"), "{msg}");
        let id = std::fs::read(user.join("identity.json")).unwrap();
        assert_eq!(node_id_of(&id).as_deref(), Some(LEGACY_ID));
        // second start: nothing to do, nothing asked
        assert_eq!(
            migrate_if_needed(&legacy_dir, &user, &sock, std::time::Duration::from_secs(1)),
            None
        );
        // BIND still works on the same socket and is still policed
        let err = super::super::port_broker::request_listener(
            &sock,
            &super::super::port_broker::BindRequest {
                ip: std::net::Ipv4Addr::new(10, 0, 0, 5),
                port: 443,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a ZTLP VIP"), "{err}");
    }

    /// A machine service from before `MIGRATE` answers "bad request": the
    /// agent must carry on (and ask again at its next start).
    #[test]
    fn an_old_service_refuses_and_the_agent_carries_on() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy_dir = legacy(tmp.path());
        let user = tmp.path().join("home").join(".ztlp");
        let sock = tmp.path().join("b.sock");
        let s2 = sock.clone();
        std::thread::spawn(move || {
            let _ = super::super::port_broker::run_broker(&s2, |_| {});
        });
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let msg = migrate_if_needed(&legacy_dir, &user, &sock, std::time::Duration::from_secs(5))
            .expect("refusal is reported");
        assert!(msg.contains("not taken over"), "{msg}");
        assert!(!user.join("identity.json").exists());
    }
}
