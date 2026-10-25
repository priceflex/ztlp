//! Trusted name-server keys (NS-anchored gateway trust, Phase 2).
//!
//! Machine-managed file `~/.ztlp/ns_trust.toml`, next to `agent.toml`:
//!
//! ```toml
//! # Managed by ztlp (enrollment token + home-signed NSSET). Do not edit.
//! [[server]]
//! addr  = "44.227.148.151:23096"
//! key   = "<64 hex Ed25519 public key>"
//! zones = ["trs.ztlp", "chooseforce.ztlp"]
//! home  = true
//! ```
//!
//! Kept out of `agent.toml` on purpose: that file is generated from a
//! hand-formatted template and hand-tuned by operators (NSSET updates would
//! have to rewrite it hourly), and any parse error there silently falls back
//! to defaults, which would quietly turn strict mode off. Here a malformed
//! file is an error the caller must surface, never "no trust".
//!
//! `strict` is derived, not configured: a device is strict for a name as
//! soon as it trusts ANY key for a zone covering that name.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One trusted name server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsServerTrust {
    pub addr: String,
    pub key: [u8; 32],
    /// Zones this server's key is trusted for (lowercase, no trailing dot).
    pub zones: Vec<String>,
    /// The device's home server (key from the enrollment token). Only the
    /// home key may vouch for other servers (NSSET, Phase 3).
    pub home: bool,
}

/// All trusted name servers of this device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NsTrustStore {
    pub servers: Vec<NsServerTrust>,
}

/// Error loading the trust file. A present-but-bad file must not read as
/// "no trust" (that would silently disable strict mode).
#[derive(Debug)]
pub enum NsTrustError {
    Io(std::io::Error),
    Parse(String),
}

impl std::fmt::Display for NsTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ns_trust.toml: {e}"),
            Self::Parse(e) => write!(f, "ns_trust.toml is invalid: {e}"),
        }
    }
}

impl std::error::Error for NsTrustError {}

pub const FILE_NAME: &str = "ns_trust.toml";

/// `~/.ztlp/ns_trust.toml`.
pub fn default_path() -> PathBuf {
    super::config::ztlp_state_dir()
        .join(".ztlp")
        .join(FILE_NAME)
}

fn normalize_zone(z: &str) -> String {
    z.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `name` is `zone` or a label-aligned subdomain of it.
fn zone_covers(zone: &str, name: &str) -> bool {
    let name = normalize_zone(name);
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

impl NsTrustStore {
    /// Load `path`. Missing file = empty store (legacy device). Present but
    /// unreadable or malformed = error.
    pub fn load(path: &Path) -> Result<Self, NsTrustError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(NsTrustError::Io(e)),
        }
    }

    /// Parse TOML text.
    pub fn from_toml(text: &str) -> Result<Self, NsTrustError> {
        let repr: FileRepr =
            toml::from_str(text).map_err(|e| NsTrustError::Parse(e.to_string()))?;
        let mut servers = Vec::with_capacity(repr.server.len());
        for (i, r) in repr.server.into_iter().enumerate() {
            let key: [u8; 32] = hex::decode(r.key.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    NsTrustError::Parse(format!(
                        "server {} ({}): key must be 64 hex chars",
                        i + 1,
                        r.addr
                    ))
                })?;
            let zones: Vec<String> = r
                .zones
                .iter()
                .map(|z| normalize_zone(z))
                .filter(|z| !z.is_empty())
                .collect();
            if zones.is_empty() {
                return Err(NsTrustError::Parse(format!(
                    "server {} ({}): zones must not be empty",
                    i + 1,
                    r.addr
                )));
            }
            servers.push(NsServerTrust {
                addr: r.addr,
                key,
                zones,
                home: r.home,
            });
        }
        if servers.iter().filter(|s| s.home).count() > 1 {
            return Err(NsTrustError::Parse("more than one home server".into()));
        }
        Ok(Self { servers })
    }

    /// Serialize to TOML text (with the "managed" header).
    pub fn to_toml(&self) -> String {
        let repr = FileRepr {
            server: self
                .servers
                .iter()
                .map(|s| ServerRepr {
                    addr: s.addr.clone(),
                    key: hex::encode(s.key),
                    zones: s.zones.clone(),
                    home: s.home,
                })
                .collect(),
        };
        let body = toml::to_string(&repr).expect("plain strings/bools always serialize");
        format!("# Managed by ztlp (enrollment token + home-signed NSSET). Do not edit.\n\n{body}")
    }

    /// Atomically write `path` (temp file + rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension(format!("toml.tmp{}", std::process::id()));
        std::fs::write(&tmp, self.to_toml())?;
        std::fs::rename(&tmp, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }

    /// The home server, if enrolled with a name-server key.
    pub fn home(&self) -> Option<&NsServerTrust> {
        self.servers.iter().find(|s| s.home)
    }

    /// True iff some trusted server lists a zone covering `name`.
    pub fn strict_for(&self, name: &str) -> bool {
        self.servers
            .iter()
            .any(|s| s.zones.iter().any(|z| zone_covers(z, name)))
    }

    /// Keys trusted for `name` (every server whose zones cover it).
    pub fn anchors_for(&self, name: &str) -> Vec<[u8; 32]> {
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for s in &self.servers {
            if s.zones.iter().any(|z| zone_covers(z, name)) && !keys.contains(&s.key) {
                keys.push(s.key);
            }
        }
        keys
    }
}

/// `ns_trust.toml` at the default path, re-read only when its mtime
/// changes (the dial path consults it per connection). A missing file is
/// the empty legacy store; an unreadable/malformed file is returned as an
/// error every time (never silently "no trust").
pub fn load_cached() -> Result<NsTrustStore, String> {
    load_cached_from(&default_path())
}

/// [`load_cached`] for an explicit path (tests).
pub fn load_cached_from(path: &Path) -> Result<NsTrustStore, String> {
    type Slot = Option<(PathBuf, Option<std::time::SystemTime>, NsTrustStore)>;
    static CACHE: std::sync::Mutex<Slot> = std::sync::Mutex::new(None);
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    if let Ok(g) = CACHE.lock() {
        if let Some((p, m, store)) = g.as_ref() {
            if p == path && *m == mtime && mtime.is_some() {
                return Ok(store.clone());
            }
        }
    }
    let store = NsTrustStore::load(path).map_err(|e| e.to_string())?;
    if let Ok(mut g) = CACHE.lock() {
        *g = Some((path.to_path_buf(), mtime, store.clone()));
    }
    Ok(store)
}

/// Summary of a device's name-server trust, for logs and `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    /// Enrolled with a name-server key: answers are verified.
    Verified { home: String, servers: usize },
    /// No key (token without 0x10): legacy, answers are not verified.
    Legacy,
    /// The trust file exists but cannot be used.
    Invalid(String),
}

impl TrustStatus {
    /// Classify a `load` result.
    pub fn of(loaded: &Result<NsTrustStore, NsTrustError>) -> Self {
        match loaded {
            Ok(s) => match s.home() {
                Some(h) => Self::Verified {
                    home: h.addr.clone(),
                    servers: s.servers.len(),
                },
                None => Self::Legacy,
            },
            Err(e) => Self::Invalid(e.to_string()),
        }
    }

    /// Short machine value for `status` JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::Legacy => "legacy",
            Self::Invalid(_) => "invalid",
        }
    }

    /// Human message for the agent's startup log.
    pub fn message(&self) -> String {
        match self {
            Self::Verified { home, servers } => format!(
                "name-server answers are verified (home {home}, {servers} trusted server(s))"
            ),
            Self::Legacy => "enrolled without a name-server key: name-server answers are NOT \
                 verified. Re-enroll with a token made by `ztlp admin enroll --ns-key`."
                .to_string(),
            Self::Invalid(e) => format!("name-server trust file unusable: {e}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FileRepr {
    #[serde(default)]
    server: Vec<ServerRepr>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerRepr {
    addr: String,
    key: String,
    zones: Vec<String>,
    #[serde(default)]
    home: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
    const K2: &str = "73193631c65c8252184a64b419dc1b5007021ba70eb531697f9b816596d986c9";

    fn key(h: &str) -> [u8; 32] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    fn sample() -> String {
        format!(
            r#"
[[server]]
addr  = "44.227.148.151:23096"
key   = "{K1}"
zones = ["trs.ztlp", "ChooseForce.ztlp."]
home  = true

[[server]]
addr  = "44.230.7.100:23096"
key   = "{K2}"
zones = ["customers.ztlp"]
"#
        )
    }

    #[test]
    fn parses_servers_and_normalizes_zones() {
        let s = NsTrustStore::from_toml(&sample()).unwrap();
        assert_eq!(s.servers.len(), 2);
        assert_eq!(s.servers[0].key, key(K1));
        assert_eq!(s.servers[0].zones, vec!["trs.ztlp", "chooseforce.ztlp"]);
        assert!(s.servers[0].home);
        assert!(!s.servers[1].home, "home defaults to false");
        assert_eq!(s.home().unwrap().addr, "44.227.148.151:23096");
    }

    #[test]
    fn toml_round_trip() {
        let s = NsTrustStore::from_toml(&sample()).unwrap();
        let text = s.to_toml();
        assert!(text.starts_with("# Managed by ztlp"), "{text}");
        assert_eq!(NsTrustStore::from_toml(&text).unwrap(), s);
    }

    #[test]
    fn save_and_load_round_trip_atomically() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(FILE_NAME);
        let s = NsTrustStore::from_toml(&sample()).unwrap();
        s.save(&p).unwrap();
        assert_eq!(NsTrustStore::load(&p).unwrap(), s);
        let leftovers: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from(FILE_NAME)]);
    }

    #[test]
    fn missing_file_is_an_empty_legacy_store() {
        let d = tempfile::tempdir().unwrap();
        let s = NsTrustStore::load(&d.path().join(FILE_NAME)).unwrap();
        assert!(s.servers.is_empty());
        assert!(!s.strict_for("www.chooseforce.ztlp"));
        assert!(s.home().is_none());
    }

    #[test]
    fn empty_file_is_an_empty_store() {
        assert!(NsTrustStore::from_toml("").unwrap().servers.is_empty());
    }

    #[test]
    fn malformed_file_is_an_error_not_an_empty_store() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(FILE_NAME);
        std::fs::write(&p, "[[server]\naddr = ").unwrap();
        assert!(matches!(
            NsTrustStore::load(&p),
            Err(NsTrustError::Parse(_))
        ));
    }

    #[test]
    fn bad_keys_are_errors() {
        for bad in ["abcd", &"zz".repeat(32), &"ab".repeat(33), ""] {
            let t = format!("[[server]]\naddr = \"a:1\"\nkey = \"{bad}\"\nzones = [\"x.ztlp\"]\n");
            assert!(NsTrustStore::from_toml(&t).is_err(), "key {bad:?} accepted");
        }
    }

    #[test]
    fn unknown_fields_are_errors() {
        // A typo like `zone =` must not silently mean "trusted for nothing".
        let t = format!("[[server]]\naddr = \"a:1\"\nkey = \"{K1}\"\nzone = [\"x.ztlp\"]\n");
        assert!(NsTrustStore::from_toml(&t).is_err());
    }

    #[test]
    fn server_without_zones_is_an_error() {
        let t = format!("[[server]]\naddr = \"a:1\"\nkey = \"{K1}\"\nzones = []\n");
        assert!(NsTrustStore::from_toml(&t).is_err());
    }

    #[test]
    fn at_most_one_home_server() {
        let t = format!(
            "[[server]]\naddr = \"a:1\"\nkey = \"{K1}\"\nzones = [\"a.ztlp\"]\nhome = true\n\
             [[server]]\naddr = \"b:1\"\nkey = \"{K2}\"\nzones = [\"b.ztlp\"]\nhome = true\n"
        );
        assert!(NsTrustStore::from_toml(&t).is_err());
    }

    #[test]
    fn strict_and_anchors_follow_zone_suffixes() {
        let s = NsTrustStore::from_toml(&sample()).unwrap();
        assert!(s.strict_for("www.chooseforce.ztlp"));
        assert!(s.strict_for("WWW.ChooseForce.ztlp."));
        assert!(s.strict_for("chooseforce.ztlp"), "the zone apex itself");
        assert!(s.strict_for("_ns.trs.ztlp"));
        assert!(
            !s.strict_for("evilchooseforce.ztlp"),
            "suffix must be label-aligned"
        );
        assert!(!s.strict_for("www.other.ztlp"));
        assert_eq!(s.anchors_for("www.chooseforce.ztlp"), vec![key(K1)]);
        assert_eq!(s.anchors_for("x.customers.ztlp"), vec![key(K2)]);
        assert!(s.anchors_for("www.other.ztlp").is_empty());
    }

    #[test]
    fn a_zone_listed_by_two_servers_trusts_both_keys_once_each() {
        let t = format!(
            "[[server]]\naddr = \"a:1\"\nkey = \"{K1}\"\nzones = [\"a.ztlp\"]\nhome = true\n\
             [[server]]\naddr = \"b:1\"\nkey = \"{K2}\"\nzones = [\"a.ztlp\"]\n\
             [[server]]\naddr = \"c:1\"\nkey = \"{K2}\"\nzones = [\"a.ztlp\"]\n"
        );
        let s = NsTrustStore::from_toml(&t).unwrap();
        assert_eq!(s.anchors_for("w.a.ztlp"), vec![key(K1), key(K2)]);
    }

    #[test]
    fn trust_status_classifies_load_results() {
        let s = NsTrustStore::from_toml(&sample()).unwrap();
        let v = TrustStatus::of(&Ok(s));
        assert_eq!(v.as_str(), "verified");
        assert!(v.message().contains("44.227.148.151:23096"));
        let l = TrustStatus::of(&Ok(NsTrustStore::default()));
        assert_eq!(l, TrustStatus::Legacy);
        assert!(l.message().contains("re-enroll") || l.message().contains("Re-enroll"));
        let i = TrustStatus::of(&Err(NsTrustError::Parse("x".into())));
        assert_eq!(i.as_str(), "invalid");
    }

    #[test]
    fn default_path_is_next_to_agent_toml() {
        let p = default_path();
        assert!(p.ends_with(".ztlp/ns_trust.toml"), "{}", p.display());
    }
}
