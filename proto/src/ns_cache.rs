//! Signed-record cache (NS-anchored gateway trust, Phase 2).
//!
//! Stores the raw `Record.encode` bytes of verified NS answers so a device
//! can keep dialing while the name server is unreachable, and so a replayed
//! older record (lower serial) is refused.
//!
//! Layout under `dir`:
//! - `<sanitized name>.<type>.rec`    raw `Record.encode` bytes
//! - `<sanitized name>.<type>.serial` highest serial ever accepted (decimal);
//!   kept after the record expires so a replay of an older, still-unexpired
//!   record is refused even after the newer one aged out.
//!
//! Every read verifies again (signature, trusted signer, expiry, name/type
//! match): the cache is a convenience, never a trust source. A tampered or
//! expired file reads as a miss and is deleted.

use crate::ns_verify::{self, VerifiedRecord};
use std::path::{Path, PathBuf};

/// Why `put` refused to store a record.
#[derive(Debug)]
pub enum CacheError {
    /// The bytes did not parse/verify.
    Verify(ns_verify::NsVerifyError),
    /// A record with a higher serial was already accepted (replay guard).
    Replay { stored: u64, offered: u64 },
    /// Filesystem error.
    Io(std::io::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verify(e) => write!(f, "{e}"),
            Self::Replay { stored, offered } => write!(
                f,
                "NS record serial {offered} is older than the accepted serial {stored} (replay?)"
            ),
            Self::Io(e) => write!(f, "NS cache I/O: {e}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Default cache directory: `$HOME/.ztlp/ns_cache` (same base as quic_pins).
pub fn default_dir() -> PathBuf {
    #[cfg(feature = "tokio-runtime")]
    let home = dirs::home_dir();
    #[cfg(not(feature = "tokio-runtime"))]
    let home = std::env::var_os("HOME").map(PathBuf::from);
    home.map(|h| h.join(".ztlp").join("ns_cache"))
        .unwrap_or_else(|| PathBuf::from(".ztlp/ns_cache"))
}

/// File stem for `name`/`type_byte`. Keeps `[A-Za-z0-9-_]`, maps every
/// other byte (including `.`, `/`, `\`, NUL) to `_`, and appends a short
/// hash of the exact name so the stem is always one plain filename (never
/// `.`/`..`/absolute) and distinct names rarely share a slot. A shared slot
/// is still safe: `get` checks the stored record's name.
fn stem(name: &str, type_byte: u8) -> String {
    use sha2::Digest;
    let readable: String = name
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let h = sha2::Sha256::digest(name.as_bytes());
    format!("n_{readable}_{}.{type_byte}", hex::encode(&h[..6]))
}

fn rec_path(dir: &Path, name: &str, type_byte: u8) -> PathBuf {
    dir.join(format!("{}.rec", stem(name, type_byte)))
}

fn serial_path(dir: &Path, name: &str, type_byte: u8) -> PathBuf {
    dir.join(format!("{}.serial", stem(name, type_byte)))
}

/// Write via a temp file + rename so a crash never leaves a half file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Verify `raw` (`Record.encode` bytes) and store it, refusing a lower
/// serial than one already accepted for the same name and type.
pub fn put(
    dir: &Path,
    raw: &[u8],
    anchors: &[[u8; 32]],
    now: u64,
) -> Result<VerifiedRecord, CacheError> {
    let parsed = ns_verify::parse_signed_record(raw).map_err(CacheError::Verify)?;
    let rec = ns_verify::verify(&parsed, anchors, now).map_err(CacheError::Verify)?;
    if let Some(stored) = highest_serial_seen(dir, &rec.name, rec.type_byte) {
        if rec.serial < stored {
            return Err(CacheError::Replay {
                stored,
                offered: rec.serial,
            });
        }
    }
    std::fs::create_dir_all(dir)?;
    // Watermark first: if the record write fails, a replay is still refused.
    write_atomic(
        &serial_path(dir, &rec.name, rec.type_byte),
        rec.serial.to_string().as_bytes(),
    )?;
    write_atomic(&rec_path(dir, &rec.name, rec.type_byte), raw)?;
    Ok(rec)
}

/// Cached record for `name`/`type_byte`, verified again against `anchors`
/// at `now`. Expired or tampered entries return `None` and are deleted.
pub fn get(
    dir: &Path,
    name: &str,
    type_byte: u8,
    anchors: &[[u8; 32]],
    now: u64,
) -> Option<VerifiedRecord> {
    let path = rec_path(dir, name, type_byte);
    let raw = std::fs::read(&path).ok()?;
    let ok = ns_verify::parse_signed_record(&raw)
        .ok()
        .filter(|p| p.name == name && p.type_byte == type_byte)
        .map(|p| ns_verify::verify(&p, anchors, now));
    match ok {
        Some(Ok(rec)) => Some(rec),
        // Untrusted signer: trust was withdrawn, but the bytes are genuine;
        // keep the file (trust may come back) and report a miss.
        Some(Err(ns_verify::NsVerifyError::UntrustedSigner)) => None,
        // Another name in this slot: not ours to delete.
        None if ns_verify::parse_signed_record(&raw).is_ok() => None,
        // Expired, tampered, or unparseable: delete.
        _ => {
            let _ = std::fs::remove_file(&path);
            None
        }
    }
}

/// Highest serial ever accepted for `name`/`type_byte` (survives expiry).
pub fn highest_serial_seen(dir: &Path, name: &str, type_byte: u8) -> Option<u64> {
    std::fs::read_to_string(serial_path(dir, name, type_byte))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Drop the cached record (not the serial watermark), e.g. before a forced
/// fresh lookup after a fingerprint mismatch.
pub fn evict(dir: &Path, name: &str, type_byte: u8) {
    let _ = std::fs::remove_file(rec_path(dir, name, type_byte));
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    const NOW: u64 = 1_800_000_100;

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    /// Build `Record.encode` bytes exactly like the NS (layout pinned
    /// against the Elixir golden vector by `golden_fixture_round_trips`).
    fn encode(
        sk: &ed25519_dalek::SigningKey,
        name: &str,
        created_at: u64,
        ttl: u32,
        serial: u64,
    ) -> Vec<u8> {
        // CBOR {"quic_cert_sha256": "<serial>"}
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(
            &ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Text("quic_cert_sha256".into()),
                ciborium::value::Value::Text(format!("fp{serial}")),
            )]),
            &mut cbor,
        )
        .unwrap();
        let mut c = vec![2u8];
        c.extend_from_slice(&(name.len() as u16).to_be_bytes());
        c.extend_from_slice(name.as_bytes());
        c.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
        c.extend_from_slice(&cbor);
        c.extend_from_slice(&created_at.to_be_bytes());
        c.extend_from_slice(&ttl.to_be_bytes());
        c.extend_from_slice(&serial.to_be_bytes());
        let sig = sk.sign(&c).to_bytes();
        c.extend_from_slice(&64u16.to_be_bytes());
        c.extend_from_slice(&sig);
        c.extend_from_slice(&32u16.to_be_bytes());
        c.extend_from_slice(&sk.verifying_key().to_bytes());
        c
    }

    fn anchors() -> Vec<[u8; 32]> {
        vec![key(1).verifying_key().to_bytes()]
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn golden_fixture_round_trips() {
        let raw =
            hex::decode(include_str!("../tests/fixtures/ns_signed_svc_record.hex").trim()).unwrap();
        let anchor: [u8; 32] =
            hex::decode(include_str!("../tests/fixtures/ns_signed_svc_record.pub").trim())
                .unwrap()
                .try_into()
                .unwrap();
        let d = tmp();
        let put_rec = put(d.path(), &raw, &[anchor], NOW).unwrap();
        let got = get(d.path(), "www.chooseforce.ztlp", 2, &[anchor], NOW).unwrap();
        assert_eq!(put_rec, got);
        assert_eq!(
            highest_serial_seen(d.path(), "www.chooseforce.ztlp", 2),
            Some(1_800_000_000)
        );
    }

    #[test]
    fn round_trip() {
        let d = tmp();
        let raw = encode(&key(1), "www.a.ztlp", NOW - 10, 3600, 5);
        put(d.path(), &raw, &anchors(), NOW).unwrap();
        let got = get(d.path(), "www.a.ztlp", 2, &anchors(), NOW).unwrap();
        assert_eq!(got.serial, 5);
        assert_eq!(got.data_str("quic_cert_sha256").as_deref(), Some("fp5"));
        assert!(
            get(d.path(), "www.a.ztlp", 1, &anchors(), NOW).is_none(),
            "type is part of the key"
        );
        assert!(get(d.path(), "www.b.ztlp", 2, &anchors(), NOW).is_none());
    }

    #[test]
    fn put_refuses_unverifiable_bytes() {
        let d = tmp();
        let raw = encode(&key(2), "www.a.ztlp", NOW - 10, 3600, 5);
        assert!(matches!(
            put(d.path(), &raw, &anchors(), NOW),
            Err(CacheError::Verify(
                ns_verify::NsVerifyError::UntrustedSigner
            ))
        ));
        let expired = encode(&key(1), "www.a.ztlp", NOW - 7200, 3600, 5);
        assert!(matches!(
            put(d.path(), &expired, &anchors(), NOW),
            Err(CacheError::Verify(ns_verify::NsVerifyError::Expired))
        ));
        assert!(get(d.path(), "www.a.ztlp", 2, &anchors(), NOW).is_none());
    }

    #[test]
    fn expired_entry_is_a_miss_and_is_deleted() {
        let d = tmp();
        let raw = encode(&key(1), "www.a.ztlp", NOW - 10, 60, 5);
        put(d.path(), &raw, &anchors(), NOW).unwrap();
        assert!(get(d.path(), "www.a.ztlp", 2, &anchors(), NOW + 60).is_none());
        let files: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(!files.iter().any(|f| f.ends_with(".rec")), "{files:?}");
        // The watermark survives expiry.
        assert_eq!(highest_serial_seen(d.path(), "www.a.ztlp", 2), Some(5));
    }

    #[test]
    fn lower_serial_is_refused_even_after_the_newer_one_expired() {
        let d = tmp();
        let old = encode(&key(1), "www.a.ztlp", NOW - 10, 86_400, 4);
        let new = encode(&key(1), "www.a.ztlp", NOW - 10, 60, 5);
        put(d.path(), &new, &anchors(), NOW).unwrap();
        assert!(matches!(
            put(d.path(), &old, &anchors(), NOW),
            Err(CacheError::Replay {
                stored: 5,
                offered: 4
            })
        ));
        // Newer one ages out; the old (still unexpired) one must stay refused.
        assert!(get(d.path(), "www.a.ztlp", 2, &anchors(), NOW + 100).is_none());
        assert!(matches!(
            put(d.path(), &old, &anchors(), NOW + 100),
            Err(CacheError::Replay { .. })
        ));
    }

    #[test]
    fn equal_and_higher_serials_are_accepted() {
        let d = tmp();
        let a = encode(&key(1), "www.a.ztlp", NOW - 10, 3600, 5);
        let b = encode(&key(1), "www.a.ztlp", NOW - 5, 3600, 6);
        put(d.path(), &a, &anchors(), NOW).unwrap();
        put(d.path(), &a, &anchors(), NOW).unwrap();
        put(d.path(), &b, &anchors(), NOW).unwrap();
        assert_eq!(
            get(d.path(), "www.a.ztlp", 2, &anchors(), NOW)
                .unwrap()
                .serial,
            6
        );
        assert_eq!(highest_serial_seen(d.path(), "www.a.ztlp", 2), Some(6));
    }

    #[test]
    fn tampered_file_is_a_miss_and_is_deleted() {
        let d = tmp();
        let raw = encode(&key(1), "www.a.ztlp", NOW - 10, 3600, 5);
        put(d.path(), &raw, &anchors(), NOW).unwrap();
        let rec_file = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().map(|x| x == "rec").unwrap_or(false))
            .unwrap();
        let mut bytes = std::fs::read(&rec_file).unwrap();
        let mid = bytes.len() / 3;
        bytes[mid] ^= 0xff;
        std::fs::write(&rec_file, &bytes).unwrap();
        assert!(get(d.path(), "www.a.ztlp", 2, &anchors(), NOW).is_none());
        assert!(!rec_file.exists());
    }

    #[test]
    fn anchors_are_rechecked_on_read() {
        // Trust removed (e.g. server dropped from the NSSET) -> cache miss.
        let d = tmp();
        let raw = encode(&key(1), "www.a.ztlp", NOW - 10, 3600, 5);
        put(d.path(), &raw, &anchors(), NOW).unwrap();
        let other = vec![key(3).verifying_key().to_bytes()];
        assert!(get(d.path(), "www.a.ztlp", 2, &other, NOW).is_none());
    }

    #[test]
    fn a_record_for_another_name_in_the_slot_is_a_miss() {
        // Two names that sanitize to the same file must not answer for each other.
        let d = tmp();
        let raw = encode(&key(1), "a/b.ztlp", NOW - 10, 3600, 5);
        put(d.path(), &raw, &anchors(), NOW).unwrap();
        assert!(get(d.path(), "a_b.ztlp", 2, &anchors(), NOW).is_none());
        assert!(get(d.path(), "a/b.ztlp", 2, &anchors(), NOW).is_some());
    }

    #[test]
    fn traversal_names_stay_inside_the_cache_dir() {
        let root = tmp();
        let d = root.path().join("cache");
        for name in [
            "../../etc/passwd",
            "..",
            ".",
            "/abs/path",
            "a\\..\\b",
            "x\0y",
        ] {
            let raw = encode(&key(1), name, NOW - 10, 3600, 5);
            put(&d, &raw, &anchors(), NOW).unwrap();
            assert!(get(&d, name, 2, &anchors(), NOW).is_some(), "{name:?}");
        }
        // Nothing was written outside `d`.
        let outside: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(outside, vec![std::ffi::OsString::from("cache")]);
        for e in std::fs::read_dir(&d).unwrap() {
            assert!(e.unwrap().file_type().unwrap().is_file());
        }
    }

    #[test]
    fn evict_drops_the_record_but_keeps_the_watermark() {
        let d = tmp();
        let raw = encode(&key(1), "www.a.ztlp", NOW - 10, 3600, 5);
        put(d.path(), &raw, &anchors(), NOW).unwrap();
        evict(d.path(), "www.a.ztlp", 2);
        assert!(get(d.path(), "www.a.ztlp", 2, &anchors(), NOW).is_none());
        assert_eq!(highest_serial_seen(d.path(), "www.a.ztlp", 2), Some(5));
        evict(d.path(), "never.cached", 2); // no panic
    }

    #[test]
    fn missing_dir_is_a_miss_not_an_error() {
        let d = tmp();
        let nope = d.path().join("nope");
        assert!(get(&nope, "www.a.ztlp", 2, &anchors(), NOW).is_none());
        assert_eq!(highest_serial_seen(&nope, "www.a.ztlp", 2), None);
    }

    #[test]
    #[cfg(feature = "tokio-runtime")]
    fn default_dir_is_under_home_ztlp() {
        let d = default_dir();
        assert!(d.ends_with(".ztlp/ns_cache"), "{}", d.display());
        if let Some(h) = dirs::home_dir() {
            assert!(d.starts_with(h));
        }
    }
}
