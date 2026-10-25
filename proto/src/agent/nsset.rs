//! NSSET consumption (NS-anchored gateway trust, task 3.3).
//!
//! The home name server publishes, per zone it is home for, a signed
//! OPERATOR record (type 0x07) at the zone apex listing the name servers
//! (address + Ed25519 key) a client may trust for that zone
//! (`ns/lib/ztlp_ns/nsset_seeder.ex`). The agent refreshes it at every
//! hourly check-in and rewrites `ns_trust.toml`:
//!
//! - accepted only when signed by the HOME key (from the enrollment token);
//! - only for zones the home server itself is trusted for;
//! - an NSSET is authoritative for exactly its own zone: servers dropped
//!   from it lose trust for that zone (fleet-wide within an hour);
//! - replays (lower serial) are refused by the signed-record cache.

use super::ns_trust::{NsServerTrust, NsTrustStore};
use crate::ns_verify::VerifiedRecord;

/// Record type of the NSSET (OPERATOR).
pub const NSSET_RECORD_TYPE: u8 = 0x07;

/// Why an NSSET was not merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NssetError {
    /// Device has no home name server (enrolled without an NS key).
    NoHome,
    /// Not signed by the home key.
    NotHomeSigned,
    /// Record is not an NSSET (type / kind / shape).
    NotNsset(String),
    /// The NSSET's zone is not one the home server is trusted for.
    ZoneOutOfScope(String),
}

impl std::fmt::Display for NssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHome => write!(
                f,
                "no home name server (enrolled without a name-server key)"
            ),
            Self::NotHomeSigned => write!(f, "NSSET is not signed by the home name-server key"),
            Self::NotNsset(why) => write!(f, "not an NSSET record: {why}"),
            Self::ZoneOutOfScope(z) => {
                write!(
                    f,
                    "NSSET for zone '{z}', which the home name server is not trusted for"
                )
            }
        }
    }
}

impl std::error::Error for NssetError {}

/// One server entry of an NSSET.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    addr: String,
    key: [u8; 32],
}

fn parse_entries(rec: &VerifiedRecord) -> Result<(String, Vec<Entry>), NssetError> {
    use ciborium::value::Value;
    let bad = |m: &str| NssetError::NotNsset(m.to_string());
    if rec.type_byte != NSSET_RECORD_TYPE {
        return Err(bad("wrong record type"));
    }
    let v: Value = ciborium::de::from_reader(rec.data_cbor.as_slice()).map_err(|_| bad("CBOR"))?;
    let map = v.as_map().ok_or_else(|| bad("data is not a map"))?;
    let get = |k: &str| {
        map.iter()
            .find(|(mk, _)| mk.as_text() == Some(k))
            .map(|(_, mv)| mv)
    };
    if get("kind").and_then(|v| v.as_text()) != Some("nsset") {
        return Err(bad("kind != nsset"));
    }
    let zone = rec.name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(z) = get("zone").and_then(|v| v.as_text()) {
        if z.trim_end_matches('.').to_ascii_lowercase() != zone {
            return Err(bad("zone field does not match the record name"));
        }
    }
    let servers = get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| bad("missing servers"))?;
    let mut out = Vec::new();
    for s in servers {
        let m = s.as_map().ok_or_else(|| bad("server entry is not a map"))?;
        let field = |k: &str| {
            m.iter()
                .find(|(mk, _)| mk.as_text() == Some(k))
                .and_then(|(_, mv)| mv.as_text())
        };
        let addr = field("addr").ok_or_else(|| bad("server without addr"))?;
        let key: [u8; 32] = field("pubkey")
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("server pubkey is not 64 hex"))?;
        out.push(Entry {
            addr: addr.to_string(),
            key,
        });
    }
    Ok((zone, out))
}

/// Merge a verified NSSET into `store` (pure). Returns the new store.
pub fn merge_nsset(
    store: &NsTrustStore,
    nsset: &VerifiedRecord,
) -> Result<NsTrustStore, NssetError> {
    let home = store.home().ok_or(NssetError::NoHome)?.clone();
    if nsset.signer != home.key {
        return Err(NssetError::NotHomeSigned);
    }
    let (zone, entries) = parse_entries(nsset)?;
    if !home.zones.iter().any(|z| *z == zone) {
        return Err(NssetError::ZoneOutOfScope(zone));
    }

    // Start from the current peers with this zone removed: the NSSET is the
    // complete list for its zone.
    let mut peers: Vec<NsServerTrust> = store
        .servers
        .iter()
        .filter(|s| !s.home)
        .cloned()
        .map(|mut s| {
            s.zones.retain(|z| *z != zone);
            s
        })
        .collect();

    for e in entries {
        if e.key == home.key {
            continue; // the home server lists itself first
        }
        match peers.iter_mut().find(|p| p.key == e.key) {
            Some(p) => {
                p.addr = e.addr;
                if !p.zones.contains(&zone) {
                    p.zones.push(zone.clone());
                }
            }
            None => peers.push(NsServerTrust {
                addr: e.addr,
                key: e.key,
                zones: vec![zone.clone()],
                home: false,
            }),
        }
    }
    peers.retain(|p| !p.zones.is_empty());

    let mut servers = vec![home];
    servers.extend(peers);
    Ok(NsTrustStore { servers })
}

/// Outcome of one refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// No home server: legacy device, nothing to do.
    NoHome,
    /// Trust file rewritten (servers changed).
    Updated,
    /// Nothing changed.
    Unchanged,
}

/// Query the home NS for the NSSET of every zone it is home for, merge the
/// verified ones and save `trust_path` if anything changed. Errors for a
/// single zone are logged and skipped (the other zones still refresh).
pub async fn refresh_nsset(
    trust_path: &std::path::Path,
    cache_dir: &std::path::Path,
) -> Result<RefreshOutcome, Box<dyn std::error::Error + Send + Sync>> {
    use super::proxy::{ns_query_verified, NsAnswer, NsTrust};

    let original = NsTrustStore::load(trust_path)?;
    let Some(home) = original.home().cloned() else {
        return Ok(RefreshOutcome::NoHome);
    };
    let trust = NsTrust {
        anchors: vec![home.key],
        strict: true,
        cache_dir: Some(cache_dir.to_path_buf()),
    };

    let mut store = original.clone();
    for zone in &home.zones {
        match ns_query_verified(zone, &home.addr, NSSET_RECORD_TYPE, &trust).await {
            Ok(NsAnswer::Verified(rec)) => match merge_nsset(&store, &rec) {
                Ok(next) => store = next,
                Err(e) => tracing::warn!("NSSET for {zone} ignored: {e}"),
            },
            Ok(NsAnswer::NotFound) => {
                tracing::debug!("home NS publishes no NSSET for {zone}")
            }
            Ok(NsAnswer::Unverified(_)) => {
                tracing::warn!("NSSET for {zone} ignored: not verified")
            }
            Err(e) => tracing::warn!("NSSET refresh for {zone} failed: {e}"),
        }
    }

    if store == original {
        return Ok(RefreshOutcome::Unchanged);
    }
    store.save(trust_path)?;
    tracing::info!(
        "name-server trust updated from NSSET: {} server(s)",
        store.servers.len()
    );
    Ok(RefreshOutcome::Updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pk(seed: u8) -> [u8; 32] {
        sk(seed).verifying_key().to_bytes()
    }

    fn home_store(zones: &[&str]) -> NsTrustStore {
        NsTrustStore {
            servers: vec![NsServerTrust {
                addr: "44.227.148.151:23096".into(),
                key: pk(1),
                zones: zones.iter().map(|z| z.to_string()).collect(),
                home: true,
            }],
        }
    }

    fn nsset_cbor(zone: &str, servers: &[(&str, [u8; 32])]) -> Vec<u8> {
        use ciborium::value::Value;
        let list = servers
            .iter()
            .map(|(addr, key)| {
                Value::Map(vec![
                    (Value::Text("addr".into()), Value::Text((*addr).into())),
                    (Value::Text("pubkey".into()), Value::Text(hex::encode(key))),
                    (
                        Value::Text("zones".into()),
                        Value::Array(vec![Value::Text(zone.into())]),
                    ),
                ])
            })
            .collect();
        let mut out = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![
                (Value::Text("kind".into()), Value::Text("nsset".into())),
                (Value::Text("servers".into()), Value::Array(list)),
                (Value::Text("zone".into()), Value::Text(zone.into())),
            ]),
            &mut out,
        )
        .unwrap();
        out
    }

    fn rec(zone: &str, signer: u8, cbor: Vec<u8>, type_byte: u8) -> VerifiedRecord {
        VerifiedRecord {
            type_byte,
            name: zone.into(),
            data_cbor: cbor,
            signer: pk(signer),
            created_at: 0,
            ttl: 86_400,
            serial: 1,
        }
    }

    #[test]
    fn adds_a_replica_for_the_zone_only() {
        let store = home_store(&["trs.ztlp", "chooseforce.ztlp"]);
        let n = rec(
            "trs.ztlp",
            1,
            nsset_cbor(
                "trs.ztlp",
                &[
                    ("44.227.148.151:23096", pk(1)),
                    ("44.230.7.100:23096", pk(2)),
                ],
            ),
            7,
        );
        let out = merge_nsset(&store, &n).unwrap();
        assert_eq!(out.servers.len(), 2);
        assert!(out.servers[0].home, "home stays first and unchanged");
        assert_eq!(out.servers[0], store.servers[0]);
        assert_eq!(out.servers[1].addr, "44.230.7.100:23096");
        assert_eq!(out.servers[1].zones, vec!["trs.ztlp"]);
        assert!(!out.servers[1].home);
        assert_eq!(out.anchors_for("www.trs.ztlp"), vec![pk(1), pk(2)]);
        assert_eq!(out.anchors_for("www.chooseforce.ztlp"), vec![pk(1)]);
    }

    #[test]
    fn a_server_dropped_from_the_nsset_loses_trust_for_that_zone() {
        let store = home_store(&["trs.ztlp", "chooseforce.ztlp"]);
        let both = |z: &str| nsset_cbor(z, &[("h:1", pk(1)), ("r:1", pk(2))]);
        let s1 = merge_nsset(&store, &rec("trs.ztlp", 1, both("trs.ztlp"), 7)).unwrap();
        let s2 = merge_nsset(
            &s1,
            &rec("chooseforce.ztlp", 1, both("chooseforce.ztlp"), 7),
        )
        .unwrap();
        assert_eq!(s2.servers[1].zones, vec!["trs.ztlp", "chooseforce.ztlp"]);

        let only_home = nsset_cbor("trs.ztlp", &[("h:1", pk(1))]);
        let s3 = merge_nsset(&s2, &rec("trs.ztlp", 1, only_home, 7)).unwrap();
        assert_eq!(s3.servers[1].zones, vec!["chooseforce.ztlp"]);
        let only_home_cf = nsset_cbor("chooseforce.ztlp", &[("h:1", pk(1))]);
        let s4 = merge_nsset(&s3, &rec("chooseforce.ztlp", 1, only_home_cf, 7)).unwrap();
        assert_eq!(s4.servers.len(), 1, "replica with no zones left is removed");
    }

    #[test]
    fn nsset_signed_by_a_non_home_key_is_ignored() {
        let mut store = home_store(&["trs.ztlp"]);
        store.servers.push(NsServerTrust {
            addr: "r:1".into(),
            key: pk(2),
            zones: vec!["trs.ztlp".into()],
            home: false,
        });
        // Even a trusted replica cannot vouch for servers.
        let n = rec(
            "trs.ztlp",
            2,
            nsset_cbor("trs.ztlp", &[("evil:1", pk(9))]),
            7,
        );
        assert_eq!(merge_nsset(&store, &n), Err(NssetError::NotHomeSigned));
    }

    #[test]
    fn zone_scope_is_enforced() {
        let store = home_store(&["trs.ztlp"]);
        let n = rec(
            "other.ztlp",
            1,
            nsset_cbor("other.ztlp", &[("x:1", pk(9))]),
            7,
        );
        assert_eq!(
            merge_nsset(&store, &n),
            Err(NssetError::ZoneOutOfScope("other.ztlp".into()))
        );
    }

    #[test]
    fn legacy_device_without_home_cannot_merge() {
        let n = rec("trs.ztlp", 1, nsset_cbor("trs.ztlp", &[]), 7);
        assert_eq!(
            merge_nsset(&NsTrustStore::default(), &n),
            Err(NssetError::NoHome)
        );
    }

    #[test]
    fn non_nsset_records_are_rejected() {
        let store = home_store(&["trs.ztlp"]);
        let wrong_type = rec("trs.ztlp", 1, nsset_cbor("trs.ztlp", &[]), 2);
        assert!(matches!(
            merge_nsset(&store, &wrong_type),
            Err(NssetError::NotNsset(_))
        ));
        let mut not_kind = Vec::new();
        ciborium::ser::into_writer(
            &ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Text("kind".into()),
                ciborium::value::Value::Text("relay".into()),
            )]),
            &mut not_kind,
        )
        .unwrap();
        assert!(matches!(
            merge_nsset(&store, &rec("trs.ztlp", 1, not_kind, 7)),
            Err(NssetError::NotNsset(_))
        ));
        let zone_mismatch = rec("trs.ztlp", 1, nsset_cbor("evil.ztlp", &[]), 7);
        assert!(matches!(
            merge_nsset(&store, &zone_mismatch),
            Err(NssetError::NotNsset(_))
        ));
    }

    #[test]
    fn bad_server_key_rejects_the_whole_nsset() {
        let store = home_store(&["trs.ztlp"]);
        let mut cbor = nsset_cbor("trs.ztlp", &[("r:1", pk(2))]);
        // Corrupt the hex key text in place ('0'-'f' -> 'z').
        let pos = cbor
            .windows(64)
            .position(|w| w == hex::encode(pk(2)).as_bytes())
            .unwrap();
        cbor[pos] = b'z';
        assert!(matches!(
            merge_nsset(&store, &rec("trs.ztlp", 1, cbor, 7)),
            Err(NssetError::NotNsset(_))
        ));
    }

    // ── refresh over the wire ──────────────────────────────────────────

    fn signed_nsset_reply(
        signer: &SigningKey,
        zone: &str,
        servers: &[(&str, [u8; 32])],
        serial: u64,
    ) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cbor = nsset_cbor(zone, servers);
        let mut c = vec![7u8];
        c.extend_from_slice(&(zone.len() as u16).to_be_bytes());
        c.extend_from_slice(zone.as_bytes());
        c.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
        c.extend_from_slice(&cbor);
        c.extend_from_slice(&(now - 5).to_be_bytes());
        c.extend_from_slice(&3600u32.to_be_bytes());
        c.extend_from_slice(&serial.to_be_bytes());
        let sig = signer.sign(&c).to_bytes();
        c.extend_from_slice(&64u16.to_be_bytes());
        c.extend_from_slice(&sig);
        c.extend_from_slice(&32u16.to_be_bytes());
        c.extend_from_slice(&signer.verifying_key().to_bytes());
        let mut r = vec![0x02];
        r.extend(c);
        r
    }

    async fn fake_ns(replies: Vec<Vec<u8>>) -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            for r in replies {
                if let Ok((_, src)) = sock.recv_from(&mut buf).await {
                    let _ = sock.send_to(&r, src).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn refresh_adds_then_ignores_a_replayed_older_nsset() {
        let d = tempfile::tempdir().unwrap();
        let trust_path = d.path().join("ns_trust.toml");
        let cache = d.path().join("ns_cache");
        let ns = fake_ns(vec![
            signed_nsset_reply(&sk(1), "trs.ztlp", &[("h:1", pk(1)), ("r:1", pk(2))], 10),
            // Replay of an older list without the replica.
            signed_nsset_reply(&sk(1), "trs.ztlp", &[("h:1", pk(1))], 9),
        ])
        .await;
        let mut store = home_store(&["trs.ztlp"]);
        store.servers[0].addr = ns;
        store.save(&trust_path).unwrap();

        assert_eq!(
            refresh_nsset(&trust_path, &cache).await.unwrap(),
            RefreshOutcome::Updated
        );
        let s = NsTrustStore::load(&trust_path).unwrap();
        assert_eq!(s.anchors_for("x.trs.ztlp"), vec![pk(1), pk(2)]);

        // Older serial: the cache keeps the newer NSSET, trust unchanged.
        assert_eq!(
            refresh_nsset(&trust_path, &cache).await.unwrap(),
            RefreshOutcome::Unchanged
        );
        assert_eq!(NsTrustStore::load(&trust_path).unwrap(), s);
    }

    #[tokio::test]
    async fn refresh_ignores_an_nsset_signed_by_another_key() {
        let d = tempfile::tempdir().unwrap();
        let trust_path = d.path().join("ns_trust.toml");
        let ns = fake_ns(vec![signed_nsset_reply(
            &sk(9),
            "trs.ztlp",
            &[("evil:1", pk(9))],
            10,
        )])
        .await;
        let mut store = home_store(&["trs.ztlp"]);
        store.servers[0].addr = ns;
        store.save(&trust_path).unwrap();
        assert_eq!(
            refresh_nsset(&trust_path, &d.path().join("c"))
                .await
                .unwrap(),
            RefreshOutcome::Unchanged
        );
        assert_eq!(NsTrustStore::load(&trust_path).unwrap().servers.len(), 1);
    }

    #[tokio::test]
    async fn refresh_on_a_legacy_device_is_a_noop() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            refresh_nsset(&d.path().join("ns_trust.toml"), &d.path().join("c"))
                .await
                .unwrap(),
            RefreshOutcome::NoHome
        );
    }
}
