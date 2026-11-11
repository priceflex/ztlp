//! Gateway-side NS record verification (issue #128).
//!
//! The Rust gateway resolves a tunnel peer's identity and authorization data
//! over plain NS UDP queries: the `0x05` pubkey reverse lookup (peer X25519
//! key -> device name) and `0x01` DEVICE / USER / GROUP record queries. Every
//! one of those replies is a record signed by the name server's registration
//! key (Ed25519 over the canonical bytes, followed by the signer key — see
//! `ns/lib/ztlp_ns/record.ex` and [`crate::ns_verify`]); the NS re-signs every
//! stored record with that key, including enrolled-device check-ins.
//!
//! Before #128 the gateway never checked those signatures. A sender able to
//! forge the NS source address and win the race could map an attacker's
//! tunnel key to a victim's device name, or inject group membership, and so
//! pass an allow rule or carry signed identity headers under a name the NS
//! never assigned.
//!
//! With the NS key pinned (`ztlp listen --ns-key <hex>`):
//! * every reply must verify under that key, and
//! * the pubkey reverse lookup must return a KEY record whose `public_key`
//!   IS the peer's key (a validly signed record for someone else's key is a
//!   replay, not an answer),
//! * the record must carry the name and type that were asked for.
//!
//! Any failure is "not found", so an unverifiable answer can only DENY.
//! Without a pinned key (legacy mode) signatures are not checked, but the
//! name / type / key-binding / expiry checks still apply.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::ns_verify::{self, VerifiedRecord};

/// KEY record type byte (`0x01`).
pub const RECORD_KEY: u8 = 0x01;
/// DEVICE record type byte.
pub const RECORD_DEVICE: u8 = 0x10;
/// USER record type byte.
pub const RECORD_USER: u8 = 0x11;
/// GROUP record type byte.
pub const RECORD_GROUP: u8 = 0x12;

/// Queries are zero-padded to this size: the NS caps a reply at 8x the
/// request size (amplification guard), and a signed GROUP record with many
/// members needs the room. Same value the agent and CLI use.
pub const NS_QUERY_PAD_BYTES: usize = 256;

/// How long one NS query may take.
const NS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// One accepted record plus its CBOR data, ready for field extraction.
#[derive(Debug, Clone)]
pub struct VerifiedNsData {
    pub record: VerifiedRecord,
}

impl VerifiedNsData {
    /// Top-level CBOR text value for `key` (e.g. `owner`, `zone`, `role`).
    pub fn data_str(&self, key: &str) -> Option<String> {
        self.record.data_str(key)
    }

    /// Top-level CBOR string array for `key` (e.g. `members`).
    pub fn data_str_array(&self, key: &str) -> Option<Vec<String>> {
        let value: ciborium::value::Value =
            ciborium::de::from_reader(self.record.data_cbor.as_slice()).ok()?;
        let arr = value
            .as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))?
            .1
            .as_array()?
            .iter()
            .filter_map(|item| item.as_text().map(str::to_string))
            .collect();
        Some(arr)
    }
}

/// The gateway's trust state for NS replies. Cheap to copy.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifiedNsLookup {
    /// `Some` = the operator pinned the NS key; `None` = legacy mode.
    key: Option<[u8; 32]>,
}

/// Parse `--ns-key`: 64 hex chars that decode to a valid Ed25519 public key.
pub fn parse_ns_key_hex(hex_key: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_key.trim()).map_err(|e| format!("--ns-key: bad hex: {e}"))?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "--ns-key must be 64 hex chars (32 bytes), got {}",
            bytes.len() * 2
        )
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| "--ns-key is not a valid Ed25519 public key".to_string())?;
    Ok(key)
}

impl VerifiedNsLookup {
    /// `None` = legacy mode (no signature check).
    pub fn from_key(key: Option<[u8; 32]>) -> Self {
        Self { key }
    }

    /// Whether replies must verify under a pinned key.
    pub fn verifies_signatures(&self) -> bool {
        self.key.is_some()
    }

    /// Peer tunnel pubkey (hex) -> device name, from a KEY record that binds
    /// exactly that key. `None` when absent, unverifiable, or bound to a
    /// different key.
    pub async fn pubkey_name(&self, ns: SocketAddr, pubkey_hex: &str) -> Option<String> {
        let reply = raw_query(ns, build_pubkey_query(pubkey_hex)).await?;
        let rec = self.accept(&reply, None, RECORD_KEY)?;
        // The record must bind THIS key: a validly signed KEY record for some
        // other device's key is a replay that would hand the peer that
        // device's name, owner and groups.
        let bound = rec.data_str("public_key")?;
        bound
            .eq_ignore_ascii_case(pubkey_hex.trim())
            .then_some(rec.name)
    }

    /// Record `record_type` for `name`, accepted only per the module rules.
    pub async fn record(
        &self,
        ns: SocketAddr,
        name: &str,
        record_type: u8,
    ) -> Option<VerifiedNsData> {
        let reply = raw_query(ns, build_record_query(name, record_type)).await?;
        self.accept(&reply, Some(name), record_type)
            .map(|record| VerifiedNsData { record })
    }

    /// Parse + check one reply: the expected type, the expected name (when
    /// given), not expired, and — when a key is pinned — signed by it.
    fn accept(&self, reply: &[u8], name: Option<&str>, record_type: u8) -> Option<VerifiedRecord> {
        let parsed = ns_verify::parse_query_reply(reply).ok()?;
        if parsed.type_byte != record_type {
            return None;
        }
        if name.is_some_and(|n| parsed.name != n) {
            return None;
        }
        match &self.key {
            Some(key) => ns_verify::verify(&parsed, &[*key], unix_now()).ok(),
            None => ns_verify::unverified(&parsed).ok(),
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `0x05` pubkey reverse-lookup query, padded.
pub fn build_pubkey_query(pubkey_hex: &str) -> Vec<u8> {
    let mut q = vec![0x05];
    q.extend_from_slice(&(pubkey_hex.len() as u16).to_be_bytes());
    q.extend_from_slice(pubkey_hex.as_bytes());
    q.resize(q.len().max(NS_QUERY_PAD_BYTES), 0);
    q
}

/// `0x01` record query, padded.
pub fn build_record_query(name: &str, record_type: u8) -> Vec<u8> {
    let mut q = vec![0x01];
    q.extend_from_slice(&(name.len() as u16).to_be_bytes());
    q.extend_from_slice(name.as_bytes());
    q.push(record_type);
    q.resize(q.len().max(NS_QUERY_PAD_BYTES), 0);
    q
}

/// Encode a record exactly as the NS sends it (`<<0x02, Record.encode>>`),
/// signed with the Ed25519 key derived from `seed`. Test support for this
/// module and the gateway binary's tests; never used on a live path.
#[doc(hidden)]
pub fn encode_signed_reply_for_tests(
    seed: [u8; 32],
    name: &str,
    record_type: u8,
    data_cbor: &[u8],
    created_at: u64,
    ttl: u32,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut canonical = vec![record_type];
    canonical.extend_from_slice(&(name.len() as u16).to_be_bytes());
    canonical.extend_from_slice(name.as_bytes());
    canonical.extend_from_slice(&(data_cbor.len() as u32).to_be_bytes());
    canonical.extend_from_slice(data_cbor);
    canonical.extend_from_slice(&created_at.to_be_bytes());
    canonical.extend_from_slice(&ttl.to_be_bytes()); // ttl:32
    canonical.extend_from_slice(&created_at.to_be_bytes()); // serial
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let sig = sk.sign(&canonical);
    let mut out = vec![0x02];
    out.extend_from_slice(&canonical);
    out.extend_from_slice(&64u16.to_be_bytes());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&32u16.to_be_bytes());
    out.extend_from_slice(&sk.verifying_key().to_bytes());
    out
}

async fn raw_query(ns: SocketAddr, query: Vec<u8>) -> Option<Vec<u8>> {
    let bind = if ns.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    // Connected socket: the kernel drops datagrams from any other sender.
    sock.connect(ns).await.ok()?;
    sock.send(&query).await.ok()?;
    let mut buf = vec![0u8; 65535];
    match timeout(NS_QUERY_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(len)) => Some(buf[..len].to_vec()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS_SEED: [u8; 32] = [0x42; 32];
    const OTHER_SEED: [u8; 32] = [0x27; 32];
    const PEER: &str = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44";
    const VICTIM: &str = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";

    fn key_of(seed: [u8; 32]) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn cbor(pairs: &[(&str, ciborium::value::Value)]) -> Vec<u8> {
        let map = ciborium::value::Value::Map(
            pairs
                .iter()
                .map(|(k, v)| (ciborium::value::Value::Text((*k).into()), v.clone()))
                .collect(),
        );
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    fn text(s: &str) -> ciborium::value::Value {
        ciborium::value::Value::Text(s.into())
    }

    fn signed_reply(
        seed: [u8; 32],
        name: &str,
        rtype: u8,
        data: &[u8],
        created_at: u64,
        ttl: u32,
    ) -> Vec<u8> {
        encode_signed_reply_for_tests(seed, name, rtype, data, created_at, ttl)
    }

    fn key_record(seed: [u8; 32], name: &str, bound_pubkey: &str) -> Vec<u8> {
        signed_reply(
            seed,
            name,
            RECORD_KEY,
            &cbor(&[("public_key", text(bound_pubkey))]),
            now(),
            86_400,
        )
    }

    /// A real UDP "NS" that answers the first query with `reply` and hands
    /// the query back. Spawned BEFORE the lookup runs (no deadlock).
    async fn fake_ns(reply: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            sock.send_to(&reply, from).await.unwrap();
            buf[..n].to_vec()
        });
        (addr, h)
    }

    fn pinned() -> VerifiedNsLookup {
        VerifiedNsLookup::from_key(Some(key_of(NS_SEED)))
    }

    // ── pubkey -> name (the identity binding) ──────────────────────────

    #[tokio::test]
    async fn pubkey_name_accepts_a_signed_key_record_binding_this_key() {
        let (ns, q) = fake_ns(key_record(NS_SEED, "laptop.acme.ztlp", PEER)).await;
        assert_eq!(
            pinned().pubkey_name(ns, PEER).await.as_deref(),
            Some("laptop.acme.ztlp")
        );
        let q = q.await.unwrap();
        assert_eq!(q[0], 0x05);
        assert_eq!(q.len(), NS_QUERY_PAD_BYTES, "query padded");
    }

    /// The attack #128 is about: a validly NS-signed KEY record for a
    /// VICTIM's device, replayed as the answer for the attacker's key.
    #[tokio::test]
    async fn pubkey_name_rejects_a_signed_record_bound_to_another_key() {
        let (ns, _q) = fake_ns(key_record(NS_SEED, "ceo-laptop.acme.ztlp", VICTIM)).await;
        assert_eq!(pinned().pubkey_name(ns, PEER).await, None);
    }

    #[tokio::test]
    async fn pubkey_name_rejects_a_record_signed_by_another_key() {
        let (ns, _q) = fake_ns(key_record(OTHER_SEED, "laptop.acme.ztlp", PEER)).await;
        assert_eq!(pinned().pubkey_name(ns, PEER).await, None);
    }

    #[tokio::test]
    async fn pubkey_name_binding_is_checked_in_legacy_mode_too() {
        let (ns, _q) = fake_ns(key_record(OTHER_SEED, "ceo-laptop.acme.ztlp", VICTIM)).await;
        assert_eq!(
            VerifiedNsLookup::default().pubkey_name(ns, PEER).await,
            None
        );
        let (ns, _q) = fake_ns(key_record(OTHER_SEED, "laptop.acme.ztlp", PEER)).await;
        assert_eq!(
            VerifiedNsLookup::default()
                .pubkey_name(ns, PEER)
                .await
                .as_deref(),
            Some("laptop.acme.ztlp"),
            "legacy mode keeps working without a pinned key"
        );
    }

    #[tokio::test]
    async fn pubkey_name_key_comparison_ignores_hex_case() {
        let (ns, _q) = fake_ns(key_record(
            NS_SEED,
            "laptop.acme.ztlp",
            &PEER.to_uppercase(),
        ))
        .await;
        assert_eq!(
            pinned().pubkey_name(ns, PEER).await.as_deref(),
            Some("laptop.acme.ztlp")
        );
    }

    #[tokio::test]
    async fn pubkey_name_not_found_reply_is_none() {
        let mut nf = vec![0x03];
        nf.extend_from_slice(&(PEER.len() as u16).to_be_bytes());
        nf.extend_from_slice(PEER.as_bytes());
        nf.push(0);
        let (ns, _q) = fake_ns(nf).await;
        assert_eq!(pinned().pubkey_name(ns, PEER).await, None);
    }

    // ── DEVICE / USER / GROUP records ──────────────────────────────────

    #[tokio::test]
    async fn record_accepts_a_signed_record_and_reads_fields() {
        let data = cbor(&[(
            "members",
            ciborium::value::Value::Array(vec![text("a@acme.ztlp"), text("b@acme.ztlp")]),
        )]);
        let (ns, q) = fake_ns(signed_reply(
            NS_SEED,
            "eng.acme.ztlp",
            RECORD_GROUP,
            &data,
            now(),
            86_400,
        ))
        .await;
        let rec = pinned()
            .record(ns, "eng.acme.ztlp", RECORD_GROUP)
            .await
            .unwrap();
        assert_eq!(
            rec.data_str_array("members").unwrap(),
            vec!["a@acme.ztlp", "b@acme.ztlp"]
        );
        let q = q.await.unwrap();
        assert_eq!((q[0], q.len()), (0x01, NS_QUERY_PAD_BYTES));
    }

    #[tokio::test]
    async fn record_rejects_wrong_signer_name_or_type() {
        let owner = cbor(&[("owner", text("a@acme.ztlp"))]);
        let (ns, _q) = fake_ns(signed_reply(
            OTHER_SEED,
            "pc.acme.ztlp",
            RECORD_DEVICE,
            &owner,
            now(),
            86_400,
        ))
        .await;
        assert!(
            pinned()
                .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
                .await
                .is_none(),
            "signer"
        );
        let (ns, _q) = fake_ns(signed_reply(
            NS_SEED,
            "other.acme.ztlp",
            RECORD_DEVICE,
            &owner,
            now(),
            86_400,
        ))
        .await;
        assert!(
            pinned()
                .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
                .await
                .is_none(),
            "name"
        );
        let (ns, _q) = fake_ns(signed_reply(
            NS_SEED,
            "pc.acme.ztlp",
            RECORD_USER,
            &owner,
            now(),
            86_400,
        ))
        .await;
        assert!(
            pinned()
                .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
                .await
                .is_none(),
            "type"
        );
    }

    #[tokio::test]
    async fn record_rejects_an_expired_record_in_both_modes() {
        let owner = cbor(&[("owner", text("a@acme.ztlp"))]);
        let old = now() - 10_000;
        let (ns, _q) = fake_ns(signed_reply(
            NS_SEED,
            "pc.acme.ztlp",
            RECORD_DEVICE,
            &owner,
            old,
            60,
        ))
        .await;
        assert!(pinned()
            .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
            .await
            .is_none());
        let (ns, _q) = fake_ns(signed_reply(
            NS_SEED,
            "pc.acme.ztlp",
            RECORD_DEVICE,
            &owner,
            old,
            60,
        ))
        .await;
        assert!(VerifiedNsLookup::default()
            .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn legacy_mode_accepts_an_unpinned_signer() {
        let owner = cbor(&[("owner", text("a@acme.ztlp"))]);
        let (ns, _q) = fake_ns(signed_reply(
            OTHER_SEED,
            "pc.acme.ztlp",
            RECORD_DEVICE,
            &owner,
            now(),
            86_400,
        ))
        .await;
        let rec = VerifiedNsLookup::default()
            .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
            .await
            .unwrap();
        assert_eq!(rec.data_str("owner").as_deref(), Some("a@acme.ztlp"));
    }

    #[tokio::test]
    async fn a_truncated_reply_cannot_verify() {
        let owner = cbor(&[("owner", text("a@acme.ztlp"))]);
        let full = signed_reply(
            NS_SEED,
            "pc.acme.ztlp",
            RECORD_DEVICE,
            &owner,
            now(),
            86_400,
        );
        let mut truncated = vec![0x02, 0x01];
        truncated.extend_from_slice(&full[1..full.len() / 2]);
        let (ns, _q) = fake_ns(truncated).await;
        assert!(pinned()
            .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn no_reply_is_none_not_a_hang() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // never answers
        let ns = sock.local_addr().unwrap();
        let t0 = std::time::Instant::now();
        assert!(pinned()
            .record(ns, "pc.acme.ztlp", RECORD_DEVICE)
            .await
            .is_none());
        assert!(t0.elapsed() < NS_QUERY_TIMEOUT + Duration::from_secs(2));
    }

    // ── --ns-key parsing ────────────────────────────────────────────────

    #[test]
    fn ns_key_parsing() {
        let good = hex::encode(key_of(NS_SEED));
        assert_eq!(parse_ns_key_hex(&good).unwrap(), key_of(NS_SEED));
        assert_eq!(
            parse_ns_key_hex(&format!("  {}\n", good.to_uppercase())).unwrap(),
            key_of(NS_SEED)
        );
        assert!(parse_ns_key_hex("nothex").is_err());
        assert!(parse_ns_key_hex("abcd").is_err());
        assert!(parse_ns_key_hex(&"00".repeat(33)).is_err());
    }
}
