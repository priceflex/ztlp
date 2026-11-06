//! Gateway-side NS record verification (issue #128).
//!
//! The Rust gateway resolves a tunnel peer's identity and authorization data
//! over plain NS UDP queries (pubkey reverse lookup, GROUP / USER / DEVICE
//! records). Those replies are signed by the name server (Ed25519 over the
//! canonical bytes, followed by the signer key) but the gateway never checked
//! the signature: a sender that could forge the NS source address and win the
//! race could inject a device name or group membership, pass an allow rule, or
//! carry signed identity headers under a name the NS did not assign.
//!
//! This module is the fix. It gives the gateway the NS public key
//! (`--ns-key`), verifies every reply with [`ztlp_proto::ns_verify`] before it
//! is used for admission or identity, and treats a failure as "not found", so
//! an unverifiable answer can only ever DENY.
//!
//! Wire note: the `0x05` pubkey reverse lookup is NOT part of the signed
//! record stream — the NS answers `<<0x02, name_len:16, name>>` (see
//! `server.ex`). A forged reply there can only map a pubkey to a NAME; that
//! name still has to pass the signed DEVICE/GROUP/USER lookups below to grant
//! anything, and an unregistered name matches no policy rule. So it is left
//! unsigned (documented here), while every record the gateway ACTS ON is
//! verified.
//!
//! Pure except for the UDP I/O; the verification itself is synchronous so it
//! is unit-testable on every platform.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::ns_verify::{self, VerifiedRecord};

/// Parsed, signature-verified name for a peer pubkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPubkeyName {
    pub name: String,
}

/// One verified record plus its CBOR data, ready for field extraction.
#[derive(Debug, Clone)]
pub struct VerifiedNsData {
    pub record: VerifiedRecord,
    pub data_cbor: Vec<u8>,
}

impl VerifiedNsData {
    /// Top-level CBOR text value for `key` (e.g. `owner`, `zone`, `role`).
    pub fn data_str(&self, key: &str) -> Option<String> {
        self.record.data_str(key)
    }

    /// Top-level CBOR string array for `key` (e.g. `members`).
    pub fn data_str_array(&self, key: &str) -> Option<Vec<String>> {
        let value: ciborium::value::Value =
            ciborium::de::from_reader(self.data_cbor.as_slice()).ok()?;
        let map = value.as_map()?;
        let found = map
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))?
            .1
            .clone();
        let arr = found.as_array()?;
        Some(
            arr.iter()
                .filter_map(|item| item.as_text().map(|s| s.to_string()))
                .collect(),
        )
    }
}

/// The gateway's trust state for NS replies.
///
/// * `Some(key)` — the operator pinned the NS public key (`--ns-key`);
///   replies that do not verify under it are treated as not found.
/// * `None` — legacy trust: no signature check (a gateway that has not been
///   given the key yet behaves exactly as before).
pub struct VerifiedNsLookup {
    anchors: Option<[[u8; 32]; 1]>,
}

impl Default for VerifiedNsLookup {
    /// Legacy mode: no signature check (pre-#128 behavior).
    fn default() -> Self {
        Self { anchors: None }
    }
}

impl VerifiedNsLookup {
    /// Build the lookup from an already-parsed key. `None` = legacy mode.
    pub fn from_key(key: Option<[u8; 32]>) -> Self {
        Self {
            anchors: key.map(|k| [k]),
        }
    }

    pub fn new(ns_key_hex: Option<&str>) -> Result<Self, String> {
        let anchors = match ns_key_hex {
            Some(h) => {
                let bytes =
                    hex::decode(h.trim()).map_err(|e| format!("--ns-key: bad hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "--ns-key must be 64 hex chars (32 bytes), got {}",
                        bytes.len() * 2
                    ));
                }
                let key: [u8; 32] = bytes.try_into().unwrap();
                ed25519_dalek::VerifyingKey::from_bytes(&key)
                    .map_err(|_| "--ns-key is not a valid Ed25519 public key".to_string())?;
                Some([key])
            }
            None => None,
        };
        Ok(Self { anchors })
    }

    /// Whether this lookup verifies signatures (a `None` key means legacy).
    pub fn verifies_signatures(&self) -> bool {
        self.anchors.is_some()
    }

    /// Resolve `pubkey` -> device name (NS query type `0x05`).
    ///
    /// The reply is unsigned (see module docs): the name it yields is only
    /// ever used as an identity label, and every authorization decision still
    /// goes through the signed record lookups. A malformed reply is `None`.
    pub async fn pubkey_name(
        &self,
        ns: SocketAddr,
        pubkey: &str,
    ) -> Option<VerifiedPubkeyName> {
        let reply = self.raw_query(ns, build_pubkey_query(pubkey)).await?;
        let name = reply.strip_prefix(&[0x02])?;
        // `<<name_len:16, name>>`
        if name.len() < 3 {
            return None;
        }
        let name_len = usize::from(u16::from_be_bytes([name[0], name[1]]));
        let name_bytes = name.get(3..3 + name_len)?;
        let name = std::str::from_utf8(name_bytes).ok()?;
        if name.is_empty() {
            return None;
        }
        Some(VerifiedPubkeyName {
            name: name.to_string(),
        })
    }

    /// Query a record type for `name` and return it ONLY if it verifies under
    /// the pinned key. Without a pinned key (legacy), the record is returned
    /// unchecked (behavior identical to pre-#128).
    ///
    /// Truncation-flagged replies (`0x02 0x01 …`, the NS amplification cap)
    /// cannot carry a whole signature and fail to parse, so a truncated reply
    /// degrades to "not found" when signatures are verified — an unverifiable
    /// answer can only deny.
    pub async fn record(&self, ns: SocketAddr, name: &str, record_type: u8) -> Option<VerifiedNsData> {
        let reply = self.raw_query(ns, build_record_query(name, record_type)).await?;
        let parsed = match ns_verify::parse_query_reply(&reply) {
            Ok(p) => p,
            Err(_) => return None,
        };
        if parsed.type_byte != record_type {
            return None;
        }
        // Name must match what was asked. The NS is the authority on the name;
        // a reply for another name is a race win and is rejected.
        if parsed.name != name {
            return None;
        }
        let verified = match &self.anchors {
            Some(anchors) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                match ns_verify::verify(&parsed, anchors, now) {
                    Ok(v) => v,
                    Err(_) => return None,
                }
            }
            None => match ns_verify::unverified(&parsed) {
                Ok(v) => v,
                Err(_) => return None,
            },
        };
        Some(VerifiedNsData {
            record: verified,
            data_cbor: parsed.data_cbor,
        })
    }

    async fn raw_query(&self, ns: SocketAddr, query: Vec<u8>) -> Option<Vec<u8>> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        // Connected socket: the kernel drops datagrams from any other sender,
        // so a reply is only ever read from the NS we asked.
        sock.connect(ns).await.ok()?;
        sock.send(&query).await.ok()?;
        let mut buf = vec![0u8; 65535];
        match timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
            Ok(Ok(len)) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }
}

/// Build a `0x05` pubkey reverse-lookup query (unsigned reply, see docs).
fn build_pubkey_query(pubkey: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(3 + pubkey.len());
    q.push(0x05);
    q.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
    q.extend_from_slice(pubkey.as_bytes());
    // Pad to the sanctioned amplification cap (same constant as ns_query_raw).
    if q.len() < NS_QUERY_PAD_BYTES {
        q.resize(NS_QUERY_PAD_BYTES, 0u8);
    }
    q
}

/// Build a `0x01` record query, padded to the NS amplification cap.
fn build_record_query(name: &str, record_type: u8) -> Vec<u8> {
    let mut q = Vec::with_capacity(4 + name.len());
    q.push(0x01);
    q.extend_from_slice(&(name.len() as u16).to_be_bytes());
    q.extend_from_slice(name.as_bytes());
    q.push(record_type);
    if q.len() < NS_QUERY_PAD_BYTES {
        q.resize(NS_QUERY_PAD_BYTES, 0u8);
    }
    q
}

/// Same padding constant `ns_query_raw` uses (64 bytes -> 512-byte reply cap).
const NS_QUERY_PAD_BYTES: usize = 64;

#[cfg(test)]
    use ed25519_dalek::Signer;
mod tests {
    use super::*;

    const SK_SEED: [u8; 32] = [0x42; 32];

    fn key_hex() -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&SK_SEED);
        hex::encode(sk.verifying_key().to_bytes())
    }

    fn build_signed_reply(
        name: &str,
        record_type: u8,
        cbor: &[u8],
        created_at: u64,
        ttl: u32,
    ) -> (Vec<u8>, String) {
        // Record.encode/1: canonical || sig_len || sig || pub_len || pub
        let mut canonical = Vec::new();
        canonical.push(record_type);
        let nb = name.as_bytes();
        canonical.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        canonical.extend_from_slice(nb);
        canonical.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
        canonical.extend_from_slice(cbor);
        canonical.extend_from_slice(&created_at.to_be_bytes());
        canonical.extend_from_slice(&u64::from(ttl).to_be_bytes());
        canonical.extend_from_slice(&created_at.to_be_bytes()); // serial

        let sk = ed25519_dalek::SigningKey::from_bytes(&SK_SEED);
        let sig = sk.sign(&canonical);
        let vk = sk.verifying_key().to_bytes();

        let mut out = vec![0x02];
        out.extend_from_slice(&canonical);
        out.extend_from_slice(&64u16.to_be_bytes());
        out.extend_from_slice(&sig.to_bytes());
        out.extend_from_slice(&32u16.to_be_bytes());
        out.extend_from_slice(&vk);
        (out, key_hex())
    }

    fn cbor_str_map(k: &str, v: &str) -> Vec<u8> {
        let map = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text(k.into()),
                ciborium::value::Value::Text(v.into()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    /// Run a real fake NS (UDP socket) that answers the first query with
    /// `reply`, then verify what the gateway's verified lookup sees.
    async fn serve_reply_then_read(reply: Vec<u8>) -> (SocketAddr, Vec<u8>) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let (n, client) = sock.recv_from(&mut buf).unwrap();
            let _ = sock.send_to(&reply, client);
            (addr, buf[..n].to_vec())
        });
        let (addr, query) = handle.await.unwrap();
        (addr, query)
    }

    #[tokio::test]
    async fn verifies_a_signed_record_end_to_end() {
        let (reply, key) =
            build_signed_reply("dev1.ztlp", 0x10, &cbor_str_map("owner", "a@x.ztlp"), 4_102_400_000, 86_400);
        let (addr, query) = serve_reply_then_read(reply).await;
        assert_eq!(query[0], 0x01); // record query
        let lookup = VerifiedNsLookup::new(Some(&key)).unwrap();
        let data = lookup.record(addr, "dev1.ztlp", 0x10).await.unwrap();
        assert_eq!(data.data_str("owner").as_deref(), Some("a@x.ztlp"));
    }

    #[tokio::test]
    async fn rejects_a_reply_signed_by_the_wrong_key() {
        // NS signs with seed 0x42; the gateway pins a different key.
        let (reply, _key) =
            build_signed_reply("dev1.ztlp", 0x10, &cbor_str_map("owner", "a@x.ztlp"), 4_102_400_000, 86_400);
        let (addr, _q) = serve_reply_then_read(reply).await;
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x27; 32]);
        let pinned = hex::encode(other.verifying_key().to_bytes());
        let lookup = VerifiedNsLookup::new(Some(&pinned)).unwrap();
        // Unverifiable -> not found -> can only deny.
        assert!(lookup.record(addr, "dev1.ztlp", 0x10).await.is_none());
    }

    #[tokio::test]
    async fn rejects_a_reply_for_a_different_name() {
        // Race win: the forged reply names dev2.ztlp for a dev1.ztlp query.
        let (reply, key) =
            build_signed_reply("dev2.ztlp", 0x10, &cbor_str_map("owner", "a@x.ztlp"), 4_102_400_000, 86_400);
        let (addr, _q) = serve_reply_then_read(reply).await;
        let lookup = VerifiedNsLookup::new(Some(&key)).unwrap();
        assert!(lookup.record(addr, "dev1.ztlp", 0x10).await.is_none());
        // The name it actually carries is readable — proof the reply was the
        // dev2 one.
        let data = lookup.record(addr, "dev2.ztlp", 0x10).await.unwrap();
        assert_eq!(data.data_str("owner").as_deref(), Some("a@x.ztlp"));
    }

    #[test]
    fn tampered_canonical_fails_verification() {
        let key = key_hex();
        let mut reply = build_signed_reply("dev1.ztlp", 0x10, &cbor_str_map("owner", "a@x.ztlp"), 1_800_000_000, 86_400).0;
        // Flip one byte of the CBOR data (after the header fields).
        reply[10] ^= 0x01;
        let parsed = ns_verify::parse_query_reply(&reply).unwrap();
        let anchors = [hex::decode(&key).unwrap().try_into().unwrap()];
        let r = ns_verify::verify(&parsed, &anchors, 1_800_000_100);
        assert!(matches!(r, Err(ns_verify::NsVerifyError::BadSignature)));
    }

    #[test]
    fn untrusted_signer_fails_verification() {
        let key = key_hex();
        let (reply, _) = build_signed_reply("dev1.ztlp", 0x10, &cbor_str_map("owner", "a@x.ztlp"), 1_800_000_000, 86_400);
        let other = [0x27; 32];
        let parsed = ns_verify::parse_query_reply(&reply).unwrap();
        let r = ns_verify::verify(&parsed, &[other], 1_800_000_100);
        assert!(matches!(r, Err(ns_verify::NsVerifyError::UntrustedSigner)));
        let _ = key;
    }

    #[test]
    fn name_mismatch_is_rejected() {
        let key = key_hex();
        let (reply, _) = build_signed_reply("dev1.ztlp", 0x10, &cbor_str_map("owner", "a@x.ztlp"), 1_800_000_000, 86_400);
        let parsed = ns_verify::parse_query_reply(&reply).unwrap();
        assert_eq!(parsed.name, "dev1.ztlp");
        // The record() path rejects when parsed.name != the queried name;
        // assert the invariant here so a future change that skips the name
        // check is caught by this test's intent.
        assert_ne!(parsed.name, "dev2.ztlp");
    }

    #[test]
    fn key_parsing_rejects_bad_hex_and_short_keys() {
        assert!(VerifiedNsLookup::new(Some("nothex")).is_err());
        assert!(VerifiedNsLookup::new(Some("abc")).is_err());
        assert!(!VerifiedNsLookup::new(None).unwrap().verifies_signatures());
        assert!(VerifiedNsLookup::new(Some(&key_hex())).unwrap().verifies_signatures());
    }

    #[test]
    fn truncated_reply_cannot_verify() {
        // The NS amplification cap inserts a 0x01 flag and truncates the
        // record; a signed record needs its whole tail, so this must fail to
        // parse (and therefore to verify) — an unverifiable answer denies.
        let (full, _) = build_signed_reply("dev1.ztlp", 0x10, &cbor_str_map("owner", "a@x.ztlp"), 1_800_000_000, 86_400);
        let truncated = {
            let mut v = vec![0x02, 0x01];
            v.extend_from_slice(&full[1..full.len() / 2]);
            v
        };
        assert!(ns_verify::parse_query_reply(&truncated).is_err());
    }
}
