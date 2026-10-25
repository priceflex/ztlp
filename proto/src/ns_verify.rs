//! Verification of signed ZTLP-NS records (NS-anchored gateway trust, Phase 2).
//!
//! The name server answers a query (`0x01`) with `<<0x02, Record.encode(record)>>`
//! where (`ns/lib/ztlp_ns/record.ex`):
//!
//! ```text
//! encode    = canonical || sig_len:u16 || sig || pub_len:u16 || pub
//! canonical = type:u8 | name_len:u16 | name | data_len:u32 | cbor
//!             | created_at:u64 | ttl:u32 | serial:u64          (all big-endian)
//! ```
//!
//! The signature is Ed25519 over `canonical`. A client trusts a record only
//! if the signer is one of the name-server keys it trusts for that zone, the
//! signature verifies (strict), and the record has not expired.
//!
//! Pure, synchronous, no network, no filesystem. Never route these bytes
//! through the bare-CBOR helpers in `ns_cbor` / `agent::proxy` (they drop the
//! signature; see the double-unwrap notes there).

use std::fmt;

/// Ed25519 signature length on the wire.
const SIG_LEN: usize = 64;
/// Ed25519 public key length on the wire.
const PUB_LEN: usize = 32;

/// Why a record was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsVerifyError {
    /// Input ended before the structure was complete.
    Truncated,
    /// Bytes left over after the public key (not a single record).
    TrailingBytes,
    /// Signature length field is not 64.
    BadSignatureLength(usize),
    /// Public key length field is not 32.
    BadPublicKeyLength(usize),
    /// Name is not valid UTF-8.
    BadName,
    /// Signer key is not one of the trusted name-server keys.
    UntrustedSigner,
    /// Ed25519 signature does not verify over the canonical bytes.
    BadSignature,
    /// `created_at + ttl <= now`.
    Expired,
    /// A valid record, but for a different name or type than was asked.
    WrongRecord,
    /// The NS signed it on behalf of an UNAUTHENTICATED registrant
    /// (`registered_unsigned: true`, dev/demo NS mode): the NS signature
    /// vouches for nothing, so it can never authenticate a gateway.
    UnauthenticatedRegistration,
}

impl fmt::Display for NsVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "NS record truncated"),
            Self::TrailingBytes => write!(f, "NS record has trailing bytes"),
            Self::BadSignatureLength(n) => write!(f, "NS record signature length {n} (want 64)"),
            Self::BadPublicKeyLength(n) => write!(f, "NS record signer key length {n} (want 32)"),
            Self::BadName => write!(f, "NS record name is not UTF-8"),
            Self::UntrustedSigner => write!(f, "NS record signed by an untrusted key"),
            Self::BadSignature => write!(f, "NS record signature does not verify"),
            Self::Expired => write!(f, "NS record expired"),
            Self::WrongRecord => write!(f, "NS record is for a different name or type"),
            Self::UnauthenticatedRegistration => {
                write!(f, "NS record came from an unauthenticated registration")
            }
        }
    }
}

impl std::error::Error for NsVerifyError {}

/// A structurally valid, NOT yet verified record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    pub type_byte: u8,
    pub name: String,
    pub data_cbor: Vec<u8>,
    pub created_at: u64,
    pub ttl: u32,
    pub serial: u64,
    /// The exact signed bytes.
    pub canonical: Vec<u8>,
    pub signature: [u8; SIG_LEN],
    pub signer: [u8; PUB_LEN],
}

/// A record whose signature verified against a trusted key and which was
/// unexpired at verification time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    pub type_byte: u8,
    pub name: String,
    pub data_cbor: Vec<u8>,
    pub signer: [u8; PUB_LEN],
    pub created_at: u64,
    pub ttl: u32,
    pub serial: u64,
}

impl VerifiedRecord {
    /// Unix time (seconds) after which the record is no longer valid.
    pub fn expires_at(&self) -> u64 {
        self.created_at.saturating_add(u64::from(self.ttl))
    }

    /// True when the NS stored this record from an unauthenticated
    /// (unsigned, dev-mode) registration.
    pub fn registered_unsigned(&self) -> bool {
        let Ok(value) =
            ciborium::de::from_reader::<ciborium::value::Value, _>(self.data_cbor.as_slice())
        else {
            return false;
        };
        value.as_map().is_some_and(|m| {
            m.iter().any(|(k, v)| {
                k.as_text() == Some("registered_unsigned") && v.as_bool() == Some(true)
            })
        })
    }

    /// Text value of a top-level CBOR map key (e.g. `quic_cert_sha256`).
    pub fn data_str(&self, key: &str) -> Option<String> {
        let value: ciborium::value::Value =
            ciborium::de::from_reader(self.data_cbor.as_slice()).ok()?;
        let map = value.as_map()?;
        map.iter()
            .find_map(|(k, v)| match (k.as_text(), v.as_text()) {
                (Some(k), Some(v)) if k == key => Some(v.to_string()),
                _ => None,
            })
    }
}

/// Parse `Record.encode/1` bytes (WITHOUT the `0x02` status byte).
pub fn parse_signed_record(bytes: &[u8]) -> Result<ParsedRecord, NsVerifyError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let type_byte = r.u8()?;
    let name_len = usize::from(r.u16()?);
    let name = std::str::from_utf8(r.take(name_len)?)
        .map_err(|_| NsVerifyError::BadName)?
        .to_string();
    let data_len = r.u32()? as usize;
    let data_cbor = r.take(data_len)?.to_vec();
    let created_at = r.u64()?;
    let ttl = r.u32()?;
    let serial = r.u64()?;
    let canonical = bytes[..r.pos].to_vec();

    let sig_len = usize::from(r.u16()?);
    if sig_len != SIG_LEN {
        return Err(NsVerifyError::BadSignatureLength(sig_len));
    }
    let signature: [u8; SIG_LEN] = r.take(SIG_LEN)?.try_into().expect("length checked");
    let pub_len = usize::from(r.u16()?);
    if pub_len != PUB_LEN {
        return Err(NsVerifyError::BadPublicKeyLength(pub_len));
    }
    let signer: [u8; PUB_LEN] = r.take(PUB_LEN)?.try_into().expect("length checked");
    if r.pos != bytes.len() {
        return Err(NsVerifyError::TrailingBytes);
    }

    Ok(ParsedRecord {
        type_byte,
        name,
        data_cbor,
        created_at,
        ttl,
        serial,
        canonical,
        signature,
        signer,
    })
}

/// Bounds-checked big-endian cursor; every read fails with `Truncated`
/// instead of panicking.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], NsVerifyError> {
        let end = self.pos.checked_add(n).ok_or(NsVerifyError::Truncated)?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(NsVerifyError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, NsVerifyError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, NsVerifyError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, NsVerifyError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, NsVerifyError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
}

/// Parse a full query reply (`0x02 || Record.encode`). A truncated reply
/// (`0x02 0x01 …`, the NS amplification cap) cannot carry a whole signature
/// and fails to parse, which is the intended outcome.
pub fn parse_query_reply(reply: &[u8]) -> Result<ParsedRecord, NsVerifyError> {
    match reply.split_first() {
        Some((0x02, record)) => parse_signed_record(record),
        _ => Err(NsVerifyError::Truncated),
    }
}

/// Verify a parsed record against the trusted name-server keys at `now`
/// (unix seconds).
pub fn verify(
    rec: &ParsedRecord,
    anchors: &[[u8; PUB_LEN]],
    now: u64,
) -> Result<VerifiedRecord, NsVerifyError> {
    // The embedded signer key means nothing by itself: it must be one the
    // device was given out of band (enrollment token / home-signed NSSET).
    if !anchors.iter().any(|a| a == &rec.signer) {
        return Err(NsVerifyError::UntrustedSigner);
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&rec.signer)
        .map_err(|_| NsVerifyError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&rec.signature);
    key.verify_strict(&rec.canonical, &sig)
        .map_err(|_| NsVerifyError::BadSignature)?;

    let v = VerifiedRecord {
        type_byte: rec.type_byte,
        name: rec.name.clone(),
        data_cbor: rec.data_cbor.clone(),
        signer: rec.signer,
        created_at: rec.created_at,
        ttl: rec.ttl,
        serial: rec.serial,
    };
    if v.expires_at() <= now {
        return Err(NsVerifyError::Expired);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = include_str!("../tests/fixtures/ns_signed_svc_record.hex");
    const GOLDEN_EXPIRED: &str = include_str!("../tests/fixtures/ns_signed_svc_record_expired.hex");
    const GOLDEN_PUB: &str = include_str!("../tests/fixtures/ns_signed_svc_record.pub");

    /// Fixture valid window: created 1_800_000_000, ttl 86_400.
    const NOW: u64 = 1_800_000_100;

    fn bytes(h: &str) -> Vec<u8> {
        hex::decode(h.trim()).unwrap()
    }

    fn anchor() -> [u8; 32] {
        bytes(GOLDEN_PUB).try_into().unwrap()
    }

    #[test]
    fn fixture_signer_is_the_seed_0x42_key() {
        // Cross-check the Elixir key derivation against ed25519-dalek.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        assert_eq!(sk.verifying_key().to_bytes(), anchor());
    }

    #[test]
    fn verifies_golden_ns_record() {
        let rec = parse_signed_record(&bytes(GOLDEN)).unwrap();
        assert_eq!(rec.type_byte, 2);
        assert_eq!(rec.name, "www.chooseforce.ztlp");
        assert_eq!(rec.created_at, 1_800_000_000);
        assert_eq!(rec.ttl, 86_400);
        assert_eq!(rec.serial, 1_800_000_000);
        let v = verify(&rec, &[anchor()], NOW).unwrap();
        assert_eq!(v.signer, anchor());
        assert_eq!(v.expires_at(), 1_800_086_400);
        assert_eq!(
            v.data_str("quic_cert_sha256").as_deref(),
            Some("abababababababababababababababababababababababababababababababab")
        );
        assert_eq!(v.data_str("address").as_deref(), Some("10.42.42.112:23097"));
        assert_eq!(v.data_str("zone").as_deref(), Some("chooseforce.ztlp"));
        assert_eq!(v.data_str("missing"), None);
        assert!(!v.registered_unsigned());
    }

    #[test]
    fn verifies_a_record_captured_from_a_live_name_server() {
        // Real KEY record reply from the live demo NS (web.demo.spongebob.ztlp,
        // 2026-08-30 capture, same bytes as proxy.rs's truncation-flag test).
        // Independent of the golden vector: proves the parser + verifier
        // match what a production NS really sends.
        let hex = "020100177765622e64656d6f2e73706f6e6765626f622e7a746c70000000bca567616464726573737433342e3232312e3136352e3234343a3234303935676e6f64655f69647820316236663535636661383563636630383032393236336433343865366361373769616c676f726974686d67456432353531396a7075626c69635f6b657978403464666533613937353466623466326166326135616134626239636132663139623730376431303262326362366264666435633366636165393739653663646473726567697374657265645f756e7369676e6564f5000000006a93b76900015180000000006a93b76900408339e10261b7135a9b92ed5f3b342b26fb7195a7950392e344eb6e11b8275a2a798cb2ae06391da17aedef3d311fdc01ed4805b42236294decd84eec0ebf8209002073193631c65c8252184a64b419dc1b5007021ba70eb531697f9b816596d986c9";
        let rec = parse_query_reply(&bytes(hex)).unwrap();
        assert_eq!(rec.type_byte, 1);
        assert_eq!(rec.name, "web.demo.spongebob.ztlp");
        let demo_ns: [u8; 32] =
            bytes("73193631c65c8252184a64b419dc1b5007021ba70eb531697f9b816596d986c9")
                .try_into()
                .unwrap();
        let v = verify(&rec, &[demo_ns], rec.created_at + 60).unwrap();
        assert_eq!(
            v.data_str("address").as_deref(),
            Some("34.221.165.244:24095")
        );
        // Same bytes are untrusted without the demo NS key.
        assert_eq!(
            verify(&rec, &[anchor()], rec.created_at + 60),
            Err(NsVerifyError::UntrustedSigner)
        );
    }

    #[test]
    fn query_reply_with_status_byte_parses() {
        let mut reply = vec![0x02];
        reply.extend(bytes(GOLDEN));
        let rec = parse_query_reply(&reply).unwrap();
        assert!(verify(&rec, &[anchor()], NOW).is_ok());
    }

    #[test]
    fn not_found_and_truncated_replies_do_not_parse() {
        assert!(parse_query_reply(&[0x03]).is_err());
        assert!(parse_query_reply(&[]).is_err());
        // NS amplification cap: <<0x02, 0x01, first N bytes of the record>>.
        let full = bytes(GOLDEN);
        let mut truncated = vec![0x02, 0x01];
        truncated.extend_from_slice(&full[..200]);
        assert!(parse_query_reply(&truncated).is_err());
    }

    #[test]
    fn flipped_cbor_byte_is_bad_signature() {
        let mut b = bytes(GOLDEN);
        // name "www.chooseforce.ztlp" is 20 bytes: data starts at 1+2+20+4.
        b[27 + 5] ^= 0x01;
        let rec = parse_signed_record(&b).unwrap();
        assert_eq!(
            verify(&rec, &[anchor()], NOW),
            Err(NsVerifyError::BadSignature)
        );
    }

    #[test]
    fn flipped_serial_is_bad_signature() {
        // Replay with a bumped serial must not verify.
        let mut b = bytes(GOLDEN);
        let rec = parse_signed_record(&b).unwrap();
        let serial_last = rec.canonical.len() - 1;
        b[serial_last] ^= 0x01;
        let rec = parse_signed_record(&b).unwrap();
        assert_eq!(
            verify(&rec, &[anchor()], NOW),
            Err(NsVerifyError::BadSignature)
        );
    }

    #[test]
    fn signer_not_in_anchors_is_untrusted() {
        let rec = parse_signed_record(&bytes(GOLDEN)).unwrap();
        let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify(&rec, &[other], NOW),
            Err(NsVerifyError::UntrustedSigner)
        );
        assert_eq!(verify(&rec, &[], NOW), Err(NsVerifyError::UntrustedSigner));
    }

    #[test]
    fn record_re_signed_by_an_attacker_key_is_untrusted() {
        // Attacker signs a valid record with their own key and embeds
        // their pubkey: the embedded key must never be trusted by itself.
        let rec = parse_signed_record(&bytes(GOLDEN)).unwrap();
        use ed25519_dalek::Signer;
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let sig = attacker.sign(&rec.canonical).to_bytes();
        let mut forged = rec.canonical.clone();
        forged.extend_from_slice(&64u16.to_be_bytes());
        forged.extend_from_slice(&sig);
        forged.extend_from_slice(&32u16.to_be_bytes());
        forged.extend_from_slice(&attacker.verifying_key().to_bytes());
        let f = parse_signed_record(&forged).unwrap();
        assert_eq!(
            verify(&f, &[anchor()], NOW),
            Err(NsVerifyError::UntrustedSigner)
        );
    }

    #[test]
    fn trusted_pubkey_with_foreign_signature_is_bad_signature() {
        // Attacker keeps the trusted pubkey field but signs with their key.
        let rec = parse_signed_record(&bytes(GOLDEN)).unwrap();
        use ed25519_dalek::Signer;
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let sig = attacker.sign(&rec.canonical).to_bytes();
        let mut forged = rec.canonical.clone();
        forged.extend_from_slice(&64u16.to_be_bytes());
        forged.extend_from_slice(&sig);
        forged.extend_from_slice(&32u16.to_be_bytes());
        forged.extend_from_slice(&anchor());
        let f = parse_signed_record(&forged).unwrap();
        assert_eq!(
            verify(&f, &[anchor()], NOW),
            Err(NsVerifyError::BadSignature)
        );
    }

    #[test]
    fn expired_fixture_is_expired() {
        let rec = parse_signed_record(&bytes(GOLDEN_EXPIRED)).unwrap();
        assert_eq!(verify(&rec, &[anchor()], NOW), Err(NsVerifyError::Expired));
    }

    #[test]
    fn expiry_boundary_is_exclusive() {
        let rec = parse_signed_record(&bytes(GOLDEN)).unwrap();
        assert!(verify(&rec, &[anchor()], 1_800_086_399).is_ok());
        assert_eq!(
            verify(&rec, &[anchor()], 1_800_086_400),
            Err(NsVerifyError::Expired)
        );
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let b = bytes(GOLDEN);
        for n in 0..b.len() {
            assert!(
                parse_signed_record(&b[..n]).is_err(),
                "prefix len {n} parsed"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut b = bytes(GOLDEN);
        b.push(0);
        assert_eq!(parse_signed_record(&b), Err(NsVerifyError::TrailingBytes));
    }

    #[test]
    fn wrong_sig_len_is_rejected() {
        let b = bytes(GOLDEN);
        let rec = parse_signed_record(&b).unwrap();
        let mut bad = rec.canonical.clone();
        bad.extend_from_slice(&63u16.to_be_bytes());
        bad.extend_from_slice(&rec.signature[..63]);
        bad.extend_from_slice(&32u16.to_be_bytes());
        bad.extend_from_slice(&rec.signer);
        assert_eq!(
            parse_signed_record(&bad),
            Err(NsVerifyError::BadSignatureLength(63))
        );
    }

    #[test]
    fn wrong_pub_len_is_rejected() {
        let b = bytes(GOLDEN);
        let rec = parse_signed_record(&b).unwrap();
        let mut bad = rec.canonical.clone();
        bad.extend_from_slice(&64u16.to_be_bytes());
        bad.extend_from_slice(&rec.signature);
        bad.extend_from_slice(&33u16.to_be_bytes());
        bad.extend_from_slice(&rec.signer);
        bad.push(0);
        assert_eq!(
            parse_signed_record(&bad),
            Err(NsVerifyError::BadPublicKeyLength(33))
        );
    }

    #[test]
    fn huge_length_fields_do_not_panic() {
        let mut b = vec![2u8, 0xff, 0xff];
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse_signed_record(&b), Err(NsVerifyError::Truncated));
        let mut b = vec![2u8, 0x00, 0x01, b'a', 0xff, 0xff, 0xff, 0xff];
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse_signed_record(&b), Err(NsVerifyError::Truncated));
    }

    #[test]
    fn data_str_ignores_non_text_values() {
        let v = VerifiedRecord {
            type_byte: 2,
            name: "x".into(),
            // CBOR {"n": 5}
            data_cbor: vec![0xa1, 0x61, b'n', 0x05],
            signer: [0; 32],
            created_at: 0,
            ttl: 0,
            serial: 0,
        };
        assert_eq!(v.data_str("n"), None);
        let bad = VerifiedRecord {
            data_cbor: vec![0xff, 0x00],
            ..v
        };
        assert_eq!(bad.data_str("n"), None);
    }
}
