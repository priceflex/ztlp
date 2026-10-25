//! Trust established at enrollment (NS-anchored gateway trust, Phase 4).
//!
//! A token minted with `--ns-key` (flag 0x10) carries the home name
//! server's Ed25519 public key. During `ztlp setup` the device:
//!
//! 1. builds `ns_trust.toml` with that key as its HOME server for the
//!    token's zone (no trust on first use: the key came out of band);
//! 2. if the ENROLL reply carries the home-signed NSSET (optional trailing
//!    field, NS v0.36+), verifies it with the token key and merges it;
//!    an NSSET that does not verify fails enrollment;
//! 3. looks up its own freshly enrolled KEY record with verification against
//!    the token key: this proves the server it enrolled with holds that key.
//!    If it does not verify, enrollment fails.

use super::ns_trust::{NsServerTrust, NsTrustStore};
use crate::ns_verify;

/// The optional signed NSSET appended to the ENROLL success config
/// (`<<relay_count, relays.., gw_count, gws.., nsset_len::16, nsset>>`).
/// `Ok(None)` for an old NS (nothing after the gateways).
pub fn nsset_from_enroll_config(config: &[u8]) -> Result<Option<&[u8]>, String> {
    let mut pos = 0usize;
    let mut skip_list = |what: &str| -> Result<bool, String> {
        let Some(&count) = config.get(pos) else {
            return Ok(false);
        };
        pos += 1;
        for i in 0..count {
            let len = config
                .get(pos..pos + 2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
                .ok_or_else(|| format!("ENROLL reply truncated in {what} {i}"))?;
            pos += 2;
            if config.len() < pos + len {
                return Err(format!("ENROLL reply truncated in {what} {i}"));
            }
            pos += len;
        }
        Ok(true)
    };
    if !skip_list("relay")? || !skip_list("gateway")? {
        return Ok(None);
    }
    if pos == config.len() {
        return Ok(None);
    }
    let len = config
        .get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .ok_or("ENROLL reply truncated at NSSET length")?;
    pos += 2;
    let nsset = config
        .get(pos..pos + len)
        .ok_or("ENROLL reply truncated in NSSET")?;
    if pos + len != config.len() {
        return Err("ENROLL reply has trailing bytes after the NSSET".into());
    }
    Ok(Some(nsset))
}

/// Initial trust store for a device enrolled with a token carrying
/// `ns_key`. `nsset_raw` is the optional `Record.encode` NSSET from the
/// ENROLL reply; when present it must verify against `ns_key` and merge.
pub fn initial_trust_store(
    ns_addr: &str,
    zone: &str,
    ns_key: [u8; 32],
    nsset_raw: Option<&[u8]>,
    now: u64,
) -> Result<NsTrustStore, String> {
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    let store = NsTrustStore {
        servers: vec![NsServerTrust {
            addr: ns_addr.to_string(),
            key: ns_key,
            zones: vec![zone],
            home: true,
        }],
    };
    let Some(raw) = nsset_raw else {
        return Ok(store);
    };
    let parsed = ns_verify::parse_signed_record(raw)
        .map_err(|e| format!("NSSET in the enrollment reply: {e}"))?;
    let rec = ns_verify::verify(&parsed, &[ns_key], now).map_err(|e| {
        format!("NSSET in the enrollment reply is not signed by the token's name-server key ({e})")
    })?;
    super::nsset::merge_nsset(&store, &rec)
        .map_err(|e| format!("NSSET in the enrollment reply: {e}"))
}

/// Confirm that the NS the device enrolled with holds `ns_key`: its own
/// KEY record must come back signed by that key and carry the device's
/// tunnel public key.
pub async fn confirm_home_key(
    ns_addr: &str,
    full_name: &str,
    ns_key: [u8; 32],
    tunnel_pubkey_hex: &str,
) -> Result<(), String> {
    use super::proxy::{ns_query_verified, NsAnswer, NsTrust};
    let trust = NsTrust {
        anchors: vec![ns_key],
        strict: true,
        cache_dir: None,
    };
    match ns_query_verified(full_name, ns_addr, 1, &trust).await {
        Ok(NsAnswer::Verified(rec)) => match rec.data_str("public_key") {
            Some(pk) if pk.eq_ignore_ascii_case(tunnel_pubkey_hex) => Ok(()),
            other => Err(format!(
                "name server returned a KEY record for {full_name} with a different key ({})",
                other.unwrap_or_default()
            )),
        },
        Ok(NsAnswer::NotFound) => Err(format!(
            "name server has no record for {full_name} right after enrolling it"
        )),
        Ok(NsAnswer::Unverified(_)) => Err("name-server answer not verified".into()),
        Err(e) => Err(format!(
            "could not verify the name server against the token's key: {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn enc(s: &str) -> Vec<u8> {
        let mut v = (s.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn config(relays: &[&str], gws: &[&str], nsset: Option<&[u8]>) -> Vec<u8> {
        let mut c = vec![relays.len() as u8];
        for r in relays {
            c.extend(enc(r));
        }
        c.push(gws.len() as u8);
        for g in gws {
            c.extend(enc(g));
        }
        if let Some(n) = nsset {
            c.extend_from_slice(&(n.len() as u16).to_be_bytes());
            c.extend_from_slice(n);
        }
        c
    }

    fn signed_nsset(
        sk: &SigningKey,
        zone: &str,
        servers: &[(&str, [u8; 32])],
        now: u64,
    ) -> Vec<u8> {
        use ciborium::value::Value;
        let list = servers
            .iter()
            .map(|(a, k)| {
                Value::Map(vec![
                    (Value::Text("addr".into()), Value::Text((*a).into())),
                    (Value::Text("pubkey".into()), Value::Text(hex::encode(k))),
                ])
            })
            .collect();
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![
                (Value::Text("kind".into()), Value::Text("nsset".into())),
                (Value::Text("servers".into()), Value::Array(list)),
                (Value::Text("zone".into()), Value::Text(zone.into())),
            ]),
            &mut cbor,
        )
        .unwrap();
        let mut c = vec![7u8];
        c.extend_from_slice(&(zone.len() as u16).to_be_bytes());
        c.extend_from_slice(zone.as_bytes());
        c.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
        c.extend_from_slice(&cbor);
        c.extend_from_slice(&(now - 5).to_be_bytes());
        c.extend_from_slice(&3600u32.to_be_bytes());
        c.extend_from_slice(&now.to_be_bytes());
        let sig = sk.sign(&c).to_bytes();
        c.extend_from_slice(&64u16.to_be_bytes());
        c.extend_from_slice(&sig);
        c.extend_from_slice(&32u16.to_be_bytes());
        c.extend_from_slice(&sk.verifying_key().to_bytes());
        c
    }

    const NOW: u64 = 1_800_000_000;

    fn home() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    #[test]
    fn old_reply_without_nsset() {
        let c = config(&["1.2.3.4:23095"], &[], None);
        assert_eq!(nsset_from_enroll_config(&c).unwrap(), None);
        assert_eq!(nsset_from_enroll_config(&[]).unwrap(), None);
        assert_eq!(
            nsset_from_enroll_config(&[0]).unwrap(),
            None,
            "relays only, no gw byte"
        );
    }

    #[test]
    fn new_reply_with_nsset() {
        let n = vec![9u8; 40];
        let c = config(&["1.2.3.4:23095", "5.6.7.8:1"], &["gw:1"], Some(&n));
        assert_eq!(nsset_from_enroll_config(&c).unwrap(), Some(&n[..]));
    }

    #[test]
    fn malformed_trailers_are_errors() {
        let mut c = config(&["r:1"], &[], Some(&[1, 2, 3]));
        c.push(0);
        assert!(nsset_from_enroll_config(&c).is_err(), "trailing byte");
        let c = config(&["r:1"], &[], Some(&[1, 2, 3]));
        assert!(
            nsset_from_enroll_config(&c[..c.len() - 1]).is_err(),
            "short nsset"
        );
        let mut c = config(&["r:1"], &[], None);
        c.push(0); // half a length
        assert!(nsset_from_enroll_config(&c).is_err());
    }

    #[test]
    fn trust_store_without_nsset_is_just_the_home_server() {
        let k = home().verifying_key().to_bytes();
        let s = initial_trust_store("44.227.148.151:23096", "TRS.ztlp.", k, None, NOW).unwrap();
        assert_eq!(s.servers.len(), 1);
        assert!(s.servers[0].home);
        assert_eq!(s.servers[0].zones, vec!["trs.ztlp"]);
        assert!(s.strict_for("www.trs.ztlp"));
    }

    #[test]
    fn verified_nsset_from_the_reply_is_merged() {
        let k = home().verifying_key().to_bytes();
        let replica = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
        let n = signed_nsset(&home(), "trs.ztlp", &[("h:1", k), ("r:1", replica)], NOW);
        let s = initial_trust_store("h:1", "trs.ztlp", k, Some(&n), NOW).unwrap();
        assert_eq!(s.anchors_for("x.trs.ztlp"), vec![k, replica]);
    }

    #[test]
    fn nsset_signed_by_another_key_fails_enrollment() {
        let k = home().verifying_key().to_bytes();
        let evil = SigningKey::from_bytes(&[9; 32]);
        let n = signed_nsset(
            &evil,
            "trs.ztlp",
            &[("evil:1", evil.verifying_key().to_bytes())],
            NOW,
        );
        let err = initial_trust_store("h:1", "trs.ztlp", k, Some(&n), NOW).unwrap_err();
        assert!(
            err.contains("not signed by the token's name-server key"),
            "{err}"
        );
    }

    #[test]
    fn garbage_nsset_fails_enrollment() {
        let k = home().verifying_key().to_bytes();
        assert!(initial_trust_store("h:1", "trs.ztlp", k, Some(&[1, 2, 3]), NOW).is_err());
    }

    // ── confirm_home_key over the wire ─────────────────────────────────

    fn key_record_reply(sk: &SigningKey, name: &str, tunnel_hex: &str) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(
            &ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Text("public_key".into()),
                ciborium::value::Value::Text(tunnel_hex.into()),
            )]),
            &mut cbor,
        )
        .unwrap();
        let mut c = vec![1u8];
        c.extend_from_slice(&(name.len() as u16).to_be_bytes());
        c.extend_from_slice(name.as_bytes());
        c.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
        c.extend_from_slice(&cbor);
        c.extend_from_slice(&(now - 5).to_be_bytes());
        c.extend_from_slice(&31_536_000u32.to_be_bytes());
        c.extend_from_slice(&now.to_be_bytes());
        let sig = sk.sign(&c).to_bytes();
        c.extend_from_slice(&64u16.to_be_bytes());
        c.extend_from_slice(&sig);
        c.extend_from_slice(&32u16.to_be_bytes());
        c.extend_from_slice(&sk.verifying_key().to_bytes());
        let mut r = vec![0x02];
        r.extend(c);
        r
    }

    async fn fake_ns(reply: Vec<u8>) -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            if let Ok((_, src)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&reply, src).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn confirm_home_key_accepts_the_real_ns() {
        let tunnel = "ab".repeat(32);
        let ns = fake_ns(key_record_reply(&home(), "dev.trs.ztlp", &tunnel)).await;
        confirm_home_key(
            &ns,
            "dev.trs.ztlp",
            home().verifying_key().to_bytes(),
            &tunnel,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn confirm_home_key_rejects_an_impostor_ns() {
        let tunnel = "ab".repeat(32);
        let evil = SigningKey::from_bytes(&[9; 32]);
        let ns = fake_ns(key_record_reply(&evil, "dev.trs.ztlp", &tunnel)).await;
        let err = confirm_home_key(
            &ns,
            "dev.trs.ztlp",
            home().verifying_key().to_bytes(),
            &tunnel,
        )
        .await
        .unwrap_err();
        assert!(err.contains("could not verify"), "{err}");
    }

    #[tokio::test]
    async fn confirm_home_key_rejects_a_record_with_another_tunnel_key() {
        let ns = fake_ns(key_record_reply(&home(), "dev.trs.ztlp", &"cd".repeat(32))).await;
        let err = confirm_home_key(
            &ns,
            "dev.trs.ztlp",
            home().verifying_key().to_bytes(),
            &"ab".repeat(32),
        )
        .await
        .unwrap_err();
        assert!(err.contains("different key"), "{err}");
    }
}
