//! Hourly NS check-in that keeps an ENROLLED device registered (v0.35.19).
//!
//! An enrolled device's KEY record in ZTLP-NS is what lets a gateway turn
//! the device's tunnel key into a `device-name` (and owner). The NS gives
//! that record a one-year TTL. Every [`check_interval`] (default 1h) the
//! agent re-registers the same KEY record, signed with the Ed25519 signing
//! key it enrolled with; the NS accepts that as the device checking in and
//! restarts the one-year window. A machine that is on therefore never
//! expires, and one that stays off for more than a year must re-enroll.
//!
//! The check-in sends exactly the fields the ENROLL path stored
//! (`algorithm`, `node_id`, `public_key` = X25519 tunnel key,
//! `signing_public_key` = Ed25519 key). The NS refuses any change to them,
//! so a check-in can never move a name to a different key.
//!
//! Flow per tick: query NS by our tunnel pubkey (0x05) to learn our name,
//! then send the signed KEY registration (0x09 v2). Records enrolled before
//! v0.35.19 carry no `signing_public_key`; they are reported as needing a
//! one-time re-enrollment instead of being retried every hour.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::agent::config::{parse_duration_str, AgentConfig, RenewalConfig};
use crate::identity::NodeIdentity;
use crate::ns_cbor::{cbor_extract_string, parse_ns_record, NsResponseStatus};

/// Default time between check-ins.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Floor for the check-in interval: the NS rate-limits re-registration of
/// the same `{name, type}` to once per 60 s, so anything faster is refused.
pub const MIN_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// How long to wait for each NS reply.
pub const NS_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

const KEY_RECORD_TYPE: u8 = 1;

/// Effective check-in interval from `[renewal] check_interval`
/// (e.g. `"1h"`). Unparseable values fall back to 1h; values under 60 s are
/// raised to 60 s.
pub fn check_interval(cfg: &RenewalConfig) -> Duration {
    let parsed = parse_duration_str(cfg.check_interval.trim()).unwrap_or(DEFAULT_CHECK_INTERVAL);
    parsed.max(MIN_CHECK_INTERVAL)
}

/// Whether (and how) the daemon should run the check-in loop: on when
/// `[renewal] enabled` (the default) and at least one NS server is
/// configured. Returns the NS servers and the interval.
pub fn checkin_plan(config: &AgentConfig) -> Option<(Vec<String>, Duration)> {
    if !config.renewal.enabled {
        return None;
    }
    let servers: Vec<String> = config
        .ns
        .servers
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if servers.is_empty() {
        return None;
    }
    Some((servers, check_interval(&config.renewal)))
}

fn cbor_head(major: u8, len: u64) -> Vec<u8> {
    let m = major << 5;
    match len {
        0..=23 => vec![m | len as u8],
        24..=0xFF => vec![m | 24, len as u8],
        0x100..=0xFFFF => {
            let mut v = vec![m | 25];
            v.extend_from_slice(&(len as u16).to_be_bytes());
            v
        }
        _ => {
            let mut v = vec![m | 26];
            v.extend_from_slice(&(len as u32).to_be_bytes());
            v
        }
    }
}

fn cbor_text(s: &str) -> Vec<u8> {
    let mut v = cbor_head(3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

/// CBOR map of text keys to text values (definite length).
fn cbor_text_map(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = cbor_head(5, pairs.len() as u64);
    for (k, v) in pairs {
        buf.extend_from_slice(&cbor_text(k));
        buf.extend_from_slice(&cbor_text(v));
    }
    buf
}

/// Hex of the X25519 tunnel key (what the enrolled record's `public_key` holds).
pub fn tunnel_pubkey_hex(identity: &NodeIdentity) -> String {
    hex::encode(&identity.static_public_key)
}

/// CBOR data of the enrolled KEY record, as the ENROLL path stored it.
pub fn enrolled_key_data(identity: &NodeIdentity) -> Vec<u8> {
    let node_id = hex::encode(identity.node_id.as_bytes());
    let public_key = tunnel_pubkey_hex(identity);
    let signing_public_key = identity.signing_public_key_hex();
    cbor_text_map(&[
        ("algorithm", "Ed25519"),
        ("node_id", &node_id),
        ("public_key", &public_key),
        ("signing_public_key", &signing_public_key),
    ])
}

/// Signed (v2) KEY registration for `name`, the check-in packet:
/// `<<0x09, name_len::16, name, 1, data_len::16, data, 64::16, sig, 32::16, pubkey>>`
/// where `sig` is Ed25519 over `<<1, name_len::16, name, data>>`.
pub fn build_checkin_packet(name: &str, identity: &NodeIdentity) -> Result<Vec<u8>, String> {
    let name_bytes = name.as_bytes();
    let name_len = u16::try_from(name_bytes.len())
        .map_err(|_| format!("name is {} bytes (max {})", name_bytes.len(), u16::MAX))?;
    let data = enrolled_key_data(identity);
    let data_len = u16::try_from(data.len())
        .map_err(|_| format!("record data is {} bytes (max {})", data.len(), u16::MAX))?;

    let mut canonical = Vec::with_capacity(3 + name_bytes.len() + data.len());
    canonical.push(KEY_RECORD_TYPE);
    canonical.extend_from_slice(&name_len.to_be_bytes());
    canonical.extend_from_slice(name_bytes);
    canonical.extend_from_slice(&data);

    let sig = identity.sign(&canonical);
    let pubkey = identity.signing_key().verifying_key().to_bytes();

    let mut pkt =
        Vec::with_capacity(1 + 2 + name_bytes.len() + 1 + 2 + data.len() + 2 + 64 + 2 + 32);
    pkt.push(0x09);
    pkt.extend_from_slice(&name_len.to_be_bytes());
    pkt.extend_from_slice(name_bytes);
    pkt.push(KEY_RECORD_TYPE);
    pkt.extend_from_slice(&data_len.to_be_bytes());
    pkt.extend_from_slice(&data);
    pkt.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&sig);
    pkt.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&pubkey);
    Ok(pkt)
}

/// NS query by public key (0x05): `<<0x05, hex_len::16, hex>>`.
pub fn build_pubkey_query(pubkey_hex: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(3 + pubkey_hex.len());
    q.push(0x05);
    q.extend_from_slice(&(pubkey_hex.len() as u16).to_be_bytes());
    q.extend_from_slice(pubkey_hex.as_bytes());
    q
}

/// What the NS knows about this device's tunnel key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnRecord {
    /// Registered under `name`; `renewable` when the record carries this
    /// identity's signing key (enrolled with v0.35.19+).
    Found { name: String, renewable: bool },
    /// No live record (never enrolled here, or expired after a year off).
    NotFound,
    /// The device was revoked.
    Revoked,
    /// Reply could not be parsed.
    Unparseable,
}

/// Interpret the NS reply to [`build_pubkey_query`].
pub fn parse_pubkey_reply(reply: &[u8], identity: &NodeIdentity) -> OwnRecord {
    let Some(rec) = parse_ns_record(reply) else {
        return OwnRecord::Unparseable;
    };
    match rec.status {
        NsResponseStatus::NotFound => OwnRecord::NotFound,
        NsResponseStatus::Revoked => OwnRecord::Revoked,
        NsResponseStatus::Found => {
            if rec.record_type != KEY_RECORD_TYPE || rec.name.is_empty() {
                return OwnRecord::Unparseable;
            }
            let ours = identity.signing_public_key_hex();
            let renewable = cbor_extract_string(&rec.data, "signing_public_key")
                .map(|k| k.eq_ignore_ascii_case(&ours))
                .unwrap_or(false)
                && cbor_extract_string(&rec.data, "public_key")
                    .map(|k| k.eq_ignore_ascii_case(&tunnel_pubkey_hex(identity)))
                    .unwrap_or(false);
            OwnRecord::Found {
                name: rec.name,
                renewable,
            }
        }
    }
}

/// Interpret the NS reply to a registration: `0x06` = accepted,
/// `0xFF <code>` = rejected.
pub fn parse_registration_reply(reply: &[u8]) -> Result<(), String> {
    match reply {
        [0x06, ..] => Ok(()),
        [0xFF, code, ..] => Err(format!(
            "NS rejected the check-in (error code 0x{code:02x})"
        )),
        [0xFF] => Err("NS rejected the check-in".to_string()),
        [] => Err("empty reply from NS".to_string()),
        [b, ..] => Err(format!("unexpected NS reply 0x{b:02x}")),
    }
}

/// Result of one check-in attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckinOutcome {
    /// The NS accepted the check-in; the one-year window restarted.
    Renewed(String),
    /// The NS has no live record for this device: it must be re-enrolled.
    NotRegistered,
    /// Registered, but with no signing key on record (enrolled by a pre-v0.35.19
    /// client or name server): works until the record expires; re-enroll once.
    NotRenewable(String),
    /// The device was revoked.
    Revoked,
    /// Network / NS error; retried next tick.
    Failed(String),
}

async fn exchange(
    sock: &UdpSocket,
    ns: &str,
    pkt: &[u8],
    wait: Duration,
) -> Result<Vec<u8>, String> {
    sock.send_to(pkt, ns)
        .await
        .map_err(|e| format!("send to NS {ns}: {e}"))?;
    let mut buf = vec![0u8; 65535];
    match timeout(wait, sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => Ok(buf[..len].to_vec()),
        Ok(Err(e)) => Err(format!("receive from NS {ns}: {e}")),
        Err(_) => Err(format!("no reply from NS {ns} within {wait:?}")),
    }
}

/// One check-in against one NS server (`host:port`).
pub async fn check_in_once(
    identity: &NodeIdentity,
    ns_server: &str,
    wait: Duration,
) -> CheckinOutcome {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return CheckinOutcome::Failed(format!("bind UDP socket: {e}")),
    };

    let query = build_pubkey_query(&tunnel_pubkey_hex(identity));
    let reply = match exchange(&sock, ns_server, &query, wait).await {
        Ok(r) => r,
        Err(e) => return CheckinOutcome::Failed(e),
    };
    let name = match parse_pubkey_reply(&reply, identity) {
        OwnRecord::Found {
            name,
            renewable: true,
        } => name,
        OwnRecord::Found {
            name,
            renewable: false,
        } => return CheckinOutcome::NotRenewable(name),
        OwnRecord::NotFound => return CheckinOutcome::NotRegistered,
        OwnRecord::Revoked => return CheckinOutcome::Revoked,
        OwnRecord::Unparseable => {
            return CheckinOutcome::Failed("unparseable reply to the pubkey query".to_string())
        }
    };

    let pkt = match build_checkin_packet(&name, identity) {
        Ok(p) => p,
        Err(e) => return CheckinOutcome::Failed(e),
    };
    match exchange(&sock, ns_server, &pkt, wait).await {
        Ok(r) => match parse_registration_reply(&r) {
            Ok(()) => CheckinOutcome::Renewed(name),
            Err(e) => CheckinOutcome::Failed(e),
        },
        Err(e) => CheckinOutcome::Failed(e),
    }
}

/// Try each configured NS in order; the first definite answer wins
/// (anything but `Failed`). All failing returns the last failure.
pub async fn check_in(
    identity: &NodeIdentity,
    ns_servers: &[String],
    wait: Duration,
) -> CheckinOutcome {
    let mut last = CheckinOutcome::Failed("no NS servers configured".to_string());
    for ns in ns_servers {
        let outcome = check_in_once(identity, ns, wait).await;
        if !matches!(outcome, CheckinOutcome::Failed(_)) {
            return outcome;
        }
        last = outcome;
    }
    last
}

fn log_outcome(outcome: &CheckinOutcome) {
    match outcome {
        CheckinOutcome::Renewed(name) => {
            info!("NS check-in: {name} renewed (registration valid for another year)")
        }
        CheckinOutcome::NotRegistered => warn!(
            "NS check-in: this device has no registration in the name server \
             (never enrolled here, or expired after a year offline). Re-enroll it."
        ),
        CheckinOutcome::NotRenewable(name) => warn!(
            "NS check-in: {name} has no renewal key on record (enrolled before v0.35.19, \
             by an older client or name server), so it cannot renew itself and expires at \
             the end of its current TTL. Re-enroll once to enable automatic yearly renewal."
        ),
        CheckinOutcome::Revoked => warn!("NS check-in: this device has been revoked"),
        CheckinOutcome::Failed(e) => warn!("NS check-in failed (will retry): {e}"),
    }
}

/// Check in now, then every `interval`, forever. Spawned by the daemon.
pub async fn run_checkin_loop(
    identity: Arc<NodeIdentity>,
    ns_servers: Vec<String>,
    interval: Duration,
) {
    loop {
        let outcome = check_in(&identity, &ns_servers, NS_REPLY_TIMEOUT).await;
        log_outcome(&outcome);
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn identity() -> NodeIdentity {
        NodeIdentity::generate().expect("identity")
    }

    fn cfg(interval: &str) -> RenewalConfig {
        RenewalConfig {
            check_interval: interval.to_string(),
            ..RenewalConfig::default()
        }
    }

    /// NS 0x05 FOUND reply for a KEY record.
    fn found_reply(name: &str, data: &[u8]) -> Vec<u8> {
        let mut r = vec![0x02, KEY_RECORD_TYPE];
        r.extend_from_slice(&(name.len() as u16).to_be_bytes());
        r.extend_from_slice(name.as_bytes());
        r.extend_from_slice(&(data.len() as u32).to_be_bytes());
        r.extend_from_slice(data);
        r
    }

    // ── interval ───────────────────────────────────────────────────────

    #[test]
    fn default_renewal_config_checks_in_hourly() {
        assert_eq!(
            check_interval(&RenewalConfig::default()),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn check_interval_parses_and_clamps() {
        assert_eq!(check_interval(&cfg("30m")), Duration::from_secs(1800));
        assert_eq!(check_interval(&cfg("10s")), MIN_CHECK_INTERVAL);
        assert_eq!(check_interval(&cfg("garbage")), DEFAULT_CHECK_INTERVAL);
        assert_eq!(check_interval(&cfg("")), DEFAULT_CHECK_INTERVAL);
    }

    // ── packets ────────────────────────────────────────────────────────

    #[test]
    fn enrolled_key_data_carries_tunnel_key_node_id_and_signing_key() {
        let id = identity();
        let data = enrolled_key_data(&id);
        assert_eq!(
            cbor_extract_string(&data, "algorithm").as_deref(),
            Some("Ed25519")
        );
        assert_eq!(
            cbor_extract_string(&data, "public_key"),
            Some(hex::encode(&id.static_public_key))
        );
        assert_eq!(
            cbor_extract_string(&data, "node_id"),
            Some(hex::encode(id.node_id.as_bytes()))
        );
        assert_eq!(
            cbor_extract_string(&data, "signing_public_key"),
            Some(id.signing_public_key_hex())
        );
    }

    #[test]
    fn checkin_packet_is_a_signed_v2_key_registration() {
        let id = identity();
        let name = "laptop.trs.ztlp";
        let pkt = build_checkin_packet(name, &id).unwrap();

        assert_eq!(pkt[0], 0x09);
        let nl = u16::from_be_bytes([pkt[1], pkt[2]]) as usize;
        assert_eq!(&pkt[3..3 + nl], name.as_bytes());
        let mut p = 3 + nl;
        assert_eq!(pkt[p], KEY_RECORD_TYPE);
        p += 1;
        let dl = u16::from_be_bytes([pkt[p], pkt[p + 1]]) as usize;
        p += 2;
        let data = &pkt[p..p + dl];
        assert_eq!(data, enrolled_key_data(&id).as_slice());
        p += dl;
        assert_eq!(u16::from_be_bytes([pkt[p], pkt[p + 1]]), 64);
        let sig: [u8; 64] = pkt[p + 2..p + 66].try_into().unwrap();
        p += 66;
        assert_eq!(u16::from_be_bytes([pkt[p], pkt[p + 1]]), 32);
        let pubkey: [u8; 32] = pkt[p + 2..p + 34].try_into().unwrap();
        assert_eq!(pkt.len(), p + 34);

        // The NS verifies Ed25519 over <<type, name_len::16, name, data>>.
        let mut canonical = vec![KEY_RECORD_TYPE];
        canonical.extend_from_slice(&(nl as u16).to_be_bytes());
        canonical.extend_from_slice(name.as_bytes());
        canonical.extend_from_slice(data);
        let vk = VerifyingKey::from_bytes(&pubkey).unwrap();
        vk.verify(&canonical, &Signature::from_bytes(&sig)).unwrap();
        assert_eq!(hex::encode(pubkey), id.signing_public_key_hex());
    }

    #[test]
    fn pubkey_query_wire_format() {
        assert_eq!(
            build_pubkey_query("abcd"),
            vec![0x05, 0x00, 0x04, b'a', b'b', b'c', b'd']
        );
    }

    // ── replies ────────────────────────────────────────────────────────

    #[test]
    fn found_record_with_our_signing_key_is_renewable() {
        let id = identity();
        let reply = found_reply("laptop.trs.ztlp", &enrolled_key_data(&id));
        assert_eq!(
            parse_pubkey_reply(&reply, &id),
            OwnRecord::Found {
                name: "laptop.trs.ztlp".into(),
                renewable: true
            }
        );
    }

    #[test]
    fn legacy_record_without_signing_key_is_not_renewable() {
        let id = identity();
        let tunnel = tunnel_pubkey_hex(&id);
        let node = hex::encode(id.node_id.as_bytes());
        let data = cbor_text_map(&[
            ("algorithm", "Ed25519"),
            ("node_id", &node),
            ("public_key", &tunnel),
        ]);
        assert_eq!(
            parse_pubkey_reply(&found_reply("old.trs.ztlp", &data), &id),
            OwnRecord::Found {
                name: "old.trs.ztlp".into(),
                renewable: false
            }
        );
    }

    #[test]
    fn record_with_someone_elses_signing_key_is_not_renewable() {
        let id = identity();
        let other = identity();
        let data = enrolled_key_data(&other);
        assert!(matches!(
            parse_pubkey_reply(&found_reply("x.trs.ztlp", &data), &id),
            OwnRecord::Found {
                renewable: false,
                ..
            }
        ));
    }

    #[test]
    fn not_found_revoked_and_garbage_replies() {
        let id = identity();
        assert_eq!(
            parse_pubkey_reply(&[0x03, 0x00, 0x00], &id),
            OwnRecord::NotFound
        );
        assert_eq!(
            parse_pubkey_reply(&[0x04, 0x00, 0x01, b'x'], &id),
            OwnRecord::Revoked
        );
        assert_eq!(parse_pubkey_reply(&[0x7f], &id), OwnRecord::Unparseable);
        assert_eq!(parse_pubkey_reply(&[], &id), OwnRecord::Unparseable);
    }

    #[test]
    fn registration_reply_codes() {
        assert!(parse_registration_reply(&[0x06]).is_ok());
        assert!(parse_registration_reply(&[0xFF, 0x0A])
            .unwrap_err()
            .contains("0x0a"));
        assert!(parse_registration_reply(&[]).is_err());
        assert!(parse_registration_reply(&[0x42]).is_err());
    }

    // ── against a fake NS over UDP ─────────────────────────────────────

    /// Fake NS: answers 0x05 with `pubkey_reply`, 0x09 with `reg_reply`,
    /// counts 0x09 packets and remembers the last one.
    async fn fake_ns(
        pubkey_reply: Vec<u8>,
        reg_reply: Vec<u8>,
    ) -> (String, Arc<AtomicUsize>, Arc<tokio::sync::Mutex<Vec<u8>>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let regs = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let (r2, l2) = (regs.clone(), last.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                match buf[0] {
                    0x05 => {
                        let _ = sock.send_to(&pubkey_reply, from).await;
                    }
                    0x09 => {
                        r2.fetch_add(1, Ordering::SeqCst);
                        *l2.lock().await = buf[..n].to_vec();
                        let _ = sock.send_to(&reg_reply, from).await;
                    }
                    _ => {}
                }
            }
        });
        (addr, regs, last)
    }

    #[tokio::test]
    async fn check_in_renews_an_enrolled_device() {
        let id = identity();
        let name = "laptop.trs.ztlp";
        let (ns, regs, last) =
            fake_ns(found_reply(name, &enrolled_key_data(&id)), vec![0x06]).await;

        let out = check_in_once(&id, &ns, Duration::from_secs(2)).await;
        assert_eq!(out, CheckinOutcome::Renewed(name.to_string()));
        assert_eq!(regs.load(Ordering::SeqCst), 1);
        assert_eq!(*last.lock().await, build_checkin_packet(name, &id).unwrap());
    }

    #[tokio::test]
    async fn check_in_reports_not_registered_without_sending_a_registration() {
        let id = identity();
        let (ns, regs, _) = fake_ns(vec![0x03, 0x00, 0x00], vec![0x06]).await;
        assert_eq!(
            check_in_once(&id, &ns, Duration::from_secs(2)).await,
            CheckinOutcome::NotRegistered
        );
        assert_eq!(regs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn check_in_does_not_hammer_a_legacy_enrollment() {
        let id = identity();
        let tunnel = tunnel_pubkey_hex(&id);
        let node = hex::encode(id.node_id.as_bytes());
        let data = cbor_text_map(&[
            ("algorithm", "Ed25519"),
            ("node_id", &node),
            ("public_key", &tunnel),
        ]);
        let (ns, regs, _) = fake_ns(found_reply("old.trs.ztlp", &data), vec![0x06]).await;
        assert_eq!(
            check_in_once(&id, &ns, Duration::from_secs(2)).await,
            CheckinOutcome::NotRenewable("old.trs.ztlp".to_string())
        );
        assert_eq!(regs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn check_in_surfaces_an_ns_rejection() {
        let id = identity();
        let (ns, _, _) = fake_ns(
            found_reply("a.trs.ztlp", &enrolled_key_data(&id)),
            vec![0xFF, 0x07],
        )
        .await;
        assert!(matches!(
            check_in_once(&id, &ns, Duration::from_secs(2)).await,
            CheckinOutcome::Failed(e) if e.contains("0x07")
        ));
    }

    #[tokio::test]
    async fn check_in_times_out_on_a_silent_ns_and_falls_over_to_the_next() {
        let id = identity();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap().to_string();
        let (good, regs, _) = fake_ns(
            found_reply("b.trs.ztlp", &enrolled_key_data(&id)),
            vec![0x06],
        )
        .await;

        let out = check_in(&id, &[silent_addr, good], Duration::from_millis(300)).await;
        assert_eq!(out, CheckinOutcome::Renewed("b.trs.ztlp".to_string()));
        assert_eq!(regs.load(Ordering::SeqCst), 1);
        drop(silent);
    }

    #[tokio::test]
    async fn checkin_loop_checks_in_immediately_on_start() {
        // A laptop waking from sleep restarts nothing, but a daemon (re)start
        // must not wait a full interval before its first check-in.
        let id = Arc::new(identity());
        let (ns, regs, _) = fake_ns(
            found_reply("c.trs.ztlp", &enrolled_key_data(&id)),
            vec![0x06],
        )
        .await;
        let handle = tokio::spawn(run_checkin_loop(id, vec![ns], Duration::from_secs(10)));
        tokio::time::sleep(Duration::from_millis(500)).await;
        handle.abort();
        assert_eq!(regs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn checkin_loop_repeats_every_interval() {
        let id = Arc::new(identity());
        let (ns, regs, _) = fake_ns(
            found_reply("d.trs.ztlp", &enrolled_key_data(&id)),
            vec![0x06],
        )
        .await;
        let handle = tokio::spawn(run_checkin_loop(id, vec![ns], Duration::from_millis(100)));
        tokio::time::sleep(Duration::from_millis(1000)).await;
        handle.abort();
        let n = regs.load(Ordering::SeqCst);
        assert!(n >= 4, "expected repeated check-ins, got {n}");
    }

    // ── daemon wiring ──────────────────────────────────────────────────

    fn agent_cfg(servers: &[&str], enabled: bool, interval: &str) -> AgentConfig {
        let mut c = AgentConfig::default();
        c.ns.servers = servers.iter().map(|s| s.to_string()).collect();
        c.renewal.enabled = enabled;
        c.renewal.check_interval = interval.to_string();
        c
    }

    #[test]
    fn daemon_checks_in_hourly_by_default() {
        let c = agent_cfg(&["198.51.100.7:23096"], true, "1h");
        assert_eq!(
            checkin_plan(&c),
            Some((
                vec!["198.51.100.7:23096".to_string()],
                Duration::from_secs(3600)
            ))
        );
        // Out of the box (no [renewal] block at all) it is on, hourly.
        let mut d = AgentConfig::default();
        d.ns.servers = vec!["198.51.100.7:23096".to_string()];
        assert_eq!(
            checkin_plan(&d).map(|p| p.1),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn daemon_skips_check_in_when_disabled_or_no_ns() {
        assert_eq!(
            checkin_plan(&agent_cfg(&["198.51.100.7:23096"], false, "1h")),
            None
        );
        assert_eq!(checkin_plan(&agent_cfg(&[], true, "1h")), None);
        assert_eq!(checkin_plan(&agent_cfg(&["  "], true, "1h")), None);
    }
}
