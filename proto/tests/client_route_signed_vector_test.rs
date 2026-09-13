//! Interop vector: CLIENT_ROUTE (0x5A 0x37 0x0B) frame HMAC-signed with a
//! relay-wide secret, exactly as `ztlp agent` / `ztlp connect` emit it when
//! `[tunnel] relay_secret` / `--relay-secret` is configured (2026-09-13).
//!
//! The Elixir relay in `ZTLP_RELAY_HMAC_MODE=prod` must accept THIS frame
//! (`relay/test/ztlp_relay/client_route_prod_hmac_test.exs` reads the
//! fixture written here) and must reject the zero-HMAC variant. Fixed
//! timestamp so the fixture is byte-stable; the relay test patches its
//! clock window accordingly (it only checks |now - ts| <= 300 s, so the
//! Elixir test rebuilds the frame with a fresh ts using the SAME secret
//! and cross-checks the HMAC algorithm against this vector).

use std::fs;
use std::path::PathBuf;

use ztlp_proto::tunnel::{build_client_route_packet, decode_relay_secret};

const SECRET_HEX: &str = "03949c364265e5e2cf0eb0f90a27cf51b97e85c2564a9ece899d6daab2a70d7c";

#[test]
fn client_route_signed_vector_matches_relay_rules_and_is_written() {
    let key = decode_relay_secret(SECRET_HEX);
    assert_eq!(key.len(), 32, "64-hex secret must decode to 32 raw bytes");

    let node_id = [0x42u8; 16];
    let service = "demo-dashboard";
    let ts: i64 = 1_800_000_000;

    let signed = build_client_route_packet(&node_id, service, ts, Some(&key)).unwrap();
    let unsigned = build_client_route_packet(&node_id, service, ts, None).unwrap();

    // Layout: magic(2) type(1) node_id(16) svc_len(1) svc(14) ts(8) hmac(32)
    assert_eq!(signed.len(), 2 + 1 + 16 + 1 + service.len() + 8 + 32);
    assert_eq!(&signed[..3], &[0x5A, 0x37, 0x0B]);
    assert_eq!(
        &signed[..signed.len() - 32],
        &unsigned[..unsigned.len() - 32]
    );
    assert_ne!(&signed[signed.len() - 32..], &[0u8; 32]);
    assert_eq!(&unsigned[unsigned.len() - 32..], &[0u8; 32]);

    // Independent recomputation: HMAC-SHA256(key, type||node_id||svc_len||svc||ts)
    {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let signed_material = &signed[2..signed.len() - 32];
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(signed_material);
        assert_eq!(
            mac.finalize().into_bytes().as_slice(),
            &signed[signed.len() - 32..]
        );
    }

    let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    let json = format!(
        "{{\n  \"secret_hex\": \"{}\",\n  \"node_id_hex\": \"{}\",\n  \"service\": \"{}\",\n  \"timestamp\": {},\n  \"frame_signed_hex\": \"{}\",\n  \"frame_unsigned_hex\": \"{}\"\n}}\n",
        SECRET_HEX,
        hex(&node_id),
        service,
        ts,
        hex(&signed),
        hex(&unsigned)
    );

    let out: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("relay")
        .join("test")
        .join("fixtures")
        .join("client_route_signed_vector.json");
    fs::create_dir_all(out.parent().unwrap()).unwrap();
    fs::write(&out, &json).unwrap();
    assert!(fs::read_to_string(&out)
        .unwrap()
        .contains("frame_signed_hex"));
}
