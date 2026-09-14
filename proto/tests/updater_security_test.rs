//! Security-focused tests for `ztlp_proto::updater` that go beyond the
//! format/size checks in `updater_test.rs`: real Ed25519 verification with a
//! generated keypair (accept / reject on tampered data, tampered signature,
//! wrong key), hex-key parsing edge cases, and the GitHub release JSON
//! asset-selection logic that decides *which binary* gets downloaded.

use ed25519_dalek::{Signer, SigningKey};
use ztlp_proto::updater::*;

fn keypair(seed: u8) -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk_hex)
}

// ─── verify_signature: real cryptography ────────────────────────────────

#[test]
fn verify_signature_accepts_valid_signature() {
    let (sk, pk_hex) = keypair(7);
    let data = b"ztlp release binary bytes";
    let sig = sk.sign(data).to_bytes();
    assert!(verify_signature(data, &sig, &pk_hex));
}

#[test]
fn verify_signature_accepts_empty_message() {
    let (sk, pk_hex) = keypair(8);
    let sig = sk.sign(b"").to_bytes();
    assert!(verify_signature(b"", &sig, &pk_hex));
}

#[test]
fn verify_signature_rejects_tampered_data() {
    let (sk, pk_hex) = keypair(7);
    let data = b"ztlp release binary bytes";
    let sig = sk.sign(data).to_bytes();
    let mut tampered = data.to_vec();
    tampered[0] ^= 0x01;
    assert!(
        !verify_signature(&tampered, &sig, &pk_hex),
        "single-bit flip must fail"
    );
    let mut appended = data.to_vec();
    appended.push(0);
    assert!(
        !verify_signature(&appended, &sig, &pk_hex),
        "appended byte must fail"
    );
}

#[test]
fn verify_signature_rejects_tampered_signature() {
    let (sk, pk_hex) = keypair(7);
    let data = b"payload";
    let mut sig = sk.sign(data).to_bytes();
    sig[10] ^= 0x80;
    assert!(!verify_signature(data, &sig, &pk_hex));
}

#[test]
fn verify_signature_rejects_wrong_public_key() {
    let (sk, _) = keypair(1);
    let (_, other_pk_hex) = keypair(2);
    let data = b"payload";
    let sig = sk.sign(data).to_bytes();
    assert!(!verify_signature(data, &sig, &other_pk_hex));
}

#[test]
fn verify_signature_rejects_all_zero_signature() {
    let (_, pk_hex) = keypair(3);
    assert!(!verify_signature(b"payload", &[0u8; 64], &pk_hex));
}

#[test]
fn verify_signature_rejects_65_byte_signature() {
    let (sk, pk_hex) = keypair(7);
    let mut sig = sk.sign(b"x").to_bytes().to_vec();
    sig.push(0);
    assert!(!verify_signature(b"x", &sig, &pk_hex));
}

#[test]
fn verify_signature_rejects_non_hex_key_of_correct_length() {
    let (sk, _) = keypair(7);
    let sig = sk.sign(b"x").to_bytes();
    let bad_key = "zz".repeat(32); // 64 chars, not hex
    assert!(!verify_signature(b"x", &sig, &bad_key));
}

#[test]
fn verify_signature_rejects_uppercase_hex_mismatch_is_not_an_issue() {
    // Hex decoding must be case-insensitive: an uppercase key is the same key.
    let (sk, pk_hex) = keypair(9);
    let sig = sk.sign(b"x").to_bytes();
    assert!(verify_signature(b"x", &sig, &pk_hex.to_uppercase()));
}

#[test]
fn verify_signature_rejects_invalid_curve_point_key() {
    // 64 hex chars that decode to 32 bytes but are not a valid compressed
    // Edwards point (all 0xFF has the top bit set and y >= p).
    let (sk, _) = keypair(7);
    let sig = sk.sign(b"x").to_bytes();
    let bad_key = "ff".repeat(32);
    assert!(!verify_signature(b"x", &sig, &bad_key));
}

#[test]
fn verify_signature_rejects_multibyte_utf8_key_of_len_64_bytes() {
    // 64 *bytes* of UTF-8 that is not ASCII hex — must not panic on slicing.
    let (sk, _) = keypair(7);
    let sig = sk.sign(b"x").to_bytes();
    let key = "é".repeat(32); // 2 bytes each -> 64 bytes
    assert_eq!(key.len(), 64);
    assert!(!verify_signature(b"x", &sig, &key));
}

// ─── checksum ────────────────────────────────────────────────────────────

#[test]
fn sha256_hex_is_deterministic_and_64_chars() {
    let a = sha256_hex(b"hello");
    let b = sha256_hex(b"hello");
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha256_hex_differs_for_different_inputs() {
    assert_ne!(sha256_hex(b"hello"), sha256_hex(b"hellp"));
    assert_ne!(sha256_hex(b""), sha256_hex(b"\0"));
}

#[test]
fn verify_checksum_rejects_mismatch_and_case_variants() {
    let data = b"binary";
    let good = sha256_hex(data);
    assert!(verify_checksum(data, &good));
    assert!(!verify_checksum(b"binarx", &good));
    assert!(!verify_checksum(data, ""));
    // Comparison is exact string equality: uppercase digest is rejected.
    if good != good.to_uppercase() {
        assert!(!verify_checksum(data, &good.to_uppercase()));
    }
}

// ─── parse_github_release: asset selection ──────────────────────────────

fn expected_asset_pattern() -> String {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    format!("ztlp-{os}-{arch}")
}

#[test]
fn parse_github_release_picks_matching_platform_asset() {
    let pat = expected_asset_pattern();
    let json = format!(
        r#"{{
          "tag_name": "v1.2.3",
          "published_at": "2026-09-01T00:00:00Z",
          "body": "notes here",
          "assets": [
            {{"name": "ztlp-windows-amd64.exe", "browser_download_url": "https://x/ztlp-windows-amd64.exe"}},
            {{"name": "{pat}", "browser_download_url": "https://x/{pat}"}},
            {{"name": "other", "browser_download_url": "https://x/other"}}
          ]
        }}"#
    );
    let info = parse_github_release(&json).unwrap();
    assert_eq!(info.version, SemVer::new(1, 2, 3));
    assert_eq!(info.download_url, format!("https://x/{pat}"));
    assert_eq!(info.published_at.as_deref(), Some("2026-09-01T00:00:00Z"));
    assert_eq!(info.release_notes.as_deref(), Some("notes here"));
    assert_eq!(info.channel, UpdateChannel::Stable);
    assert!(info.signature.is_none());
    assert!(info.checksum_sha256.is_none());
    assert!(info.size_bytes.is_none());
}

#[test]
fn parse_github_release_falls_back_to_generic_url_when_no_asset_matches() {
    let json = r#"{"tag_name": "v2.0.0", "assets": [
        {"browser_download_url": "https://x/ztlp-plan9-mips"}
    ]}"#;
    let info = parse_github_release(json).unwrap();
    assert_eq!(
        info.download_url,
        "https://github.com/priceflex/ztlp/releases/download/v2.0.0/ztlp"
    );
}

#[test]
fn parse_github_release_fallback_url_keeps_v_prefix_in_tag() {
    let json = r#"{"tag_name": "3.1.4"}"#;
    let info = parse_github_release(json).unwrap();
    assert_eq!(info.version, SemVer::new(3, 1, 4));
    assert!(info.download_url.ends_with("/download/3.1.4/ztlp"));
}

#[test]
fn parse_github_release_prerelease_tag_maps_to_beta_channel() {
    let json = r#"{"tag_name": "v1.0.0-beta.2"}"#;
    let info = parse_github_release(json).unwrap();
    assert_eq!(info.channel, UpdateChannel::Beta);
    assert!(info.version.is_pre_release());
    assert_eq!(info.version.pre.as_deref(), Some("beta.2"));
}

#[test]
fn parse_github_release_requires_tag_name() {
    assert!(parse_github_release(r#"{"body": "x"}"#).is_none());
    assert!(parse_github_release("").is_none());
    assert!(
        parse_github_release(r#"{"tag_name": 123}"#).is_none(),
        "non-string tag"
    );
    assert!(parse_github_release(r#"{"tag_name": "not-a-version"}"#).is_none());
    assert!(parse_github_release(r#"{"tag_name": "v1.2"}"#).is_none());
}

#[test]
fn parse_github_release_tolerates_whitespace_around_colon() {
    let json = "{ \"tag_name\"   :\n   \"v0.9.9\" }";
    let info = parse_github_release(json).unwrap();
    assert_eq!(info.version, SemVer::new(0, 9, 9));
}

#[test]
fn parse_github_release_unterminated_string_is_rejected() {
    assert!(parse_github_release(r#"{"tag_name": "v1.0.0"#).is_none());
}

#[test]
fn parse_github_release_asset_url_missing_value_does_not_loop_forever() {
    // `browser_download_url` present but with a non-string value; the scanner
    // must advance past it and fall back.
    let json = r#"{"tag_name": "v1.0.0", "assets": [
        {"browser_download_url": null},
        {"browser_download_url": 42}
    ]}"#;
    let info = parse_github_release(json).unwrap();
    assert!(info.download_url.contains("/download/v1.0.0/ztlp"));
}

// Regression (found+fixed 2026-09-13): `extract_asset_url` used to slice
// the JSON from the start of the *unquoted* word `browser_download_url`, then
// searches for the *quoted* key, so it always reads the NEXT asset's URL. The
// first asset is never examined. If the platform binary is the first (or only)
// asset, the updater falls back to the generic `/download/<tag>/ztlp` URL.
#[test]
fn parse_github_release_finds_single_first_asset() {
    let pat = expected_asset_pattern();
    let json = format!(
        r#"{{"tag_name":"v1.0.0","assets":[{{"browser_download_url":"https://only/{pat}"}}]}}"#
    );
    let info = parse_github_release(&json).unwrap();
    assert_eq!(info.download_url, format!("https://only/{pat}"));
}

#[test]
fn parse_github_release_picks_first_matching_asset() {
    let pat = expected_asset_pattern();
    let json = format!(
        r#"{{"tag_name":"v1.0.0","assets":[
            {{"browser_download_url":"https://first/{pat}.tar.gz"}},
            {{"browser_download_url":"https://second/{pat}"}}
        ]}}"#
    );
    let info = parse_github_release(&json).unwrap();
    assert_eq!(info.download_url, format!("https://first/{pat}.tar.gz"));
}

// ─── check_update channel matrix ────────────────────────────────────────

fn rel(v: &str) -> ReleaseInfo {
    ReleaseInfo {
        version: SemVer::parse(v).unwrap(),
        channel: UpdateChannel::Stable,
        download_url: String::new(),
        signature: None,
        checksum_sha256: None,
        release_notes: None,
        size_bytes: None,
        published_at: None,
    }
}

fn cfg(v: &str, ch: UpdateChannel) -> UpdateConfig {
    UpdateConfig {
        current_version: SemVer::parse(v).unwrap(),
        ..UpdateConfig::default()
    }
    .with_channel(ch)
}

#[test]
fn check_update_nightly_accepts_prerelease() {
    match check_update(
        &cfg("1.0.0", UpdateChannel::Nightly),
        &rel("1.0.1-nightly.20260913"),
    ) {
        UpdateStatus::Available(r) => {
            assert_eq!(r.version.pre.as_deref(), Some("nightly.20260913"))
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn check_update_beta_does_not_downgrade_to_older_prerelease() {
    // 1.0.0-beta.1 < 1.0.0 (current): must not be offered.
    assert!(matches!(
        check_update(&cfg("1.0.0", UpdateChannel::Beta), &rel("1.0.0-beta.1")),
        UpdateStatus::UpToDate
    ));
}

#[test]
fn check_update_stable_ignores_prerelease_even_if_much_newer() {
    assert!(matches!(
        check_update(&cfg("1.0.0", UpdateChannel::Stable), &rel("9.0.0-rc.1")),
        UpdateStatus::UpToDate
    ));
}

#[test]
fn check_update_stable_offers_release_when_current_is_prerelease() {
    // Running 1.0.0-beta.3 on stable: 1.0.0 final is newer and allowed.
    match check_update(&cfg("1.0.0-beta.3", UpdateChannel::Stable), &rel("1.0.0")) {
        UpdateStatus::Available(r) => assert_eq!(r.version, SemVer::new(1, 0, 0)),
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn update_status_check_failed_is_debug_printable() {
    let s = UpdateStatus::CheckFailed("network down".into());
    assert!(format!("{s:?}").contains("network down"));
}

// ─── config builders / channel names ────────────────────────────────────

#[test]
fn update_config_builders_chain() {
    let c = UpdateConfig::default()
        .with_channel(UpdateChannel::Nightly)
        .with_signing_key("ab".repeat(32).as_str())
        .with_interval(0);
    assert_eq!(c.channel, UpdateChannel::Nightly);
    assert_eq!(c.signing_key.as_deref().map(str::len), Some(64));
    assert_eq!(c.check_interval_secs, 0);
    assert!(!c.auto_download);
}

#[test]
fn update_config_default_version_matches_crate_version() {
    let c = UpdateConfig::default();
    assert_eq!(
        c.current_version,
        SemVer::parse(env!("CARGO_PKG_VERSION")).unwrap()
    );
    assert_ne!(
        c.current_version,
        SemVer::new(0, 0, 0),
        "fallback must not be hit"
    );
}

#[test]
fn update_channel_name_roundtrips_through_parse() {
    for ch in [
        UpdateChannel::Stable,
        UpdateChannel::Beta,
        UpdateChannel::Nightly,
    ] {
        assert_eq!(UpdateChannel::parse_channel(ch.name()), Some(ch));
        assert_eq!(
            UpdateChannel::parse_channel(&ch.name().to_uppercase()),
            Some(ch)
        );
    }
    assert_eq!(UpdateChannel::parse_channel(" stable"), None, "no trimming");
}

// ─── SemVer edge cases not in updater_test.rs ───────────────────────────

#[test]
fn semver_prerelease_ordering_is_lexicographic() {
    let a = SemVer::parse("1.0.0-alpha").unwrap();
    let b = SemVer::parse("1.0.0-beta").unwrap();
    let rc = SemVer::parse("1.0.0-rc.1").unwrap();
    assert!(b.is_newer_than(&a));
    assert!(rc.is_newer_than(&b));
    assert!(a < b && b < rc);
}

#[test]
fn semver_prerelease_numeric_suffix_compares_as_string() {
    // Pin documented behaviour: "beta.10" < "beta.2" lexicographically.
    let ten = SemVer::parse("1.0.0-beta.10").unwrap();
    let two = SemVer::parse("1.0.0-beta.2").unwrap();
    assert!(two.is_newer_than(&ten));
}

#[test]
fn semver_parse_rejects_negative_empty_and_overflow() {
    assert!(SemVer::parse("-1.0.0").is_some() == false || SemVer::parse("-1.0.0").is_none());
    assert!(SemVer::parse("1..0").is_none());
    assert!(SemVer::parse("1.0.").is_none());
    assert!(SemVer::parse("").is_none());
    assert!(SemVer::parse("v").is_none());
    assert!(SemVer::parse("99999999999.0.0").is_none(), "u32 overflow");
    assert!(SemVer::parse("1.0.0.0").is_none());
    assert!(SemVer::parse("1.0.0-")
        .map(|v| v.pre == Some(String::new()))
        .unwrap_or(false));
}

#[test]
fn semver_with_pre_builder_and_display() {
    let v = SemVer::new(2, 5, 0).with_pre("rc.3");
    assert!(v.is_pre_release());
    assert_eq!(v.to_string(), "2.5.0-rc.3");
    assert_eq!(SemVer::parse(&v.to_string()).unwrap(), v);
}

#[test]
fn semver_partial_ord_agrees_with_ord() {
    let a = SemVer::new(1, 2, 3);
    let b = SemVer::new(1, 2, 4);
    assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Less));
    assert_eq!(b.partial_cmp(&a), Some(std::cmp::Ordering::Greater));
    assert_eq!(a.partial_cmp(&a.clone()), Some(std::cmp::Ordering::Equal));
    assert!(!a.is_newer_than(&a));
}
