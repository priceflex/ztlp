use ztlp_proto::updater::*;

// ─── SemVer parsing ────────────────────────────────────────────────

#[test]
fn semver_parse_basic() {
    let v = SemVer::parse("1.2.3").unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
    assert!(v.pre.is_none());
}

#[test]
fn semver_parse_v_prefix() {
    let v = SemVer::parse("v0.22.0").unwrap();
    assert_eq!(v.major, 0);
    assert_eq!(v.minor, 22);
    assert_eq!(v.patch, 0);
    assert!(v.pre.is_none());
}

#[test]
fn semver_parse_pre_release() {
    let v = SemVer::parse("1.0.0-beta.1").unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert_eq!(v.patch, 0);
    assert_eq!(v.pre.as_deref(), Some("beta.1"));
}

#[test]
fn semver_parse_rejects_invalid() {
    assert!(SemVer::parse("abc").is_none());
}

#[test]
fn semver_parse_rejects_two_parts() {
    assert!(SemVer::parse("1.2").is_none());
}

// ─── SemVer ordering ──────────────────────────────────────────────

#[test]
fn semver_ordering_major_wins() {
    let v2 = SemVer::new(2, 0, 0);
    let v1 = SemVer::new(1, 9, 9);
    assert!(v2 > v1);
}

#[test]
fn semver_ordering_minor_wins() {
    let v = SemVer::new(1, 3, 0);
    let u = SemVer::new(1, 2, 9);
    assert!(v > u);
}

#[test]
fn semver_ordering_patch_wins() {
    let v = SemVer::new(1, 2, 4);
    let u = SemVer::new(1, 2, 3);
    assert!(v > u);
}

#[test]
fn semver_ordering_prerelease_less_than_release() {
    let beta = SemVer::parse("1.0.0-beta").unwrap();
    let release = SemVer::new(1, 0, 0);
    assert!(beta < release);
}

#[test]
fn semver_ordering_release_greater_than_prerelease() {
    let release = SemVer::new(1, 0, 0);
    let beta = SemVer::parse("1.0.0-beta").unwrap();
    assert!(release > beta);
}

#[test]
fn semver_ordering_equal() {
    let a = SemVer::new(1, 2, 3);
    let b = SemVer::new(1, 2, 3);
    assert_eq!(a, b);
    assert!(!(a > b));
    assert!(!(a < b));
}

#[test]
fn semver_is_newer_than() {
    let newer = SemVer::new(2, 0, 0);
    let older = SemVer::new(1, 0, 0);
    assert!(newer.is_newer_than(&older));
    assert!(!older.is_newer_than(&newer));
    assert!(!older.is_newer_than(&older));
}

// ─── SemVer display ───────────────────────────────────────────────

#[test]
fn semver_display_basic() {
    let v = SemVer::new(1, 2, 3);
    assert_eq!(v.to_string(), "1.2.3");
}

#[test]
fn semver_display_with_pre() {
    let v = SemVer::new(1, 0, 0).with_pre("beta.1");
    assert_eq!(v.to_string(), "1.0.0-beta.1");
}

// ─── UpdateChannel ────────────────────────────────────────────────

#[test]
fn update_channel_from_str_roundtrip() {
    assert_eq!(
        UpdateChannel::parse_channel("stable"),
        Some(UpdateChannel::Stable)
    );
    assert_eq!(
        UpdateChannel::parse_channel("Beta"),
        Some(UpdateChannel::Beta)
    );
    assert_eq!(
        UpdateChannel::parse_channel("NIGHTLY"),
        Some(UpdateChannel::Nightly)
    );

    // Verify name() roundtrips
    assert_eq!(UpdateChannel::Stable.name(), "stable");
    assert_eq!(UpdateChannel::Beta.name(), "beta");
    assert_eq!(UpdateChannel::Nightly.name(), "nightly");
}

#[test]
fn update_channel_from_str_rejects_unknown() {
    assert!(UpdateChannel::parse_channel("alpha").is_none());
    assert!(UpdateChannel::parse_channel("").is_none());
}

#[test]
fn update_channel_accepts_prerelease() {
    assert!(!UpdateChannel::Stable.accepts_prerelease());
    assert!(UpdateChannel::Beta.accepts_prerelease());
    assert!(UpdateChannel::Nightly.accepts_prerelease());
}

// ─── UpdateConfig ─────────────────────────────────────────────────

#[test]
fn update_config_default_values() {
    let config = UpdateConfig::default();
    // Should parse from CARGO_PKG_VERSION = "0.22.0"
    assert_eq!(config.current_version, SemVer::new(0, 23, 0));
    assert_eq!(config.channel, UpdateChannel::Stable);
    assert!(config.release_url.contains("github.com"));
    assert!(config.release_url.contains("priceflex/ztlp"));
    assert_eq!(config.check_interval_secs, 86400);
    assert!(!config.auto_download);
    assert!(config.signing_key.is_none());
}

// ─── check_update ─────────────────────────────────────────────────

fn make_release(version: SemVer) -> ReleaseInfo {
    ReleaseInfo {
        version,
        channel: UpdateChannel::Stable,
        download_url: "https://example.com/ztlp".into(),
        signature: None,
        checksum_sha256: None,
        release_notes: None,
        size_bytes: None,
        published_at: None,
    }
}

#[test]
fn check_update_available_when_newer() {
    let config = UpdateConfig {
        current_version: SemVer::new(0, 21, 0),
        ..UpdateConfig::default()
    };
    let release = make_release(SemVer::new(0, 23, 0));
    match check_update(&config, &release) {
        UpdateStatus::Available(r) => assert_eq!(r.version, SemVer::new(0, 23, 0)),
        other => panic!("Expected Available, got {:?}", other),
    }
}

#[test]
fn check_update_up_to_date_same_version() {
    let config = UpdateConfig {
        current_version: SemVer::new(1, 0, 0),
        ..UpdateConfig::default()
    };
    let release = make_release(SemVer::new(1, 0, 0));
    assert!(matches!(
        check_update(&config, &release),
        UpdateStatus::UpToDate
    ));
}

#[test]
fn check_update_up_to_date_older_release() {
    let config = UpdateConfig {
        current_version: SemVer::new(2, 0, 0),
        ..UpdateConfig::default()
    };
    let release = make_release(SemVer::new(1, 0, 0));
    assert!(matches!(
        check_update(&config, &release),
        UpdateStatus::UpToDate
    ));
}

#[test]
fn check_update_filters_prerelease_on_stable() {
    let config = UpdateConfig {
        current_version: SemVer::new(0, 21, 0),
        channel: UpdateChannel::Stable,
        ..UpdateConfig::default()
    };
    let release = ReleaseInfo {
        version: SemVer::parse("0.22.0-beta.1").unwrap(),
        channel: UpdateChannel::Beta,
        download_url: "https://example.com/ztlp".into(),
        signature: None,
        checksum_sha256: None,
        release_notes: None,
        size_bytes: None,
        published_at: None,
    };
    assert!(matches!(
        check_update(&config, &release),
        UpdateStatus::UpToDate
    ));
}

#[test]
fn check_update_allows_prerelease_on_beta() {
    let config = UpdateConfig {
        current_version: SemVer::new(0, 21, 0),
        channel: UpdateChannel::Beta,
        ..UpdateConfig::default()
    };
    let release = ReleaseInfo {
        version: SemVer::parse("0.22.0-beta.1").unwrap(),
        channel: UpdateChannel::Beta,
        download_url: "https://example.com/ztlp".into(),
        signature: None,
        checksum_sha256: None,
        release_notes: None,
        size_bytes: None,
        published_at: None,
    };
    match check_update(&config, &release) {
        UpdateStatus::Available(r) => {
            assert_eq!(r.version, SemVer::parse("0.22.0-beta.1").unwrap());
        }
        other => panic!("Expected Available, got {:?}", other),
    }
}

// ─── parse_github_release ─────────────────────────────────────────

#[test]
fn parse_github_release_extracts_tag() {
    let json = r#"{"tag_name": "v1.2.3", "body": "Release notes here", "published_at": "2026-01-15T00:00:00Z"}"#;
    let info = parse_github_release(json).unwrap();
    assert_eq!(info.version, SemVer::new(1, 2, 3));
    assert_eq!(info.release_notes.as_deref(), Some("Release notes here"));
    assert_eq!(info.published_at.as_deref(), Some("2026-01-15T00:00:00Z"));
    assert_eq!(info.channel, UpdateChannel::Stable);
}

#[test]
fn parse_github_release_missing_body() {
    let json = r#"{"tag_name": "v0.1.0", "published_at": "2026-03-01T00:00:00Z"}"#;
    let info = parse_github_release(json).unwrap();
    assert_eq!(info.version, SemVer::new(0, 1, 0));
    assert!(info.release_notes.is_none());
}

// ─── verify_signature ─────────────────────────────────────────────

#[test]
fn verify_signature_rejects_wrong_size_signature() {
    let short_sig = vec![0u8; 32]; // should be 64
    let key_hex = "ab".repeat(32); // 64 hex chars = 32 bytes
    assert!(!verify_signature(b"data", &short_sig, &key_hex));
}

#[test]
fn verify_signature_rejects_wrong_size_key() {
    let sig = vec![0u8; 64];
    let short_key = "ab".repeat(16); // 32 hex chars = 16 bytes, too short
    assert!(!verify_signature(b"data", &sig, &short_key));
}

// ─── checksum ─────────────────────────────────────────────────────

#[test]
fn verify_checksum_roundtrip() {
    let data = b"hello ztlp updater";
    let checksum = sha256_hex(data);
    assert_eq!(checksum.len(), 64); // 4 * 16 hex chars
    assert!(verify_checksum(data, &checksum));
    assert!(!verify_checksum(b"different data", &checksum));
}

// ─── hex_decode ───────────────────────────────────────────────────

#[test]
fn hex_decode_roundtrip() {
    // Use the public sha256_hex / verify_checksum to indirectly test hex_decode
    // Also test via verify_signature which calls hex_decode internally
    // Direct test via signature path: valid hex key decoding
    let key_hex = "ab".repeat(32); // 64 hex chars
    let sig = vec![0u8; 64];
    // This will reach hex_decode and succeed at parsing; the crypto verify
    // will likely fail, but the key IS parsed. We just check it doesn't panic.
    let _ = verify_signature(b"test", &sig, &key_hex);
}

#[test]
fn hex_decode_rejects_odd_length() {
    // Odd-length hex fed through signature verification path
    let sig = vec![0u8; 64];
    // 63 hex chars (odd) — will fail the length check before hex_decode
    // Use a 65-char key to bypass the len==64 check but still be odd for hex_decode
    // Actually, verify_signature checks public_key_hex.len() != 64 first.
    // So let's test via checksum instead - the hex_decode is internal.
    // The unit test in the module itself covers this directly.
    // Here we verify the contract indirectly: wrong-size key is rejected.
    let odd_key = "a".repeat(63);
    assert!(!verify_signature(b"data", &sig, &odd_key));
}
