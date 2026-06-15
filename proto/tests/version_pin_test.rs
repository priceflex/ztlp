//! Version-string regression pins for the `ztlp-proto` Rust crate.
//!
//! Companion to the `release_test.exs` "version reporting (regression pin)"
//! describe blocks in `relay/`, `gateway/`, and `ns/`. The relay defect that
//! motivated those tests — git tag cut without bumping the version in
//! `mix.exs`, so runtime `Application.spec(_, :vsn)` lied about the deployed
//! tag — is structurally possible for every component in this repo, including
//! the Rust proto crate (which historically lagged the Elixir tree).
//!
//! What these tests guarantee:
//!
//! 1. `CARGO_PKG_VERSION` parses as semver (i.e. `Cargo.toml`'s `version =`
//!    field is well-formed).
//! 2. `CARGO_PKG_VERSION` is at least [`MINIMUM_VERSION`], the version of the
//!    v0.29.4 strict-routing tag. A floor guard (rather than an exact-match
//!    assertion) means this test does NOT need to be touched on every routine
//!    bump — it only fails on an accidental down-bump or on a freshly cut tag
//!    that forgot to update `Cargo.toml`.
//!
//! References:
//! - `relay/test/ztlp_relay/release_test.exs` for the canonical Elixir version
//!   of these checks (and the on-call story that explains why they exist).
//! - `~/hermes_session_handoff.md` "Known Problems #6" / "Open Question #1"
//!   for the broader version-string-drift story.
//!
//! Implementation note: we deliberately re-use the in-crate
//! [`ztlp_proto::updater::SemVer`] rather than pulling in the external
//! `semver` crate. The proto already uses this homegrown parser for
//! self-update version comparisons, so this test exercises the same code
//! path the updater does — if its parser ever regresses, this test will
//! catch it alongside the version-pin bug.

use std::cmp::Ordering;
use ztlp_proto::updater::SemVer;

/// Minimum semver any future commit on this crate is required to declare.
/// Bump this floor only when the project's release-management policy explicitly
/// says pre-`MINIMUM_VERSION` builds are no longer supported.
///
/// Ratcheted 0.29.4 → 0.30.3 in PR <release/v0.30.3> after the v0.30.3 git
/// tag was cut from `a5993ee` (PR #40 — Z2LS gateway-auth enrollment API).
/// Ratcheted 0.30.3 → 0.30.4 in PR <release/v0.30.4> after the original
/// v0.30.4 tag was found to point at `6e9d40b`, whose manifests still read
/// 0.30.3. v0.30.4 is being re-cut from the post-bump commit so the tag
///
/// Ratcheted 0.32.2 → 0.34.4 in PR <release/v0.34.4> to align the floor with
/// the v0.34 family: v0.34 (granular registration error codes, PR #77),
/// v0.34.1 (relay control-frame exemption), v0.34.2 (gateway SVC refresh cap,
/// PR #80), v0.34.3 (NS mixed-case enrollment, PR #81), v0.34.4 (D4 Windows
/// NRPT DNS interception PR #82, D5 browser TLS green-lock PR #83, D6 UI
/// Setup Wizard PR #84). Per the release-version-pinning skill pitfall 13,
/// the floor must track the current release; leaving it at 0.32.2 while
/// manifests sit at 0.34.x lets future down-bumps slip through silently.
/// Ratcheted 0.35.0 → 0.35.1 in PR <fix/connect-relay-fallback-on-stale-nat>
/// after the connect path gained relay-forwarding fallback when all direct
/// candidates fail (NAT'd endpoints with stale srflx ports no longer go dark).
const MINIMUM_VERSION: &str = "0.35.1";

#[test]
fn cargo_pkg_version_is_parseable_semver() {
    let raw = env!("CARGO_PKG_VERSION");
    let parsed = SemVer::parse(raw).unwrap_or_else(|| {
        panic!(
            "CARGO_PKG_VERSION {raw:?} must be a parseable semver \
             (MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-PRE)"
        )
    });

    // Sanity: a parsed semver round-trips through Display to the same text.
    // This guards against the parser silently accepting input that doesn't
    // round-trip (e.g. extra components, weird casing).
    assert_eq!(
        parsed.to_string(),
        raw,
        "semver round-trip mismatch — proto/Cargo.toml version field is malformed",
    );
}

#[test]
fn cargo_pkg_version_is_at_least_minimum_floor() {
    let raw = env!("CARGO_PKG_VERSION");
    let actual = SemVer::parse(raw).expect("CARGO_PKG_VERSION must be a parseable semver string");
    let floor = SemVer::parse(MINIMUM_VERSION)
        .expect("MINIMUM_VERSION constant must be a parseable semver");

    match actual.cmp(&floor) {
        Ordering::Greater | Ordering::Equal => { /* OK */ }
        Ordering::Less => panic!(
            "proto/Cargo.toml version {actual} is older than the v{floor} strict-routing tag. \
             Bump `version = \"...\"` in proto/Cargo.toml. \
             See hermes_session_handoff.md Known Problems #6 for context."
        ),
    }
}
