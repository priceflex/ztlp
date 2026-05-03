//! Linux-runnable harness for IosTunnelEngine / MuxEngine development.
//!
//! These tests compile and run on Linux against the `ios-sync` feature set so
//! we can iterate on the Nebula-style collapse (plan:
//! docs/plans/2026-05-03-ios-nebula-collapse.md) without an iOS device in the
//! loop.
//!
//! Intentionally minimal — Phase 0 baseline only. Later phases add unit tests
//! for UDP transport, MuxEngine codec, rwnd policy, send buffer, and session
//! health directly inside the module under test. This harness just proves the
//! ios-sync feature build compiles and that the module is reachable from an
//! external integration test.

#![cfg(feature = "ios-sync")]

#[test]
fn harness_loads_ios_utun_module() {
    // Smoke test: we just need the ios-sync feature build to compile and link
    // the IosUtun type. Passing fd=-1 means no real kernel fd is opened.
    let utun = ztlp_proto::ios_tunnel_engine::IosUtun::new(-1);
    assert_eq!(utun.fd(), -1);
}
