//! Smoke tests for D2.T4 token-file ACL hardening.
//!
//! On Linux: assert `harden_token_file_acl()` is a no-op returning Ok — install()
//! on non-Windows bails out before reaching the ACL step anyway, so the public
//! function being a safe no-op is the entire invariant we need here.
//!
//! On Windows: this file is compile-only. Real ACL verification requires an
//! Administrator-elevated shell on a Windows host and is the D2.T5 manual gate.

use ztlp_service::install::harden_token_file_acl;

#[test]
#[cfg(not(target_os = "windows"))]
fn harden_token_file_acl_is_noop_on_non_windows() {
    // Repeat invocation is idempotent (no panics, no side-effects).
    harden_token_file_acl().expect("non-Windows stub must return Ok");
    harden_token_file_acl().expect("non-Windows stub must remain idempotent");
}

#[test]
#[cfg(target_os = "windows")]
fn harden_token_file_acl_symbol_exists_on_windows() {
    // Compile-only smoke: confirm the symbol is reachable. Calling it in CI
    // would require admin rights to icacls, which is reserved for D2.T5.
    let _ = harden_token_file_acl;
}
