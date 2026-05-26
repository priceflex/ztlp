//! Cross-platform smoke tests for the ztlp-service `run` (SCM dispatcher) surface.
//!
//! On Linux these assert the "requires Windows SCM" error path so we don't
//! accidentally ship a no-op stub. On Windows we only verify the function
//! symbol exists at compile time — real SCM exercise requires admin and is
//! handled manually per D2.T5.

use ztlp_service::service;

#[cfg(not(target_os = "windows"))]
#[test]
fn run_service_returns_unsupported_on_non_windows() {
    let err = service::run_service().expect_err("run_service() must fail on non-Windows targets");
    let msg = format!("{err}");
    assert!(
        msg.contains("requires Windows SCM"),
        "expected 'requires Windows SCM' error, got: {msg}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_run_service_symbol_exists() {
    // Real SCM dispatch is exercised manually on Steve's bench per D2.T5;
    // here we just confirm the symbol is reachable so the build doesn't drift.
    let _ = service::run_service;
}
