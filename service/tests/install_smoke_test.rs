//! Cross-platform smoke tests for the ztlp-service install/uninstall surface.
//!
//! On Linux these assert the "unsupported on this platform" error path so we
//! don't accidentally ship a no-op stub. On Windows we only verify the
//! function symbols exist at compile time — real sc.exe integration requires
//! admin and is exercised manually per D2.T5.

use ztlp_service::install;

#[cfg(not(target_os = "windows"))]
#[test]
fn install_returns_unsupported_on_non_windows() {
    let err = install::install().expect_err("install() must fail on non-Windows targets");
    let msg = format!("{err}");
    assert!(
        msg.contains("only supported on Windows"),
        "expected unsupported-platform error, got: {msg}"
    );
}

#[cfg(not(target_os = "windows"))]
#[test]
fn uninstall_returns_unsupported_on_non_windows() {
    let err = install::uninstall().expect_err("uninstall() must fail on non-Windows targets");
    let msg = format!("{err}");
    assert!(
        msg.contains("only supported on Windows"),
        "expected unsupported-platform error, got: {msg}"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_install_function_exists() {
    // integration tested manually on Steve's bench per D2.T5
    let _ = install::install;
    let _ = install::uninstall;
}
