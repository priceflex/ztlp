//! D3.T1: OS-user binding for node identities.
//!
//! At enrollment time, `ztlp setup --bind-user` records the current OS user's
//! stable identifier into `identity.json` under `bound_user_sid`. On daemon
//! startup the recorded identifier is compared against the current process's
//! user identifier; on mismatch the daemon emits a structured
//! `bound_user_mismatch` log event and refuses to operate.
//!
//! Identifier format is platform-specific:
//! - **Windows**: a SID string (e.g. `S-1-5-21-...`) read from
//!   `whoami /user /fo csv /nh`.
//! - **Unix** (Linux/macOS): `uid:<numeric uid>`, read from `id -u`.
//!
//! The shell-out approach (versus calling libc directly) keeps the
//! implementation portable, avoids `unsafe` (forbidden crate-wide), and matches
//! the operational expectation: if `whoami`/`id` is missing or broken, we'd
//! rather degrade than misidentify the user.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::process::Command;

use crate::identity::NodeIdentity;

/// Errors produced while resolving or verifying the bound user identity.
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    /// The identity is bound to a different OS user than the one running this
    /// process.
    #[error("identity is bound to user {expected} but current user is {actual}")]
    Mismatch {
        /// The SID/uid recorded in identity.json at enrollment time.
        expected: String,
        /// The SID/uid of the user running this process.
        actual: String,
    },

    /// The current user identity could not be resolved (e.g. `whoami`/`id`
    /// missing, malformed output, non-UTF-8). Callers may choose to treat this
    /// as a hard failure (during `--bind-user` enrollment) or as a warning
    /// (during daemon startup, to avoid bricking on a broken environment).
    #[error("failed to resolve current user identity: {0}")]
    ResolutionFailed(String),
}

/// Resolve the current process's stable user identifier.
///
/// On Windows this is the user SID; on Unix it is `uid:<uid>`.
pub fn current_user_sid() -> Result<String, BindingError> {
    #[cfg(windows)]
    {
        current_user_sid_windows()
    }
    #[cfg(unix)]
    {
        current_user_sid_unix()
    }
    #[cfg(not(any(windows, unix)))]
    {
        Err(BindingError::ResolutionFailed(
            "unsupported platform".to_string(),
        ))
    }
}

#[cfg(unix)]
fn current_user_sid_unix() -> Result<String, BindingError> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| BindingError::ResolutionFailed(format!("failed to spawn `id -u`: {}", e)))?;

    if !output.status.success() {
        return Err(BindingError::ResolutionFailed(format!(
            "`id -u` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| {
        BindingError::ResolutionFailed(format!("non-UTF-8 output from `id -u`: {}", e))
    })?;
    let uid_str = stdout.trim();
    if uid_str.is_empty() {
        return Err(BindingError::ResolutionFailed(
            "`id -u` returned empty output".to_string(),
        ));
    }
    // Validate it's actually numeric so we fail clearly rather than binding to
    // garbage if the shim happens to print a banner.
    uid_str.parse::<u64>().map_err(|e| {
        BindingError::ResolutionFailed(format!(
            "`id -u` returned non-numeric output {:?}: {}",
            uid_str, e
        ))
    })?;
    Ok(format!("uid:{}", uid_str))
}

#[cfg(windows)]
fn current_user_sid_windows() -> Result<String, BindingError> {
    // `whoami /user /fo csv /nh` prints a single line like:
    //   "DOMAIN\\user","S-1-5-21-1111-2222-3333-1001"
    let output = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|e| BindingError::ResolutionFailed(format!("failed to spawn `whoami`: {}", e)))?;

    if !output.status.success() {
        return Err(BindingError::ResolutionFailed(format!(
            "`whoami /user` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| {
        BindingError::ResolutionFailed(format!("non-UTF-8 output from `whoami`: {}", e))
    })?;
    let line = stdout.lines().next().ok_or_else(|| {
        BindingError::ResolutionFailed("`whoami /user` produced no output".to_string())
    })?;

    // Parse second CSV column. Values are wrapped in double quotes.
    let cols: Vec<&str> = line.split(',').collect();
    if cols.len() < 2 {
        return Err(BindingError::ResolutionFailed(format!(
            "unexpected `whoami /user` output: {:?}",
            line
        )));
    }
    let sid = cols[1].trim().trim_matches('"').to_string();
    if !sid.starts_with("S-") {
        return Err(BindingError::ResolutionFailed(format!(
            "`whoami /user` did not return a SID, got {:?}",
            sid
        )));
    }
    Ok(sid)
}

/// Verify that `identity`'s recorded user binding (if any) matches `current_sid`.
///
/// Returns `Ok(())` when no binding is recorded, or when the binding matches.
/// Returns [`BindingError::Mismatch`] otherwise.
pub fn verify_user_binding(identity: &NodeIdentity, current_sid: &str) -> Result<(), BindingError> {
    match identity.bound_user_sid.as_deref() {
        None => Ok(()),
        Some(expected) if expected == current_sid => Ok(()),
        Some(expected) => Err(BindingError::Mismatch {
            expected: expected.to_string(),
            actual: current_sid.to_string(),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ident_with(bound: Option<&str>) -> NodeIdentity {
        let mut ident = NodeIdentity::generate().unwrap();
        ident.bound_user_sid = bound.map(|s| s.to_string());
        ident
    }

    #[test]
    fn unbound_identity_accepts_any_sid() {
        let ident = ident_with(None);
        verify_user_binding(&ident, "anything").unwrap();
    }

    #[test]
    fn bound_identity_accepts_matching_sid() {
        let ident = ident_with(Some("uid:1000"));
        verify_user_binding(&ident, "uid:1000").unwrap();
    }

    #[test]
    fn bound_identity_rejects_other_sid() {
        let ident = ident_with(Some("uid:1000"));
        let err = verify_user_binding(&ident, "uid:1001").unwrap_err();
        assert!(matches!(err, BindingError::Mismatch { .. }));
    }
}
