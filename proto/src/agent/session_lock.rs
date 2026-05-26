//! D3.T3: Windows session-change handler — tear down all tunnels and clear
//! the DNS cache when the OS signals a lock/logoff/disconnect event.
//!
//! The Windows side registers `WTSRegisterSessionNotification` so the agent
//! receives a notification when the active interactive session changes state.
//! On any of these events we eagerly tear everything down:
//!
//! - `WTS_SESSION_LOCK` (winuser SESSION_LOCK)
//! - `WTS_SESSION_LOGOFF` (SESSION_LOGOFF)
//! - `WTS_CONSOLE_DISCONNECT`
//! - `WTS_REMOTE_DISCONNECT`
//!
//! Linux / macOS have no equivalent surface for this product, so the public
//! entry point is a no-op on those platforms (returns `Ok(())`).
//!
//! Architecturally this module is *cooperative*: it does not own the tunnel
//! pool or the DNS state. It accepts a `tokio::sync::broadcast::Sender<LockdownReason>`
//! (the lockdown channel) supplied by `daemon.rs`. The daemon's GC task
//! subscribes to the channel and drives the actual teardown using the same
//! locks the periodic-idle path uses. This keeps lock ordering identical to
//! the steady-state path so we can't deadlock here.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use tokio::sync::broadcast;

/// Reasons a lockdown event was emitted. Used for structured logging in
/// `daemon.rs::run_daemon` so operators can correlate a teardown with the
/// triggering session-change reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownReason {
    SessionLock,
    SessionLogoff,
    ConsoleDisconnect,
    RemoteDisconnect,
}

impl LockdownReason {
    /// Human-readable name suitable for the `reason` field in tracing logs.
    pub fn as_str(self) -> &'static str {
        match self {
            LockdownReason::SessionLock => "session_lock",
            LockdownReason::SessionLogoff => "session_logoff",
            LockdownReason::ConsoleDisconnect => "console_disconnect",
            LockdownReason::RemoteDisconnect => "remote_disconnect",
        }
    }
}

/// Spawn the session-change listener.
///
/// On Windows this would install a `WTSRegisterSessionNotification` hook and
/// translate `WM_WTSSESSION_CHANGE` messages into broadcasts on
/// `lockdown_tx`. The actual WTS plumbing requires a message-pump thread and
/// `unsafe` Win32 calls, which we cannot do from this `#![deny(unsafe_code)]`
/// crate. The plan acknowledges this — the production hook lives in the
/// ztlp-service crate (which already accepts `unsafe_code`) and forwards
/// events to this daemon through the existing control-socket plane.
///
/// In this slice we only land the *receiver* side (the broadcast channel and
/// the `LockdownReason` enum) so the daemon can subscribe and react. The
/// Windows producer is a follow-up that lives in `service/src/session.rs`
/// once D4/D5 land the inter-process plumbing.
///
/// On non-Windows platforms this function returns immediately with `Ok(())`
/// and no listener is installed.
pub fn spawn_listener(_lockdown_tx: broadcast::Sender<LockdownReason>) -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    {
        // No-op on Linux/macOS: there is no equivalent surface. The agent on
        // these platforms relies on the user's session-manager (systemd
        // logind, launchd) to deliver SIGTERM, which `daemon.rs` already
        // handles via the ctrl_c branch.
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        // Future work: install the WTS hook here. For now we return Ok so
        // the daemon plumbing is exercised end-to-end on Windows CI builds
        // without requiring the (unsafe) Win32 message-pump.
        tracing::info!(
            target: "session_lock",
            "Windows session-lock listener stub installed; \
             producer side is owned by ztlp-service.exe (see service/src/session.rs)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_strings_are_stable() {
        // These strings show up in structured logs and dashboards — pin them.
        assert_eq!(LockdownReason::SessionLock.as_str(), "session_lock");
        assert_eq!(LockdownReason::SessionLogoff.as_str(), "session_logoff");
        assert_eq!(
            LockdownReason::ConsoleDisconnect.as_str(),
            "console_disconnect"
        );
        assert_eq!(
            LockdownReason::RemoteDisconnect.as_str(),
            "remote_disconnect"
        );
    }

    #[tokio::test]
    async fn spawn_listener_is_ok_on_any_platform() {
        // The Windows path installs a stub today; the Unix path is a no-op.
        // Either way, spawn_listener must return Ok cleanly.
        let (tx, _rx) = broadcast::channel::<LockdownReason>(8);
        assert!(spawn_listener(tx).is_ok());
    }
}
