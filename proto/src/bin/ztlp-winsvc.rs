//! ZTLP Windows Service host (Task B1, Windows/Linux desktop parity plan).
//!
//! A real Windows Service (SCM), not a `.spawn()`'d child of the Tauri
//! desktop app — `desktop/src-tauri/src/tunnel.rs::start_tunnel` today just
//! spawns `ztlp.exe agent start` as a child process, which dies the instant
//! the GUI closes and never survives logout/reboot. This binary is the
//! Windows analog of Linux's systemd unit / macOS's root LaunchDaemon: SCM
//! starts it (AutoStart), it hosts the SAME standby-then-full-daemon
//! sequencing every other platform uses
//! (`ztlp_proto::agent::run_agent_lifecycle`, extracted in Task B1 from the
//! CLI's `cmd_agent_start` for exactly this reuse), and it keeps running
//! independent of any desktop GUI session.
//!
//! Not unit-testable in the classic sense — there is no real Windows SCM to
//! register against outside a live Windows box. TDD here means "build it,
//! install it via `ztlp.exe agent install` (Task B2) on a real Windows
//! machine, verify it starts" rather than `cargo test`. This file is
//! `#[cfg(windows)]`-gated at the module level so `cargo build --bin
//! ztlp-winsvc` on Linux/macOS just prints an error and exits — see the
//! `#[cfg(not(windows))] fn main()` fallback below, which IS what compiles
//! (and is exercised) on this dev box.
//!
//! Cross-compilation reality (see the `ztlp-desktop-browser-clients` skill):
//! the Windows MSVC target cannot be built from a Linux box (`aws-lc-sys`'s
//! C dependency needs `cl.exe`), so the `#[cfg(windows)]` module body below
//! is verified via the GitHub Actions `windows-latest` runner, not locally.

#[cfg(windows)]
mod svc {
    use std::ffi::OsString;
    use windows_service::{
        define_windows_service, service_dispatcher,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    /// Must match the service name Task B2's `ztlp.exe agent install`
    /// registers with the SCM (`ServiceInfo.name`).
    pub const SERVICE_NAME: &str = "ZtlpAgent";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            tracing::error!("ztlp-winsvc: fatal service error: {e}");
        }
    }

    fn run_service() -> Result<(), Box<dyn std::error::Error>> {
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

        // Standard SCM status-reporting dance: register a control handler
        // that accepts STOP/SHUTDOWN before reporting Running, so the SCM
        // doesn't consider the service hung during startup.
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        // Run the SAME standby->full-daemon sequencing the CLI's
        // `ztlp agent start` uses (Task B1's extraction), in a dedicated
        // tokio runtime, racing it against the SCM's stop/shutdown signal
        // arriving on a background OS thread (windows-service's control
        // handler callback runs off the async runtime).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            tokio::select! {
                res = ztlp_proto::agent::run_agent_lifecycle(None, /* foreground */ true) => {
                    if let Err(e) = res {
                        tracing::error!("ztlp-winsvc: agent lifecycle exited with error: {e}");
                    }
                }
                _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()) => {
                    tracing::info!("ztlp-winsvc: stop/shutdown control received");
                }
            }
        });

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    svc::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ztlp-winsvc is Windows-only");
    std::process::exit(1);
}
