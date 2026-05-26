//! Windows SCM dispatcher entry point.
//!
//! On Windows, `run_service()` registers with the Service Control Manager via
//! `windows_service::service_dispatcher::start`, sets up a STOP-signal channel
//! via `service_control_handler::register`, reports the standard SCM state
//! transitions (START_PENDING → RUNNING → STOP_PENDING → STOPPED), and drives
//! the child-process supervisor (D2.T3) until SCM signals stop.
//!
//! On every other target `run_service()` returns Err("requires Windows SCM").

use anyhow::Result;

/// SCM dispatcher entry point.
///
/// On Windows: blocks the calling thread inside
/// `windows_service::service_dispatcher::start` until the service exits.
///
/// On non-Windows targets: returns Err with a message containing
/// "requires Windows SCM" so callers can degrade gracefully and so the
/// `ztlp-service run` CLI fails fast on Linux/macOS instead of pretending
/// to be a service.
pub fn run_service() -> Result<()> {
    run_service_impl()
}

#[cfg(not(target_os = "windows"))]
fn run_service_impl() -> Result<()> {
    Err(anyhow::anyhow!(
        "ztlp-service run requires Windows SCM; current target: {}",
        std::env::consts::OS
    ))
}

#[cfg(target_os = "windows")]
fn run_service_impl() -> Result<()> {
    windows_impl::run().map_err(|e| anyhow::anyhow!("SCM dispatcher failed: {e}"))
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use crate::supervisor::{BackoffPolicy, ChildSpec, Supervisor};
    use crate::SERVICE_NAME;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    /// Block on `service_dispatcher::start` until the SCM tells us to exit.
    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    // The `define_windows_service!` macro expands to an `extern "system" fn`
    // with the exact signature the SCM expects, then calls into our safe
    // `service_main` after parsing the raw argv. Keep this name stable —
    // `service_dispatcher::start` passes the macro-generated symbol.
    define_windows_service!(ffi_service_main, service_main);

    /// Safe service entry. Called by the macro-generated `ffi_service_main`
    /// on a background thread the SCM spins up for us. There is no stdout /
    /// stderr available here — all diagnostics go through `tracing`.
    ///
    /// FFI safety: `ffi_service_main` is `extern "system" fn`, so a panic
    /// crossing that boundary is UB. We wrap the entire body in
    /// `catch_unwind` and log instead of propagating. `AssertUnwindSafe` is
    /// fine because on panic we drop all captured state and return; the SCM
    /// dispatcher's watchdog will mark the service Stopped once we exit.
    fn service_main(arguments: Vec<OsString>) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            service_main_inner(arguments)
        }));
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!(error = %e, "ztlp-service: service_main_inner returned error");
            }
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };
                tracing::error!(panic = %msg, "ztlp-service: service_main panicked across FFI boundary");
                // We don't have status_handle out here; the SCM dispatcher
                // watchdog will transition the service to Stopped once this
                // function returns. Logging the payload is the minimum
                // FFI safety contract.
            }
        }
    }

    fn service_main_inner(_arguments: Vec<OsString>) -> windows_service::Result<()> {
        // Stop channel — the SCM control handler closure owns the sender
        // and fires it on STOP; `run_loop` blocks on the receiver.
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                // INTERROGATE: SCM asking for current status. Returning
                // NoError tells SCM "I'm alive, my last reported state stands".
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

                // STOP: signal the worker loop and acknowledge. The actual
                // SERVICE_STOPPED state transition happens after the worker
                // unwinds, in service_main_inner below.
                ServiceControl::Stop => {
                    // send() only fails if the receiver was already dropped,
                    // which would mean the worker already exited — nothing
                    // useful to do beyond logging.
                    if let Err(e) = stop_tx.send(()) {
                        tracing::warn!(
                            error = %e,
                            "ztlp-service: stop signal could not be delivered (worker already gone)"
                        );
                    }
                    ServiceControlHandlerResult::NoError
                }

                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        // Report START_PENDING — we have a control handler but aren't
        // accepting controls yet. wait_hint is generous (10s) because
        // D2.T3's supervisor will spawn a child process here. The SCM
        // tolerates an instant jump to RUNNING, but sc.exe start clients
        // and event log consumers expect to see START_PENDING first.
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })?;

        // Report RUNNING — we're ready to accept STOP.
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        tracing::info!(service = SERVICE_NAME, "reported RUNNING to SCM");

        // Build the ChildSpec for `ztlp.exe agent start --foreground` and
        // run the supervisor. Plan-deviation: the original plan said
        // `--token-path "C:\ProgramData\ZTLP\agent.token"` but that CLI
        // flag does not exist on `ztlp agent start`. The daemon reads
        // ZTLP_AGENT_TOKEN_PATH from the environment (wired in D1), so
        // we pass the path via env instead. This is more idiomatic for
        // service-spawned children anyway.
        let supervisor_result = match build_agent_child_spec() {
            Ok(spec) => Supervisor::new(spec, BackoffPolicy::default(), stop_rx).run(),
            Err(e) => {
                tracing::error!(error = %e, "ztlp-service: failed to build agent child spec");
                // Fall through to STOP_PENDING / STOPPED so SCM sees a
                // clean exit; the error is already logged.
                Ok(())
            }
        };
        if let Err(e) = supervisor_result {
            tracing::error!(error = %e, "ztlp-service: supervisor returned error");
        }

        // STOP_PENDING — best-effort signal to the SCM that we're winding
        // down. Not a hard failure if it doesn't land; we'll still report
        // STOPPED below.
        if let Err(e) = status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        }) {
            tracing::warn!(error = %e, "ztlp-service: failed to report STOP_PENDING");
        }

        // STOPPED — terminal state. SCM uses this to mark the service exited
        // cleanly and (if configured) to trigger restart policies.
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        tracing::info!(service = SERVICE_NAME, "reported STOPPED to SCM");
        Ok(())
    }

    /// Locate `ztlp.exe` next to the current executable and assemble the
    /// `ChildSpec` for `ztlp.exe agent start --foreground`. Ensures the
    /// log directory exists. The installer is responsible for placing
    /// `ztlp.exe` next to `ztlp-service.exe`; if it's missing we surface
    /// a clear error.
    fn build_agent_child_spec() -> anyhow::Result<ChildSpec> {
        use anyhow::Context;

        let service_exe = std::env::current_exe().context("current_exe() failed")?;
        let exe_dir = service_exe
            .parent()
            .context("current_exe has no parent directory")?;
        let agent_binary = exe_dir.join("ztlp.exe");
        if !agent_binary.exists() {
            anyhow::bail!(
                "ztlp.exe not found next to ztlp-service.exe (expected at {}); \
                 the installer must place them in the same directory",
                agent_binary.display()
            );
        }

        let log_dir = PathBuf::from(r"C:\ProgramData\ZTLP\logs");
        std::fs::create_dir_all(&log_dir)
            .with_context(|| format!("creating log dir {}", log_dir.display()))?;
        let log_path = log_dir.join("agent.log");

        let token_path = OsString::from(r"C:\ProgramData\ZTLP\agent.token");

        Ok(ChildSpec {
            binary: agent_binary,
            args: vec![
                OsString::from("agent"),
                OsString::from("start"),
                OsString::from("--foreground"),
            ],
            env: vec![(OsString::from("ZTLP_AGENT_TOKEN_PATH"), token_path)],
            log_path,
        })
    }
}
