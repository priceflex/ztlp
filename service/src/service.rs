//! Windows SCM dispatcher entry point.
//!
//! On Windows, `run_service()` registers with the Service Control Manager via
//! `windows_service::service_dispatcher::start`, sets up a STOP-signal channel
//! via `service_control_handler::register`, reports the standard SCM state
//! transitions (START_PENDING → RUNNING → STOP_PENDING → STOPPED), and drives
//! a placeholder heartbeat loop until SCM signals stop.
//!
//! The placeholder `run_loop` is intentionally minimal — D2.T3 replaces it
//! with the real child-process supervisor. Keep the dispatcher / control
//! handler wiring stable so D2.T3 only swaps the worker body.
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
    use crate::SERVICE_NAME;
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::thread;
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

        // Placeholder worker. D2.T3 replaces this with the supervisor.
        run_loop(stop_rx);

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

    /// Placeholder worker loop. Logs a heartbeat every 5 seconds via a
    /// helper thread so the event log shows the service is alive, and
    /// blocks the calling thread on `stop_rx.recv()` until the control
    /// handler signals SERVICE_CONTROL_STOP.
    ///
    /// D2.T3 replaces the body of this function with the child-process
    /// supervisor (spawn ztlp-agent, watch for exit, restart on policy).
    fn run_loop(stop_rx: mpsc::Receiver<()>) {
        // Heartbeat thread. Shares the stop signal via a second channel so
        // we can shut it down cleanly when the main loop exits.
        let (hb_stop_tx, hb_stop_rx) = mpsc::channel::<()>();
        let heartbeat = thread::spawn(move || {
            let mut tick: u64 = 0;
            loop {
                match hb_stop_rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        tick += 1;
                        tracing::info!(
                            service = SERVICE_NAME,
                            tick,
                            "ztlp-service heartbeat (placeholder run_loop; D2.T3 replaces this)"
                        );
                    }
                }
            }
        });

        // Block until SCM signals stop. recv() returns Err only if the
        // sender was dropped, which on a healthy run shouldn't happen —
        // either way we exit the loop and proceed to STOP_PENDING.
        let _ = stop_rx.recv();

        // Tear down the heartbeat thread.
        let _ = hb_stop_tx.send(());
        let _ = heartbeat.join();
    }
}
