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
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    /// Must match the service name Task B2's `ztlp.exe agent install`
    /// registers with the SCM (`ServiceInfo.name`).
    pub const SERVICE_NAME: &str = "ZtlpAgent";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    /// Service log file. A LocalSystem SCM service has no console, so
    /// without this every `tracing::error!` in this binary AND in the
    /// hosted daemon was silently dropped (no subscriber was ever
    /// installed) — Bug D (HANDOFF-2026-09-21-session5) was undiagnosable
    /// from the Event Log alone.
    pub fn log_path() -> std::path::PathBuf {
        std::path::PathBuf::from(ztlp_proto::agent::windows_daemon::WINDOWS_SYSTEM_CONFIG_DIR)
            .join(".ztlp")
            .join("ztlp-winsvc.log")
    }

    fn open_log() -> Option<std::fs::File> {
        let path = log_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok()
    }

    fn append_log_line(line: &str) {
        use std::io::Write;
        if let Some(mut f) = open_log() {
            let _ = writeln!(f, "{line}");
        }
    }

    fn init_diagnostics() {
        // 1. File-backed tracing subscriber (info by default, RUST_LOG
        //    honored) so the daemon's own log lines land somewhere.
        if let Some(file) = open_log() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        tracing_subscriber::EnvFilter::new("info,ztlp_proto=info")
                    }),
                )
                .with_ansi(false)
                .with_target(false)
                .with_writer(std::sync::Mutex::new(file))
                .try_init();
        }

        // 2. Panic hook that records the panic location + message to the
        //    same file. Any panic escaping `service_main` unwinds into the
        //    `extern "system"` FFI entry `define_windows_service!` generates,
        //    which Rust turns into `abort()` -> `__fastfail`, which WER logs
        //    as 0xc0000409 STATUS_STACK_BUFFER_OVERRUN with no message.
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let loc = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "<unknown location>".into());
            let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".into()
            };
            append_log_line(&format!(
                "PANIC ztlp-winsvc thread={:?} at {loc}: {msg}\n{}",
                std::thread::current().name(),
                std::backtrace::Backtrace::force_capture()
            ));
            default_hook(info);
        }));
    }

    fn service_main(_args: Vec<OsString>) {
        init_diagnostics();
        // Bug D: mirror ztlp-cli's main() — pick the rustls provider before
        // any TLS code runs (also done inside run_agent_lifecycle).
        ztlp_proto::agent::ensure_rustls_crypto_provider();
        tracing::info!(
            "ztlp-winsvc: service_main entered (pid {}), log at {}",
            std::process::id(),
            log_path().display()
        );
        // Never let a panic cross the FFI boundary into the SCM dispatcher
        // (that is the 0xc0000409 crash). Catch it, log it, report Stopped
        // with a non-zero exit code so `sc query` shows a real error
        // instead of 1067 "terminated unexpectedly".
        match std::panic::catch_unwind(run_service) {
            Ok(Ok(())) => tracing::info!("ztlp-winsvc: service exited cleanly"),
            Ok(Err(e)) => {
                tracing::error!("ztlp-winsvc: fatal service error: {e}");
                append_log_line(&format!("FATAL ztlp-winsvc: {e}"));
            }
            Err(_) => {
                append_log_line("FATAL ztlp-winsvc: run_service panicked (see PANIC line above)");
                report_stopped_after_panic();
            }
        }
    }

    /// After a caught panic the `status_handle` owned by `run_service` is
    /// gone; re-register a throwaway handler just to tell the SCM we're
    /// Stopped with an error code (best-effort — if registration fails the
    /// SCM will still notice the process exit).
    fn report_stopped_after_panic() {
        if let Ok(handle) = service_control_handler::register(SERVICE_NAME, |_| {
            ServiceControlHandlerResult::NoError
        }) {
            let _ = handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(0xD),
                checkpoint: 0,
                wait_hint: std::time::Duration::default(),
                process_id: None,
            });
        }
    }

    fn run_service() -> Result<(), Box<dyn std::error::Error>> {
        // D1 (Phase D plan,
        // docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md):
        // LocalSystem's home_dir() resolves to
        // C:\Windows\System32\config\systemprofile, not the enrolled user's
        // C:\Users\<user>\.ztlp. Set ZTLP_HOME unconditionally, before
        // anything else runs, so every `ztlp_state_dir()` call in this
        // process (and in any `ztlp.exe` child it re-execs, e.g. `enroll`'s
        // self re-exec in control.rs) resolves under
        // C:\ProgramData\ZTLP\.ztlp instead. Mirrors the macOS LaunchDaemon
        // plist pinning HOME to /Library/Application Support/ZTLP — same
        // goal, set via env var here because Windows's dirs::home_dir()
        // doesn't reliably honor a bare HOME/USERPROFILE override.
        std::env::set_var(
            ztlp_proto::agent::windows_daemon::ZTLP_HOME_ENV_VAR,
            ztlp_proto::agent::windows_daemon::WINDOWS_SYSTEM_CONFIG_DIR,
        );

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
