use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use ztlp_proto::agent::control::{ControlCommand, ControlResponse};

/// Locate the daemon's control-API bearer token from the GUI's (interactive
/// user's) point of view.
///
/// `ztlp_proto::agent::config::load_agent_token()` already handles the
/// Windows service-vs-caller path split (D1/D5 review fix); this is a
/// thin wrapper kept so call sites here read as GUI-specific and to
/// leave room for a future GUI-only override without touching the
/// shared library function.
pub fn load_gui_agent_token() -> Option<String> {
    ztlp_proto::agent::config::load_agent_token()
}

/// Maximum time to wait for the agent control socket to accept a connection.
///
/// The desktop polls `get_status` / `get_traffic_stats` every 2 seconds and on
/// every page navigation. The agent (`ztlp-node`) listens on a fixed loopback
/// address (127.100.255.1:4433); when it isn't running, the OS rejects the
/// connection after a long retransmission window (Windows defaults to ~2s for
/// the first SYN retry — long enough to freeze the UI on every nav click).
///
/// A genuinely-down daemon is rejected by the OS *immediately* (RST), so a
/// generous timeout does NOT slow the "agent not running" path. But a
/// *healthy* daemon under real load (tunnel activity + the app's own 2s
/// polling) can take tens of ms to accept a connection — observed at ~35ms in
/// the interactive session, with bursts higher under load. The old 100ms
/// budget tripped intermittently on a live agent and made `setup_status`
/// fall back to `daemon_running: false` (a false "agent not running" in the
/// Setup wizard). 500ms matches `IPC_IO_TIMEOUT` and gives a healthy agent
/// 5x headroom while a down agent still fails instantly on RST.
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Bound on read/write so a hung/half-open daemon socket can't lock up the UI.
/// Real responses come back in single-digit ms over loopback, so 500 ms is
/// generous while still cheap to recover from.
const IPC_IO_TIMEOUT: Duration = Duration::from_millis(500);

/// Per-command read budget. The 500ms default is right for the cheap 2s
/// status polls, but two commands do real work inside the daemon:
///
/// * `setup_status` shells out on Windows (icacls / query user / NRPT and
///   cert-store probes) — measured 800-870ms against the ZtlpAgent service
///   on 10.170.3.207 (2026-09-28). With 500ms the GUI always timed out and
///   painted "Service: Not installed" over a healthy, enrolled service.
/// * `enroll` runs `ztlp setup` + ca-init + install-ca-cert as subprocesses
///   (several seconds, NS round trip).
pub fn io_timeout_for(cmd: &str) -> Duration {
    match cmd {
        "setup_status" => Duration::from_secs(5),
        "enroll" => Duration::from_secs(120),
        _ => IPC_IO_TIMEOUT,
    }
}

pub fn ipc_request_with_addr(addr: &str, cmd: &str, name: Option<String>) -> Result<Value, String> {
    let req = ControlCommand {
        cmd: cmd.to_string(),
        name,
        token: load_gui_agent_token(),
        ..Default::default()
    };
    ipc_send(addr, req)
}

/// Send an `enroll` command to the agent daemon at `addr` — the IPC-based
/// enrollment path (Task A3): forwards the token straight to the daemon's
/// control socket instead of a bare `ztlp setup` spawn under the desktop
/// app's own (interactive-user) HOME.
pub fn ipc_enroll_at(
    addr: &str,
    enrollment_uri: &str,
    name: Option<String>,
    relay_secret: Option<String>,
) -> Result<Value, String> {
    let req = ControlCommand {
        cmd: "enroll".to_string(),
        name,
        token: load_gui_agent_token(),
        enrollment_uri: Some(enrollment_uri.to_string()),
        relay_secret,
    };
    ipc_send(addr, req)
}

/// Shared low-level send/receive over the control socket for any
/// [`ControlCommand`].
fn ipc_send(addr: &str, req: ControlCommand) -> Result<Value, String> {
    let io_timeout = io_timeout_for(&req.cmd);
    // Resolve first so we can use `connect_timeout` (which requires a
    // SocketAddr, not a string). For a literal "127.x:port" this is
    // essentially free, but ToSocketAddrs handles the parse uniformly.
    let socket_addr: SocketAddr = addr
        .to_socket_addrs()
        .map_err(|e| format!("Invalid daemon address {}: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("No socket address resolved for {}", addr))?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, IPC_CONNECT_TIMEOUT)
        .map_err(|e| format!("Failed to connect to daemon at {}: {}", addr, e))?;

    // Apply read/write timeouts so a stuck daemon can't hang the UI thread.
    stream
        .set_read_timeout(Some(io_timeout))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(io_timeout))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    let mut req_bytes =
        serde_json::to_vec(&req).map_err(|e| format!("Failed to serialize request: {}", e))?;
    req_bytes.push(b'\n');

    stream
        .write_all(&req_bytes)
        .map_err(|e| format!("Failed to write request: {}", e))?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if resp_line.is_empty() {
        return Err("Connection closed by daemon before response".into());
    }

    let resp: ControlResponse =
        serde_json::from_str(&resp_line).map_err(|e| format!("Failed to parse response: {}", e))?;

    if resp.ok {
        Ok(resp.data.unwrap_or(Value::Null))
    } else {
        Err(resp
            .error
            .unwrap_or_else(|| "Unknown daemon error".to_string()))
    }
}

pub fn ipc_request(cmd: &str, name: Option<String>) -> Result<Value, String> {
    ipc_request_with_addr("127.100.255.1:4433", cmd, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_timeout_covers_slow_daemon_commands() {
        // Regression (2026-09-28): setup_status measured ~850ms live.
        assert!(io_timeout_for("setup_status") >= Duration::from_secs(2));
        assert!(io_timeout_for("enroll") >= Duration::from_secs(60));
        assert_eq!(io_timeout_for("status"), IPC_IO_TIMEOUT);
    }

    #[test]
    fn slow_setup_status_reply_is_not_a_timeout() {
        // A daemon that takes 900ms (> the 500ms poll budget) to answer
        // setup_status must still be read successfully.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let h = thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            thread::sleep(Duration::from_millis(900));
            let mut w = s;
            let resp = ControlResponse::ok(json!({"daemon_running": true}));
            writeln!(w, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
        });
        let v =
            ipc_request_with_addr(&addr, "setup_status", None).expect("slow reply must succeed");
        assert_eq!(v["daemon_running"], json!(true));
        h.join().unwrap();
    }
    use serde_json::json;
    use std::net::TcpListener;
    use std::thread;
    use ztlp_proto::agent::control::ControlResponse;

    #[test]
    fn test_ipc_request_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();

            assert!(line.ends_with('\n'));
            let _req: ControlCommand = serde_json::from_str(&line).unwrap();

            let resp = ControlResponse {
                ok: true,
                error: None,
                data: Some(json!({"status": "running"})),
            };
            let mut resp_bytes = serde_json::to_vec(&resp).unwrap();
            resp_bytes.push(b'\n');
            stream.write_all(&resp_bytes).unwrap();
        });

        let res = ipc_request_with_addr(&addr, "test_cmd", Some("test_name".to_string()));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), json!({"status": "running"}));
    }

    #[test]
    fn test_ipc_request_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();

            let resp = ControlResponse {
                ok: false,
                error: Some("Test error message".to_string()),
                data: None,
            };
            let mut resp_bytes = serde_json::to_vec(&resp).unwrap();
            resp_bytes.push(b'\n');
            stream.write_all(&resp_bytes).unwrap();
        });

        let res = ipc_request_with_addr(&addr, "fail_cmd", None);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Test error message");
    }

    #[test]
    fn test_ipc_request_connection_refused() {
        // Using an intentionally un-listened port to simulate a lack of daemon.
        let res = ipc_request_with_addr("127.0.0.1:44445", "cmd", None);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Failed to connect"));
    }

    /// Regression: connect to an unreachable host must fail within a bounded
    /// time (not the OS ~2s SYN retransmission window) so it never freezes the
    /// UI thread. See `IPC_CONNECT_TIMEOUT` in this module.
    ///
    /// We use a TEST-NET-1 address (192.0.2.0/24, RFC 5737) routed nowhere so
    /// the OS produces a connect *timeout* rather than an immediate RST — this
    /// is what makes the slowness visible to users with no agent running.
    ///
    /// The bound is `IPC_CONNECT_TIMEOUT + slack` (not a hardcoded literal) so
    /// it stays correct if the timeout is tuned. A down daemon on loopback
    /// fails on immediate RST (well under this); only a *non-routable* address
    /// exercises the full timeout path.
    #[test]
    fn test_ipc_request_unreachable_fails_fast() {
        use std::time::Instant;
        let start = Instant::now();
        let res = ipc_request_with_addr("192.0.2.1:4433", "status", None);
        let elapsed = start.elapsed();
        assert!(res.is_err(), "expected connect to fail on TEST-NET-1");
        let bound = IPC_CONNECT_TIMEOUT + Duration::from_millis(500);
        assert!(
            elapsed < bound,
            "ipc_request_with_addr took {:?} on unreachable host; \
             must fail within IPC_CONNECT_TIMEOUT + 500ms slack to keep UI responsive",
            elapsed
        );
    }
}
