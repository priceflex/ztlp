use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use ztlp_proto::agent::config::load_agent_token;
use ztlp_proto::agent::control::{ControlCommand, ControlResponse};

/// Maximum time to wait for the agent control socket to accept a connection.
///
/// The desktop polls `get_status` / `get_traffic_stats` every 2 seconds and on
/// every page navigation. The agent (`ztlp-node`) listens on a fixed loopback
/// address (127.100.255.1:4433); when it isn't running, the OS rejects the
/// connection after a long retransmission window (Windows defaults to ~2s for
/// the first SYN retry — long enough to freeze the UI on every nav click).
///
/// Cap connect at 100 ms so unreachable-daemon failures surface immediately
/// and the UI can render a clean "Agent not running" state instead of
/// blocking. Loopback connects on a live listener complete in <1 ms so this
/// budget never trips a healthy agent.
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// Bound on read/write so a hung/half-open daemon socket can't lock up the UI.
/// Real responses come back in single-digit ms over loopback, so 500 ms is
/// generous while still cheap to recover from.
const IPC_IO_TIMEOUT: Duration = Duration::from_millis(500);

pub fn ipc_request_with_addr(addr: &str, cmd: &str, name: Option<String>) -> Result<Value, String> {
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
        .set_read_timeout(Some(IPC_IO_TIMEOUT))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(IPC_IO_TIMEOUT))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    let req = ControlCommand {
        cmd: cmd.to_string(),
        name,
        token: load_agent_token(),
    };

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

    /// Regression: connect to an un-listened port must fail fast (<= 200 ms)
    /// instead of blocking the UI thread for Windows' default ~2s SYN
    /// retransmission window. See IPC_CONNECT_TIMEOUT in this module.
    ///
    /// We use a TEST_NET-1 address (192.0.2.0/24, RFC 5737) routed nowhere so
    /// the OS produces a connect timeout rather than an immediate RST — this
    /// is what makes the slowness visible to users with no agent running.
    #[test]
    fn test_ipc_request_unreachable_fails_fast() {
        use std::time::Instant;
        let start = Instant::now();
        let res = ipc_request_with_addr("192.0.2.1:4433", "status", None);
        let elapsed = start.elapsed();
        assert!(res.is_err(), "expected connect to fail on TEST-NET-1");
        assert!(
            elapsed < Duration::from_millis(500),
            "ipc_request_with_addr took {:?} on unreachable host; \
             must fail within IPC_CONNECT_TIMEOUT + slack to keep UI responsive",
            elapsed
        );
    }
}
