use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use ztlp_proto::agent::config::load_agent_token;
use ztlp_proto::agent::control::{ControlCommand, ControlResponse};

pub fn ipc_request_with_addr(addr: &str, cmd: &str, name: Option<String>) -> Result<Value, String> {
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| format!("Failed to connect to daemon at {}: {}", addr, e))?;

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
    use std::net::TcpListener;
    use std::thread;
    use ztlp_proto::agent::control::ControlResponse;
    use serde_json::json;

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
}
