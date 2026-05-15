use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use ztlp_proto::agent::control::{ControlCommand, ControlResponse};

pub fn ipc_request(cmd: &str, name: Option<String>) -> Result<Value, String> {
    let mut stream = TcpStream::connect("127.100.255.1:4433")
        .map_err(|e| format!("Failed to connect to daemon: {}", e))?;

    let req = ControlCommand {
        cmd: cmd.to_string(),
        name,
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
