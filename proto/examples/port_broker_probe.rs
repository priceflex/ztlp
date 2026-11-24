//! Live proof for agent::port_broker on macOS (dev tool, not shipped).
//!
//!   sudo port_broker_probe serve /tmp/pb.sock          # root: one request
//!   port_broker_probe client /tmp/pb.sock 127.100.0.1 443   # as the user
//!
//! The client receives the root-bound listener, then answers ONE HTTP
//! request with "port-broker-ok" so `curl http://127.100.0.1:443/` proves a
//! non-root process is accepting on the real privileged port.
//!
//! Unix-only: `agent::port_broker` (and `std::os::unix`) are cfg-gated to
//! unix, so on Windows this example compiles to an empty `fn main` — it must
//! not be part of a Windows `--all-targets` build. (surfaced by PR #132
//! merge: the example imported the unix-only module without a cfg gate.)
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use ztlp_proto::agent::port_broker::{
    bind_listener, request_listener, serve_one, validate, BindRequest,
};

#[cfg(unix)]
fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("serve") => {
            let path = Path::new(&a[2]);
            let _ = std::fs::remove_file(path);
            let l = std::os::unix::net::UnixListener::bind(path).expect("bind broker socket");
            // let the non-root client connect (policy check is the boundary)
            let _ = std::process::Command::new("chmod")
                .args(["666", &a[2]])
                .status();
            eprintln!("broker uid={} listening on {}", unsafe_uid(), a[2]);
            let (conn, _) = l.accept().expect("accept");
            match serve_one(conn, validate, bind_listener) {
                Ok(m) => eprintln!("broker: {m}"),
                Err(e) => eprintln!("broker: {e}"),
            }
            let _ = std::fs::remove_file(path);
        }
        Some("client") => {
            let req = BindRequest {
                ip: a[3].parse::<Ipv4Addr>().expect("ip"),
                port: a[4].parse().expect("port"),
            };
            eprintln!(
                "client uid={} asking for {}:{}",
                unsafe_uid(),
                req.ip,
                req.port
            );
            let l = match request_listener(Path::new(&a[2]), &req) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("client: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("client: got listener {}", l.local_addr().unwrap());
            let (mut s, peer) = l.accept().expect("accept");
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let body = "port-broker-ok\n";
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            eprintln!("client: served {peer}");
        }
        _ => eprintln!("usage: serve <sock> | client <sock> <ip> <port>"),
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("port_broker_probe is a macOS/unix dev tool; not applicable here");
}

#[cfg(unix)]
fn unsafe_uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}
