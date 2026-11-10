//! macOS port broker.
//!
//! The per-user agent is not root, and macOS only lets root bind ports
//! below 1024 on a specific address — so `127.100.0.3:443` failed with
//! "Permission denied" and every `https://<name>.ztlp` site was refused.
//!
//! The fix keeps the REAL port (no pf redirect): the root machine service
//! (`org.ztlp.machine`) opens the privileged listening socket and hands the
//! file descriptor to the agent over a Unix socket (`SCM_RIGHTS`). The agent
//! then accepts on it directly; the broker never sees any traffic.
//!
//! Wire protocol (one request per connection):
//! - agent → broker: `BIND <ipv4> <port>\n`
//! - broker → agent: `OK\n` + the listening socket fd, or `ERR <reason>\n`
//!
//! The broker only binds ZTLP VIPs (127.100.0.0/16, excluding the reserved
//! 127.100.255.0/24 control/health block). The agent binds directly first
//! and only asks the broker when that fails with "Permission denied"
//! (privileged port) or "Can't assign requested address" (new VIP, no lo0
//! alias yet — the broker adds it as root).
#![cfg(unix)]

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Where the root broker listens (root-owned dir; socket mode 0666 — the
/// request validation, not the socket mode, is the security boundary).
pub const BROKER_SOCKET_PATH: &str = "/var/run/ztlp-portbroker.sock";

/// One bind request from the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindRequest {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl BindRequest {
    pub fn to_line(&self) -> String {
        format!("BIND {} {}\n", self.ip, self.port)
    }
}

/// Does this port need the broker? (Only privileged ports do.)
pub fn needs_broker(port: u16) -> bool {
    port != 0 && port < 1024
}

/// Parse `BIND <ipv4> <port>`.
pub fn parse_request(line: &str) -> Result<BindRequest, String> {
    let mut it = line.split_whitespace();
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some("BIND"), Some(ip), Some(port), None) => {
            let ip: Ipv4Addr = ip.parse().map_err(|_| format!("bad address: {ip}"))?;
            let port: u16 = port.parse().map_err(|_| format!("bad port: {port}"))?;
            Ok(BindRequest { ip, port })
        }
        _ => Err(format!("bad request: {:?}", line.trim())),
    }
}

/// The broker's whole policy: ZTLP VIP range only, privileged ports only.
pub fn validate(req: &BindRequest) -> Result<(), String> {
    let o = req.ip.octets();
    if o[0] != 127 || o[1] != 100 {
        return Err(format!("{} is not a ZTLP VIP (127.100.0.0/16)", req.ip));
    }
    if o[2] == 255 {
        return Err(format!(
            "{} is in the reserved 127.100.255.0/24 block",
            req.ip
        ));
    }
    if req.port == 0 {
        return Err("port 0 is not a service port".into());
    }
    Ok(())
}

/// Agent side: should a failed VIP bind be retried through the broker?
/// Yes for "Permission denied" (privileged port, non-root) and "Can't assign
/// requested address" (new VIP with no lo0 alias yet — the broker, as root,
/// adds it), and only for ZTLP VIPs.
pub fn should_ask_broker(kind: io::ErrorKind, ip: Ipv4Addr) -> bool {
    let vip = BindRequest { ip, port: 1 };
    matches!(
        kind,
        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
    ) && validate(&vip).is_ok()
}

/// Root side: serve bind requests forever on `path` (one thread per
/// request). `prepare` runs before each bind (production: add the lo0
/// alias for the VIP). Returns only if the socket can't be created.
pub fn run_broker(
    path: &Path,
    prepare: impl Fn(&BindRequest) + Send + Sync + 'static,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    // Any local user's agent may ask; validate() is the boundary.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let prepare = std::sync::Arc::new(prepare);
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let prepare = prepare.clone();
        std::thread::spawn(move || {
            let r = serve_one(conn, validate, |req| {
                prepare(req);
                bind_listener(req)
            });
            match r {
                Ok(m) => eprintln!("port broker: {m}"),
                Err(e) => eprintln!("port broker: {e}"),
            }
        });
    }
    Ok(())
}

// ── SCM_RIGHTS fd passing ───────────────────────────────────────────────

/// Send `msg` plus one file descriptor over a connected Unix stream.
#[allow(unsafe_code)] // libc sendmsg/recvmsg/getpeereid; crate is otherwise deny(unsafe_code)
pub fn send_fd(sock: &UnixStream, fd: RawFd, msg: &[u8]) -> io::Result<()> {
    assert!(!msg.is_empty(), "SCM_RIGHTS needs at least one data byte");
    unsafe {
        let mut iov = libc::iovec {
            iov_base: msg.as_ptr() as *mut libc::c_void,
            iov_len: msg.len(),
        };
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut RawFd, fd);
        if libc::sendmsg(sock.as_raw_fd(), &hdr, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive data plus (optionally) one file descriptor.
#[allow(unsafe_code)] // libc sendmsg/recvmsg/getpeereid; crate is otherwise deny(unsafe_code)
pub fn recv_fd(sock: &UnixStream, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_controllen = space as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut hdr, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut fd = None;
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        {
            let raw = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd);
            fd = Some(OwnedFd::from_raw_fd(raw));
        }
        Ok((n as usize, fd))
    }
}

// ── peer identity ───────────────────────────────────────────────────────

/// UID of the process on the other end of a Unix stream.
#[allow(unsafe_code)] // libc sendmsg/recvmsg/getpeereid; crate is otherwise deny(unsafe_code)
pub fn peer_uid(sock: &UnixStream) -> io::Result<u32> {
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    unsafe {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        if libc::getpeereid(sock.as_raw_fd(), &mut uid, &mut gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
}

// ── broker (server) side ────────────────────────────────────────────────

/// A real listening socket on `ip:port` (root needed for <1024 on macOS).
/// SO_REUSEADDR so an agent restart can re-acquire the port at once.
pub fn bind_listener(req: &BindRequest) -> io::Result<OwnedFd> {
    use socket2::{Domain, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    s.set_reuse_address(true)?;
    s.bind(&std::net::SocketAddr::from((req.ip, req.port)).into())?;
    s.listen(1024)?;
    Ok(OwnedFd::from(s))
}

/// Serve ONE request on an accepted connection. `binder` does the actual
/// bind (injected so tests can use an unprivileged port without root);
/// `check` is the policy (production: [`validate`]). Returns what was done,
/// for the caller's log.
/// How long the root broker waits on one client's request/reply.
pub const BROKER_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub fn serve_one(
    mut conn: UnixStream,
    check: impl Fn(&BindRequest) -> Result<(), String>,
    binder: impl Fn(&BindRequest) -> io::Result<OwnedFd>,
) -> Result<String, String> {
    let uid = peer_uid(&conn).map_err(|e| format!("peer uid: {e}"))?;
    // The socket is world-connectable: never let one client hold this
    // (root) thread longer than BROKER_IO_TIMEOUT.
    conn.set_read_timeout(Some(BROKER_IO_TIMEOUT))
        .and_then(|_| conn.set_write_timeout(Some(BROKER_IO_TIMEOUT)))
        .map_err(|e| format!("socket timeout: {e}"))?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < 128 {
        match conn.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => line.push(byte[0]),
            _ => break,
        }
    }
    let line = String::from_utf8_lossy(&line).into_owned();
    let result = parse_request(&line).and_then(|req| {
        check(&req)?;
        binder(&req)
            .map(|fd| (req, fd))
            .map_err(|e| format!("bind {}:{} failed: {e}", req.ip, req.port))
    });
    match result {
        Ok((req, fd)) => {
            send_fd(&conn, fd.as_raw_fd(), b"OK\n").map_err(|e| format!("send fd: {e}"))?;
            Ok(format!(
                "uid {uid}: handed {}:{} to the agent",
                req.ip, req.port
            ))
        }
        Err(e) => {
            let _ = conn.write_all(format!("ERR {e}\n").as_bytes());
            Err(format!("uid {uid}: refused: {e}"))
        }
    }
}

// ── agent (client) side ─────────────────────────────────────────────────

/// Why the broker didn't hand over a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// No broker socket (yet) — e.g. the agent started before the machine
    /// service finished booting. Worth retrying.
    Unavailable(String),
    /// The broker answered and said no (policy / bind failure). Final.
    Refused(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::Unavailable(m) | BrokerError::Refused(m) => f.write_str(m),
        }
    }
}

impl BrokerError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, BrokerError::Unavailable(_))
    }
}

/// Ask the broker at `socket_path` for a listening socket on `req`.
pub fn request_listener(
    socket_path: &Path,
    req: &BindRequest,
) -> Result<std::net::TcpListener, BrokerError> {
    let mut conn = UnixStream::connect(socket_path).map_err(|e| {
        BrokerError::Unavailable(format!(
            "port broker unavailable at {}: {e}",
            socket_path.display()
        ))
    })?;
    conn.write_all(req.to_line().as_bytes())
        .map_err(|e| BrokerError::Unavailable(format!("port broker write: {e}")))?;
    let mut buf = [0u8; 256];
    let (n, fd) = recv_fd(&conn, &mut buf)
        .map_err(|e| BrokerError::Unavailable(format!("port broker read: {e}")))?;
    let reply = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    match (reply.as_str(), fd) {
        ("OK", Some(fd)) => Ok(std::net::TcpListener::from(fd)),
        _ => Err(BrokerError::Refused(format!(
            "port broker refused {}:{}: {}",
            req.ip,
            req.port,
            reply.trim_start_matches("ERR ").trim()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(ip: [u8; 4], port: u16) -> BindRequest {
        BindRequest {
            ip: Ipv4Addr::from(ip),
            port,
        }
    }

    #[test]
    fn request_line_round_trips() {
        let r = req([127, 100, 0, 3], 443);
        assert_eq!(r.to_line(), "BIND 127.100.0.3 443\n");
        assert_eq!(parse_request(&r.to_line()), Ok(r));
    }

    #[test]
    fn malformed_requests_are_rejected() {
        for bad in [
            "",
            "BIND",
            "BIND 127.100.0.3",
            "BIND x 443",
            "BIND 127.100.0.3 99999",
            "BIND 127.100.0.3 443 extra",
            "LISTEN 127.100.0.3 443",
        ] {
            assert!(parse_request(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn policy_allows_only_ztlp_vips_on_privileged_ports() {
        assert!(validate(&req([127, 100, 0, 3], 443)).is_ok());
        assert!(validate(&req([127, 100, 7, 200], 80)).is_ok());
        assert!(validate(&req([127, 100, 0, 3], 22)).is_ok());
        // not a VIP: real interfaces, localhost, other loopback
        assert!(validate(&req([0, 0, 0, 0], 443)).is_err());
        assert!(validate(&req([10, 0, 0, 5], 443)).is_err());
        assert!(validate(&req([127, 0, 0, 1], 443)).is_err());
        // reserved control/health block
        assert!(validate(&req([127, 100, 255, 1], 443)).is_err());
        // unprivileged ports are allowed (new VIP needs the root alias)
        assert!(validate(&req([127, 100, 0, 3], 8443)).is_ok());
        assert!(validate(&req([127, 100, 0, 3], 0)).is_err());
    }

    #[test]
    fn agent_asks_broker_only_for_vip_permission_or_missing_alias() {
        use io::ErrorKind::*;
        let vip = Ipv4Addr::new(127, 100, 0, 3);
        assert!(should_ask_broker(PermissionDenied, vip));
        assert!(should_ask_broker(AddrNotAvailable, vip));
        // port already taken: the broker can't help
        assert!(!should_ask_broker(AddrInUse, vip));
        // never for non-VIPs or the reserved control/health block
        assert!(!should_ask_broker(
            PermissionDenied,
            Ipv4Addr::new(127, 0, 0, 1)
        ));
        assert!(!should_ask_broker(
            PermissionDenied,
            Ipv4Addr::new(127, 100, 255, 2)
        ));
    }

    #[test]
    fn run_broker_serves_requests_and_refuses_non_vips() {
        let dir = std::env::temp_dir().join(format!("ztlp-pb-run-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("b.sock");
        let p2 = path.clone();
        let prepared = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pc = prepared.clone();
        std::thread::spawn(move || {
            let _ = run_broker(&p2, move |_| {
                pc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        });
        for _ in 0..50 {
            if path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o666
        );
        let err = request_listener(&path, &req([10, 0, 0, 5], 443)).unwrap_err();
        assert!(err.to_string().contains("not a ZTLP VIP"), "{err}");
        // a second request on the same broker is served too (it loops)
        let err = request_listener(&path, &req([127, 0, 0, 1], 443)).unwrap_err();
        assert!(err.to_string().contains("not a ZTLP VIP"), "{err}");
        assert_eq!(
            prepared.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "refused requests must not alias"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live on the Studio: the agent started before the machine service
    /// had its socket up -> "No such file" -> the site's 443 never bound.
    /// A missing broker must be reported as retryable.
    #[test]
    fn missing_broker_socket_is_retryable() {
        let p = std::env::temp_dir().join(format!("ztlp-pb-none-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let err = request_listener(&p, &req([127, 100, 0, 3], 443)).unwrap_err();
        assert!(err.is_retryable(), "{err}");
        assert!(err.to_string().contains("unavailable"), "{err}");
    }

    #[test]
    fn needs_broker_only_below_1024() {
        assert!(needs_broker(443) && needs_broker(80) && needs_broker(22) && needs_broker(1023));
        assert!(!needs_broker(0) && !needs_broker(1024) && !needs_broker(8443));
    }

    #[test]
    fn fd_passes_between_processes_sides() {
        let (a, b) = UnixStream::pair().unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        send_fd(&a, l.as_raw_fd(), b"OK\n").unwrap();
        drop(l); // the receiver's copy must keep the socket alive
        let mut buf = [0u8; 8];
        let (n, fd) = recv_fd(&b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"OK\n");
        let got = std::net::TcpListener::from(fd.expect("fd"));
        assert_eq!(got.local_addr().unwrap(), addr);
        let _c = std::net::TcpStream::connect(addr).unwrap();
        assert!(got.accept().is_ok(), "received listener must accept");
    }

    /// End to end over a real broker socket, with an injected policy so the
    /// test can use an unprivileged 127.0.0.1 port without root.
    #[test]
    fn broker_hands_a_working_listener_to_the_client() {
        let dir = std::env::temp_dir().join(format!("ztlp-pb-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("b.sock");
        let _ = std::fs::remove_file(&path);
        let server = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let t = std::thread::spawn(move || {
            let (conn, _) = server.accept().unwrap();
            serve_one(
                conn,
                |_| Ok(()),
                |r| {
                    bind_listener(&BindRequest {
                        ip: Ipv4Addr::LOCALHOST,
                        port: r.port,
                    })
                },
            )
        });
        let free = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let l = request_listener(&path, &req([127, 0, 0, 1], free)).unwrap();
        assert!(t.join().unwrap().is_ok());
        assert_eq!(l.local_addr().unwrap().port(), free);
        let _c = std::net::TcpStream::connect(("127.0.0.1", free)).unwrap();
        assert!(l.accept().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broker_refusal_reaches_the_client_with_the_reason() {
        let dir = std::env::temp_dir().join(format!("ztlp-pb-r-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("b.sock");
        let _ = std::fs::remove_file(&path);
        let server = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let t = std::thread::spawn(move || {
            let (conn, _) = server.accept().unwrap();
            serve_one(conn, validate, bind_listener)
        });
        let err = request_listener(&path, &req([10, 0, 0, 5], 443)).unwrap_err();
        assert!(err.to_string().contains("not a ZTLP VIP"), "{err}");
        assert!(!err.is_retryable(), "a policy refusal is final");
        assert!(t.join().unwrap().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CodeRabbit #132: the socket is 0666, so any local process can connect
    /// and send nothing; serve_one blocked in read() forever, pinning one
    /// root thread per connection. It must give up after BROKER_IO_TIMEOUT.
    #[test]
    fn silent_client_times_out_instead_of_pinning_a_thread() {
        let (server, _client_kept_open_but_silent) = UnixStream::pair().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = serve_one(server, |_| Ok(()), |_| Err(io::Error::other("unused")));
            let _ = tx.send(r);
        });
        let got = rx
            .recv_timeout(BROKER_IO_TIMEOUT + std::time::Duration::from_secs(3))
            .expect("serve_one is still blocked on a silent client");
        assert!(got.is_err(), "a silent client is a failed request: {got:?}");
    }
}
