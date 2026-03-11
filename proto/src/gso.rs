//! UDP GSO (Generic Segmentation Offload) and GRO (Generic Receive Offload) support for Linux.
//!
//! **GSO (send-side):** When available, GSO lets us hand the kernel one large
//! buffer containing multiple logical UDP datagrams and a segment size. The
//! kernel (or NIC) splits them, eliminating per-packet syscall overhead.
//!
//! **GRO (receive-side):** When enabled, the kernel coalesces multiple incoming
//! UDP datagrams of the same size into a single large buffer. The application
//! reads this with one `recvmsg()` call and splits by the segment size reported
//! via the `UDP_GRO` cmsg.
//!
//! Fallback: on systems without GSO/GRO support, we fall back to standard
//! per-packet send_to() / recv_from() calls.

#![allow(unsafe_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Linux UDP_SEGMENT socket option for GSO.
#[cfg(target_os = "linux")]
const UDP_SEGMENT: libc::c_int = 103;

/// SOL_UDP for setsockopt/cmsg.
#[cfg(target_os = "linux")]
const SOL_UDP: libc::c_int = 17;

/// Maximum number of segments in a single GSO send on Linux.
/// The kernel enforces a limit; 64 is the typical maximum.
pub const MAX_GSO_SEGMENTS: usize = 64;

/// Linux UDP_GRO socket option.
#[cfg(target_os = "linux")]
const UDP_GRO: libc::c_int = 104;

/// Receive buffer size for GRO. With ZTLP tunnel packets at ~16KB and
/// up to 64 coalesced segments, 1MB is sufficient.
pub const GRO_RECV_BUF_SIZE: usize = 1_048_576;

// ─── GSO capability detection ───────────────────────────────────────────────

/// Whether GSO is available on this system/socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GsoCapability {
    /// GSO is available with the given maximum segment count.
    Available { max_segments: usize },
    /// GSO is not available (non-Linux, old kernel, or socket error).
    Unavailable,
}

impl GsoCapability {
    /// Returns true if GSO is available.
    pub fn is_available(&self) -> bool {
        matches!(self, GsoCapability::Available { .. })
    }
}

/// Probe whether the given UDP socket supports GSO.
///
/// We try setting `UDP_SEGMENT` via setsockopt. If the kernel accepts it,
/// GSO is available. We immediately clear the option afterwards (it's set
/// per-sendmsg via cmsg in the actual send path).
#[cfg(target_os = "linux")]
pub fn detect_gso(socket: &UdpSocket) -> GsoCapability {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let segment_size: u16 = 1200; // arbitrary test value

    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_SEGMENT,
            &segment_size as *const u16 as *const libc::c_void,
            std::mem::size_of::<u16>() as libc::socklen_t,
        )
    };

    if ret == 0 {
        // Clear the sockopt — we set it per-send via cmsg
        let zero: u16 = 0;
        unsafe {
            libc::setsockopt(
                fd,
                SOL_UDP,
                UDP_SEGMENT,
                &zero as *const u16 as *const libc::c_void,
                std::mem::size_of::<u16>() as libc::socklen_t,
            );
        }
        debug!("GSO detected: available (max_segments={})", MAX_GSO_SEGMENTS);
        GsoCapability::Available {
            max_segments: MAX_GSO_SEGMENTS,
        }
    } else {
        let err = io::Error::last_os_error();
        debug!("GSO not available: {}", err);
        GsoCapability::Unavailable
    }
}

/// Non-Linux: GSO is always unavailable.
#[cfg(not(target_os = "linux"))]
pub fn detect_gso(_socket: &UdpSocket) -> GsoCapability {
    debug!("GSO not available (non-Linux platform)");
    GsoCapability::Unavailable
}

// ─── GRO capability detection ───────────────────────────────────────────────

/// Whether GRO is available on this system/socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroCapability {
    /// GRO is available and has been enabled on the socket.
    Available,
    /// GRO is not available (non-Linux, old kernel, or socket error).
    Unavailable,
}

impl GroCapability {
    /// Returns true if GRO is available.
    pub fn is_available(&self) -> bool {
        matches!(self, GroCapability::Available)
    }
}

/// Probe whether the given UDP socket supports GRO and enable it.
///
/// Unlike GSO detection which sets-and-clears, GRO is **left enabled** on
/// the socket because it's a socket-level option that affects all subsequent
/// receives.
#[cfg(target_os = "linux")]
pub fn detect_gro(socket: &UdpSocket) -> GroCapability {
    match enable_gro(socket) {
        Ok(()) => {
            debug!("GRO detected: available (enabled on socket)");
            GroCapability::Available
        }
        Err(e) => {
            debug!("GRO not available: {}", e);
            GroCapability::Unavailable
        }
    }
}

/// Non-Linux: GRO is always unavailable.
#[cfg(not(target_os = "linux"))]
pub fn detect_gro(_socket: &UdpSocket) -> GroCapability {
    debug!("GRO not available (non-Linux platform)");
    GroCapability::Unavailable
}

/// Enable GRO on the given UDP socket via `setsockopt(SOL_UDP, UDP_GRO, 1)`.
///
/// Returns an error if the kernel doesn't support UDP_GRO.
#[cfg(target_os = "linux")]
pub fn enable_gro(socket: &UdpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let val: libc::c_int = 1;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Non-Linux: GRO enable always fails.
#[cfg(not(target_os = "linux"))]
pub fn enable_gro(_socket: &UdpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "GRO is only available on Linux",
    ))
}

// ─── GRO segment + receive ─────────────────────────────────────────────────

/// A single segment extracted from a (possibly coalesced) GRO receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroSegment {
    /// Start offset in the receive buffer.
    pub offset: usize,
    /// Length of this segment.
    pub len: usize,
    /// Source address.
    pub addr: SocketAddr,
}

/// Split a received buffer into segments based on the GRO segment size.
///
/// If `gso_size` is `Some(size)`, the buffer is split into chunks of `size`
/// bytes, with the last chunk possibly shorter. If `None`, the entire buffer
/// is treated as a single segment.
pub fn split_gro_segments(
    total_len: usize,
    gso_size: Option<u16>,
    addr: SocketAddr,
) -> Vec<GroSegment> {
    match gso_size {
        Some(seg_size) if seg_size > 0 => {
            let seg = seg_size as usize;
            let mut segments = Vec::with_capacity((total_len + seg - 1) / seg);
            let mut offset = 0;
            while offset < total_len {
                let remaining = total_len - offset;
                let len = remaining.min(seg);
                segments.push(GroSegment { offset, len, addr });
                offset += len;
            }
            segments
        }
        _ => {
            // No GRO cmsg or zero size → single segment
            vec![GroSegment {
                offset: 0,
                len: total_len,
                addr,
            }]
        }
    }
}

/// Receive using `recvmsg()` with GRO cmsg parsing.
///
/// If GRO is enabled and the kernel coalesced datagrams, the `UDP_GRO` cmsg
/// will contain the segment size. The returned segments describe how to split
/// the buffer.
///
/// The caller provides the buffer; on return, `buf[..total_len]` contains the
/// received data and the returned segments describe individual datagrams.
#[cfg(target_os = "linux")]
pub fn recv_gro_sync(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<u16>)> {
    let mut sockaddr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // cmsg buffer: enough for UDP_GRO (u16) plus alignment
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space.max(256)];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut sockaddr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let ret = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let total_len = ret as usize;

    // Parse source address
    let addr = raw_to_socket_addr(&sockaddr, msg.msg_namelen)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to parse source address"))?;

    // Parse cmsg for UDP_GRO segment size
    let mut gso_size: Option<u16> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == SOL_UDP && (*cmsg).cmsg_type == UDP_GRO {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const u16;
                gso_size = Some(std::ptr::read_unaligned(data_ptr));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((total_len, addr, gso_size))
}

/// Non-Linux: GRO recv falls back to regular recv_from.
#[cfg(not(target_os = "linux"))]
pub fn recv_gro_sync(
    _fd: i32,
    _buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<u16>)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "GRO recvmsg is only available on Linux",
    ))
}

// ─── Socket address conversion (reverse) ────────────────────────────────────

/// Convert a raw `sockaddr_storage` back to a `SocketAddr`.
///
/// This is the reverse of `socket_addr_to_raw()`.
#[cfg(target_os = "linux")]
pub fn raw_to_socket_addr(
    storage: &libc::sockaddr_storage,
    _len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn raw_to_socket_addr(
    _storage: &libc::sockaddr_storage,
    _len: libc::socklen_t,
) -> Option<SocketAddr> {
    None
}

// ─── RecvBatch ──────────────────────────────────────────────────────────────

/// A batch of received segments from a single `recvmsg()` call.
///
/// The buffer is owned by `RecvBatch`. Individual segments are described
/// by offset + length into this buffer.
pub struct RecvBatch {
    /// The raw receive buffer data.
    buf: Vec<u8>,
    /// Total bytes actually received (valid data in `buf[..total_len]`).
    total_len: usize,
    /// Individual segments.
    segments: Vec<GroSegment>,
}

impl RecvBatch {
    /// Get the raw buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buf[..self.total_len]
    }

    /// Get the segments.
    pub fn segments(&self) -> &[GroSegment] {
        &self.segments
    }

    /// Number of segments in this batch.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Whether this batch is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Total bytes received.
    pub fn total_bytes(&self) -> usize {
        self.total_len
    }
}

// ─── GroReceiver — high-level wrapper ───────────────────────────────────────

/// A high-level wrapper around a UDP socket that transparently uses GRO
/// for efficient batch receiving.
///
/// Similar to `UdpSender` on the send side, `GroReceiver` probes for GRO
/// support and enables it on the socket. When GRO is active, a single
/// `recv()` call may return multiple coalesced datagrams.
pub struct GroReceiver {
    socket: Arc<UdpSocket>,
    gro_enabled: bool,
    buf: Vec<u8>,
}

impl GroReceiver {
    /// Create a new `GroReceiver` wrapping the given socket.
    ///
    /// Probes GRO capability and enables it unless `mode` is `Disabled`.
    pub fn new(socket: Arc<UdpSocket>, mode: GsoMode) -> Self {
        let gro_enabled = match mode {
            GsoMode::Disabled => false,
            _ => detect_gro(&socket).is_available(),
        };

        let buf_size = if gro_enabled {
            GRO_RECV_BUF_SIZE
        } else {
            65535
        };

        debug!(
            "GroReceiver created: mode={}, gro_enabled={}",
            mode, gro_enabled
        );

        Self {
            socket,
            gro_enabled,
            buf: vec![0u8; buf_size],
        }
    }

    /// Whether GRO is enabled on this receiver.
    pub fn is_gro_enabled(&self) -> bool {
        self.gro_enabled
    }

    /// Receive one batch of (possibly coalesced) UDP datagrams.
    ///
    /// When GRO is enabled, the kernel may coalesce multiple datagrams into
    /// a single buffer. The returned `RecvBatch` contains the raw data and
    /// segment descriptors.
    ///
    /// When GRO is not enabled, each call returns exactly one segment.
    pub async fn recv(&mut self) -> io::Result<RecvBatch> {
        if self.gro_enabled {
            self.recv_gro().await
        } else {
            self.recv_plain().await
        }
    }

    /// GRO-enabled receive path using raw recvmsg().
    #[cfg(target_os = "linux")]
    async fn recv_gro(&mut self) -> io::Result<RecvBatch> {
        use std::os::unix::io::AsRawFd;

        loop {
            self.socket.readable().await?;

            let fd = self.socket.as_raw_fd();
            match recv_gro_sync(fd, &mut self.buf) {
                Ok((total_len, addr, gso_size)) => {
                    let segments = split_gro_segments(total_len, gso_size, addr);
                    trace!(
                        "GRO recv: {} bytes, {} segments (gso_size={:?}) from {}",
                        total_len,
                        segments.len(),
                        gso_size,
                        addr
                    );

                    // Copy the received data into the RecvBatch's own buffer
                    let mut batch_buf = vec![0u8; total_len];
                    batch_buf.copy_from_slice(&self.buf[..total_len]);

                    return Ok(RecvBatch {
                        buf: batch_buf,
                        total_len,
                        segments,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Spurious readiness — retry
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Non-Linux: GRO is not available, fall back to plain recv.
    #[cfg(not(target_os = "linux"))]
    async fn recv_gro(&mut self) -> io::Result<RecvBatch> {
        self.recv_plain().await
    }

    /// Plain receive path (no GRO). Always returns exactly one segment.
    async fn recv_plain(&mut self) -> io::Result<RecvBatch> {
        let (n, addr) = self.socket.recv_from(&mut self.buf).await?;
        let mut batch_buf = vec![0u8; n];
        batch_buf.copy_from_slice(&self.buf[..n]);
        Ok(RecvBatch {
            buf: batch_buf,
            total_len: n,
            segments: vec![GroSegment {
                offset: 0,
                len: n,
                addr,
            }],
        })
    }

    /// Get a reference to the underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Get a clone of the underlying socket Arc.
    pub fn socket_arc(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

// ─── Buffer assembly ────────────────────────────────────────────────────────

/// Assemble multiple segments into a single contiguous buffer for GSO.
///
/// All segments except the last MUST be exactly `segment_size` bytes.
/// The last segment may be shorter. Returns the assembled buffer.
///
/// Returns an error if:
/// - `segment_size` is 0
/// - Any non-last segment doesn't match `segment_size`
/// - `segments` is empty
pub fn assemble_gso_buffer(segments: &[&[u8]], segment_size: u16) -> io::Result<Vec<u8>> {
    if segment_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "segment_size must be > 0",
        ));
    }
    if segments.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "segments must not be empty",
        ));
    }
    let seg_sz = segment_size as usize;

    // Validate: all segments except the last must be exactly segment_size
    for (i, seg) in segments.iter().enumerate() {
        if i < segments.len() - 1 && seg.len() != seg_sz {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "segment {} is {} bytes, expected {} (all non-last segments must match segment_size)",
                    i, seg.len(), seg_sz
                ),
            ));
        }
        if seg.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("segment {} is empty", i),
            ));
        }
    }

    // Last segment must be <= segment_size
    if segments.last().unwrap().len() > seg_sz {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "last segment is {} bytes, exceeds segment_size {}",
                segments.last().unwrap().len(),
                seg_sz
            ),
        ));
    }

    let total_len: usize = segments.iter().map(|s| s.len()).sum();
    let mut buf = Vec::with_capacity(total_len);
    for seg in segments {
        buf.extend_from_slice(seg);
    }
    Ok(buf)
}

// ─── GSO send ───────────────────────────────────────────────────────────────

/// Send multiple segments via a single `sendmsg()` with GSO (UDP_SEGMENT cmsg).
///
/// `segments` are the individual datagrams to send. They will be assembled
/// into a single contiguous buffer. The kernel splits them by `segment_size`.
///
/// All segments except the last must be exactly `segment_size` bytes.
/// The last segment may be shorter.
///
/// Returns the total number of bytes sent.
#[cfg(target_os = "linux")]
pub async fn send_gso(
    socket: &UdpSocket,
    segments: &[&[u8]],
    segment_size: u16,
    dest: SocketAddr,
) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;

    if segments.is_empty() {
        return Ok(0);
    }

    // For a single segment, just use regular send_to — no GSO overhead
    if segments.len() == 1 {
        socket.writable().await?;
        return socket.send_to(segments[0], dest).await;
    }

    let buffer = assemble_gso_buffer(segments, segment_size)?;
    let total_len = buffer.len();

    // Wait for the socket to be writable (tokio reactor integration)
    socket.writable().await?;

    let fd = socket.as_raw_fd();

    // Build sockaddr
    let (sockaddr, sockaddr_len) = socket_addr_to_raw(dest);

    // Build iovec
    let iov = libc::iovec {
        iov_base: buffer.as_ptr() as *mut libc::c_void,
        iov_len: total_len,
    };

    // Build cmsg buffer for UDP_SEGMENT
    // CMSG space: cmsg_header + u16 payload (padded)
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    // Build msghdr
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &sockaddr as *const _ as *mut libc::c_void;
    msg.msg_namelen = sockaddr_len;
    msg.msg_iov = &iov as *const _ as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    // Fill in the cmsg
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "CMSG_FIRSTHDR returned null",
            ));
        }
        (*cmsg).cmsg_level = SOL_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
        // The kernel expects the segment size in host byte order (native u16)
        std::ptr::write_unaligned(data_ptr, segment_size);
    }

    // sendmsg
    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        warn!("GSO sendmsg failed: {}", err);
        return Err(err);
    }

    trace!(
        "GSO sent {} segments ({} bytes total, segment_size={}) to {}",
        segments.len(),
        ret,
        segment_size,
        dest
    );
    Ok(ret as usize)
}

/// Non-Linux fallback: GSO send is not available; return an error.
#[cfg(not(target_os = "linux"))]
pub async fn send_gso(
    _socket: &UdpSocket,
    _segments: &[&[u8]],
    _segment_size: u16,
    _dest: SocketAddr,
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "GSO is only available on Linux",
    ))
}

// ─── sendmmsg ───────────────────────────────────────────────────────────────

/// Send multiple independent datagrams via a single `sendmmsg()` syscall.
///
/// Unlike GSO, sendmmsg doesn't require all segments to be the same size.
/// Each element of `packets` is sent as a separate UDP datagram.
///
/// Returns the number of messages successfully sent.
#[cfg(target_os = "linux")]
pub async fn send_mmsg(
    socket: &UdpSocket,
    packets: &[&[u8]],
    dest: SocketAddr,
) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;

    if packets.is_empty() {
        return Ok(0);
    }

    if packets.len() == 1 {
        socket.writable().await?;
        socket.send_to(packets[0], dest).await?;
        return Ok(1);
    }

    socket.writable().await?;

    let fd = socket.as_raw_fd();
    let (sockaddr, sockaddr_len) = socket_addr_to_raw(dest);

    // Build iovecs — one per packet
    let iovecs: Vec<libc::iovec> = packets
        .iter()
        .map(|pkt| libc::iovec {
            iov_base: pkt.as_ptr() as *mut libc::c_void,
            iov_len: pkt.len(),
        })
        .collect();

    // Build mmsghdr array
    let mut msgs: Vec<libc::mmsghdr> = iovecs
        .iter()
        .map(|iov| {
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_name = &sockaddr as *const _ as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = sockaddr_len;
            hdr.msg_hdr.msg_iov = iov as *const libc::iovec as *mut libc::iovec;
            hdr.msg_hdr.msg_iovlen = 1;
            hdr
        })
        .collect();

    let ret = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, 0) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        warn!("sendmmsg failed: {}", err);
        return Err(err);
    }

    trace!(
        "sendmmsg sent {}/{} packets to {}",
        ret,
        packets.len(),
        dest
    );
    Ok(ret as usize)
}

/// Non-Linux fallback: sendmmsg is not available.
#[cfg(not(target_os = "linux"))]
pub async fn send_mmsg(
    _socket: &UdpSocket,
    _packets: &[&[u8]],
    _dest: SocketAddr,
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sendmmsg is only available on Linux",
    ))
}

// ─── Socket address conversion ──────────────────────────────────────────────

/// Convert a `SocketAddr` to a raw `libc::sockaddr_storage` + length.
#[cfg(target_os = "linux")]
fn socket_addr_to_raw(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    match addr {
        SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

// ─── GsoMode configuration ─────────────────────────────────────────────────

/// Configuration for GSO behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GsoMode {
    /// Automatically detect and use GSO if available.
    Auto,
    /// Force GSO on (fail if unavailable).
    Enabled,
    /// Disable GSO entirely, always use individual sends.
    Disabled,
}

impl GsoMode {
    /// Parse from a string (for config file / CLI).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "enabled" | "on" | "true" | "yes" => GsoMode::Enabled,
            "disabled" | "off" | "false" | "no" => GsoMode::Disabled,
            _ => GsoMode::Auto,
        }
    }
}

impl Default for GsoMode {
    fn default() -> Self {
        GsoMode::Auto
    }
}

impl std::fmt::Display for GsoMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GsoMode::Auto => write!(f, "auto"),
            GsoMode::Enabled => write!(f, "enabled"),
            GsoMode::Disabled => write!(f, "disabled"),
        }
    }
}

// ─── UdpSender — high-level wrapper ────────────────────────────────────────

/// Strategy the `UdpSender` chose for sending packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendStrategy {
    /// Using GSO (single sendmsg with UDP_SEGMENT cmsg).
    Gso,
    /// Using sendmmsg (one syscall, multiple messages).
    SendMmsg,
    /// Using individual send_to calls (fallback).
    Individual,
}

impl std::fmt::Display for SendStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendStrategy::Gso => write!(f, "GSO"),
            SendStrategy::SendMmsg => write!(f, "sendmmsg"),
            SendStrategy::Individual => write!(f, "individual"),
        }
    }
}

/// A wrapper around a `UdpSocket` that transparently uses the best available
/// send method: GSO → sendmmsg → individual send_to.
pub struct UdpSender {
    socket: std::sync::Arc<UdpSocket>,
    capability: GsoCapability,
    mode: GsoMode,
}

impl UdpSender {
    /// Create a new `UdpSender` with automatic GSO detection.
    pub fn new(socket: std::sync::Arc<UdpSocket>, mode: GsoMode) -> Self {
        let capability = match mode {
            GsoMode::Disabled => GsoCapability::Unavailable,
            _ => detect_gso(&socket),
        };

        debug!(
            "UdpSender created: mode={}, capability={:?}",
            mode, capability
        );

        Self {
            socket,
            capability,
            mode,
        }
    }

    /// Create with a specific capability (for testing).
    pub fn with_capability(
        socket: std::sync::Arc<UdpSocket>,
        mode: GsoMode,
        capability: GsoCapability,
    ) -> Self {
        Self {
            socket,
            capability,
            mode,
        }
    }

    /// The GSO capability detected for this sender.
    pub fn capability(&self) -> GsoCapability {
        self.capability
    }

    /// The active send strategy this sender will use.
    pub fn strategy(&self) -> SendStrategy {
        match self.mode {
            GsoMode::Disabled => {
                // sendmmsg is independent of GSO mode
                #[cfg(target_os = "linux")]
                return SendStrategy::SendMmsg;
                #[cfg(not(target_os = "linux"))]
                return SendStrategy::Individual;
            }
            GsoMode::Enabled | GsoMode::Auto => {
                if self.capability.is_available() {
                    SendStrategy::Gso
                } else {
                    #[cfg(target_os = "linux")]
                    return SendStrategy::SendMmsg;
                    #[cfg(not(target_os = "linux"))]
                    return SendStrategy::Individual;
                }
            }
        }
    }

    /// Get a reference to the underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Get a clone of the socket Arc.
    pub fn socket_arc(&self) -> std::sync::Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Send a single packet. Always uses plain send_to.
    pub async fn send_one(&self, data: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(data, dest).await
    }

    /// Send multiple packets to the same destination using the best available method.
    ///
    /// For GSO: all packets must be the same size (except possibly the last one).
    /// If packets have varying sizes, falls back to sendmmsg or individual sends.
    ///
    /// Returns the number of packets successfully sent.
    pub async fn send_batch(&self, packets: &[Vec<u8>], dest: SocketAddr) -> io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }
        if packets.len() == 1 {
            self.socket.send_to(&packets[0], dest).await?;
            return Ok(1);
        }

        let strategy = self.strategy();

        match strategy {
            SendStrategy::Gso => {
                // Check if all packets (except last) are the same size
                let first_size = packets[0].len();
                let all_same = packets[..packets.len() - 1]
                    .iter()
                    .all(|p| p.len() == first_size)
                    && packets.last().map_or(true, |p| p.len() <= first_size);

                if all_same && first_size > 0 && first_size <= u16::MAX as usize {
                    let max_segs = match self.capability {
                        GsoCapability::Available { max_segments } => max_segments,
                        GsoCapability::Unavailable => MAX_GSO_SEGMENTS,
                    };

                    // Split into GSO-sized groups
                    let mut total_sent = 0;
                    for chunk in packets.chunks(max_segs) {
                        let refs: Vec<&[u8]> = chunk.iter().map(|p| p.as_slice()).collect();
                        match send_gso(&self.socket, &refs, first_size as u16, dest).await {
                            Ok(_bytes) => {
                                total_sent += chunk.len();
                            }
                            Err(e) => {
                                // GSO failed — fall back to sendmmsg or individual
                                warn!("GSO send failed, falling back: {}", e);
                                let remaining = &packets[total_sent..];
                                total_sent +=
                                    self.send_batch_fallback(remaining, dest).await?;
                                return Ok(total_sent);
                            }
                        }
                    }
                    return Ok(total_sent);
                } else {
                    // Mixed sizes — can't use GSO, fall back
                    return self.send_batch_fallback(packets, dest).await;
                }
            }
            SendStrategy::SendMmsg => {
                return self.send_batch_sendmmsg(packets, dest).await;
            }
            SendStrategy::Individual => {
                return self.send_batch_individual(packets, dest).await;
            }
        }
    }

    /// Fallback path: try sendmmsg, then individual.
    async fn send_batch_fallback(
        &self,
        packets: &[Vec<u8>],
        dest: SocketAddr,
    ) -> io::Result<usize> {
        match self.send_batch_sendmmsg(packets, dest).await {
            Ok(n) => Ok(n),
            Err(_) => self.send_batch_individual(packets, dest).await,
        }
    }

    /// Send via sendmmsg.
    async fn send_batch_sendmmsg(
        &self,
        packets: &[Vec<u8>],
        dest: SocketAddr,
    ) -> io::Result<usize> {
        let refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();
        send_mmsg(&self.socket, &refs, dest).await
    }

    /// Send packets individually.
    async fn send_batch_individual(
        &self,
        packets: &[Vec<u8>],
        dest: SocketAddr,
    ) -> io::Result<usize> {
        let mut sent = 0;
        for pkt in packets {
            match self.socket.send_to(pkt, dest).await {
                Ok(_) => sent += 1,
                Err(e) => {
                    if sent == 0 {
                        return Err(e);
                    }
                    warn!(
                        "individual send failed after {} packets: {}",
                        sent, e
                    );
                    return Ok(sent);
                }
            }
        }
        Ok(sent)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gso_detection() {
        // Create a UDP socket and probe GSO
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cap = detect_gso(&socket);
        // On Linux with a modern kernel, this should be Available.
        // On non-Linux or old kernels, Unavailable. Either is valid.
        match cap {
            GsoCapability::Available { max_segments } => {
                assert!(max_segments > 0);
                println!("GSO available: max_segments={}", max_segments);
            }
            GsoCapability::Unavailable => {
                println!("GSO not available on this system");
            }
        }
    }

    #[tokio::test]
    async fn test_gso_send_basic() {
        // Send 10 segments via GSO (or fallback), receive individually
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let cap = detect_gso(&sender);
        if !cap.is_available() {
            println!("Skipping GSO send test — GSO not available");
            // Test the fallback path instead
            let udp_sender =
                UdpSender::new(std::sync::Arc::new(sender), GsoMode::Auto);
            let packets: Vec<Vec<u8>> = (0..10).map(|i| vec![i; 100]).collect();
            let sent = udp_sender.send_batch(&packets, dest).await.unwrap();
            assert_eq!(sent, 10);

            // Receive all 10
            let mut buf = [0u8; 200];
            for i in 0..10u8 {
                let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
                assert_eq!(n, 100);
                assert_eq!(buf[0], i);
            }
            return;
        }

        // GSO path
        let segments: Vec<Vec<u8>> = (0..10).map(|i| vec![i; 100]).collect();
        let refs: Vec<&[u8]> = segments.iter().map(|s| s.as_slice()).collect();
        let bytes_sent = send_gso(&sender, &refs, 100, dest).await.unwrap();
        assert_eq!(bytes_sent, 1000);

        // Receive the 10 individual datagrams
        let mut buf = [0u8; 200];
        for i in 0..10u8 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 100);
            assert!(buf[..n].iter().all(|&b| b == i));
        }
    }

    #[tokio::test]
    async fn test_gso_send_varied_last_segment() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let cap = detect_gso(&sender);
        if !cap.is_available() {
            println!("Skipping — GSO not available");
            return;
        }

        // 4 segments of 100 bytes + 1 segment of 50 bytes
        let mut segments: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 100]).collect();
        segments.push(vec![0xFF; 50]);

        let refs: Vec<&[u8]> = segments.iter().map(|s| s.as_slice()).collect();
        let bytes_sent = send_gso(&sender, &refs, 100, dest).await.unwrap();
        assert_eq!(bytes_sent, 450);

        let mut buf = [0u8; 200];
        for i in 0..4u8 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 100);
            assert!(buf[..n].iter().all(|&b| b == i));
        }
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 50);
        assert!(buf[..n].iter().all(|&b| b == 0xFF));
    }

    #[tokio::test]
    async fn test_gso_send_single_segment() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        // Single segment — should just use send_to
        let segments = vec![vec![0xAA; 200]];
        let refs: Vec<&[u8]> = segments.iter().map(|s| s.as_slice()).collect();
        let bytes_sent = send_gso(&sender, &refs, 200, dest).await.unwrap();
        assert_eq!(bytes_sent, 200);

        let mut buf = [0u8; 300];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 200);
        assert!(buf[..n].iter().all(|&b| b == 0xAA));
    }

    #[tokio::test]
    async fn test_gso_send_max_segments() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let cap = detect_gso(&sender);
        if !cap.is_available() {
            println!("Skipping — GSO not available");
            return;
        }

        // Send MAX_GSO_SEGMENTS (64) segments of 100 bytes each
        let segments: Vec<Vec<u8>> = (0..MAX_GSO_SEGMENTS)
            .map(|i| vec![(i & 0xFF) as u8; 100])
            .collect();
        let refs: Vec<&[u8]> = segments.iter().map(|s| s.as_slice()).collect();
        let bytes_sent = send_gso(&sender, &refs, 100, dest).await.unwrap();
        assert_eq!(bytes_sent, MAX_GSO_SEGMENTS * 100);

        let mut buf = [0u8; 200];
        for i in 0..MAX_GSO_SEGMENTS {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 100);
            assert!(buf[..n].iter().all(|&b| b == (i & 0xFF) as u8));
        }
    }

    #[tokio::test]
    async fn test_gso_fallback_on_unsupported() {
        // Force disabled mode → uses fallback
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let udp_sender =
            UdpSender::new(std::sync::Arc::new(sender), GsoMode::Disabled);
        assert!(!udp_sender.capability().is_available());

        let packets: Vec<Vec<u8>> = (0..5).map(|i| vec![i; 80]).collect();
        let sent = udp_sender.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 200];
        for i in 0..5u8 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 80);
            assert!(buf[..n].iter().all(|&b| b == i));
        }
    }

    #[test]
    fn test_gso_segment_size_validation() {
        // segment_size = 0
        let segs: Vec<&[u8]> = vec![&[1, 2, 3]];
        assert!(assemble_gso_buffer(&segs, 0).is_err());

        // Empty segments list
        let segs: Vec<&[u8]> = vec![];
        assert!(assemble_gso_buffer(&segs, 100).is_err());

        // Non-last segment doesn't match segment_size
        let seg1 = vec![1u8; 100];
        let seg2 = vec![2u8; 50]; // wrong size (not last)
        let seg3 = vec![3u8; 100];
        let segs: Vec<&[u8]> = vec![&seg1, &seg2, &seg3];
        assert!(assemble_gso_buffer(&segs, 100).is_err());

        // Last segment larger than segment_size
        let seg1 = vec![1u8; 100];
        let seg2 = vec![2u8; 150]; // too large
        let segs: Vec<&[u8]> = vec![&seg1, &seg2];
        assert!(assemble_gso_buffer(&segs, 100).is_err());

        // Empty segment
        let seg1 = vec![1u8; 100];
        let seg2: Vec<u8> = vec![];
        let segs: Vec<&[u8]> = vec![&seg1, &seg2];
        assert!(assemble_gso_buffer(&segs, 100).is_err());
    }

    #[test]
    fn test_gso_buffer_assembly() {
        // 3 segments of 4 bytes each
        let seg1 = [1u8, 2, 3, 4];
        let seg2 = [5u8, 6, 7, 8];
        let seg3 = [9u8, 10, 11, 12];
        let segs: Vec<&[u8]> = vec![&seg1, &seg2, &seg3];
        let buf = assemble_gso_buffer(&segs, 4).unwrap();
        assert_eq!(buf, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        // Last segment shorter
        let seg1 = [0xAA; 8];
        let seg2 = [0xBB; 8];
        let seg3 = [0xCC; 5]; // shorter
        let segs: Vec<&[u8]> = vec![&seg1, &seg2, &seg3];
        let buf = assemble_gso_buffer(&segs, 8).unwrap();
        assert_eq!(buf.len(), 21);
        assert_eq!(&buf[0..8], &[0xAA; 8]);
        assert_eq!(&buf[8..16], &[0xBB; 8]);
        assert_eq!(&buf[16..21], &[0xCC; 5]);

        // Single segment
        let seg = [42u8; 10];
        let segs: Vec<&[u8]> = vec![&seg];
        let buf = assemble_gso_buffer(&segs, 10).unwrap();
        assert_eq!(buf, vec![42; 10]);
    }

    #[test]
    fn test_gso_cmsg_construction() {
        // Verify the cmsg buffer layout for UDP_SEGMENT
        let segment_size: u16 = 1200;
        let cmsg_space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        // Simulate building the msghdr + cmsg
        let iov = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &iov as *const _ as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            assert!(!cmsg.is_null());
            (*cmsg).cmsg_level = SOL_UDP;
            (*cmsg).cmsg_type = UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
            let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
            std::ptr::write_unaligned(data_ptr, segment_size);

            // Verify we can read it back
            assert_eq!((*cmsg).cmsg_level, SOL_UDP);
            assert_eq!((*cmsg).cmsg_type, UDP_SEGMENT);
            let read_back = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const u16);
            assert_eq!(read_back, segment_size);
        }
    }

    #[test]
    fn test_gso_mode_parsing() {
        assert_eq!(GsoMode::from_str_loose("auto"), GsoMode::Auto);
        assert_eq!(GsoMode::from_str_loose("Auto"), GsoMode::Auto);
        assert_eq!(GsoMode::from_str_loose("enabled"), GsoMode::Enabled);
        assert_eq!(GsoMode::from_str_loose("on"), GsoMode::Enabled);
        assert_eq!(GsoMode::from_str_loose("true"), GsoMode::Enabled);
        assert_eq!(GsoMode::from_str_loose("disabled"), GsoMode::Disabled);
        assert_eq!(GsoMode::from_str_loose("off"), GsoMode::Disabled);
        assert_eq!(GsoMode::from_str_loose("false"), GsoMode::Disabled);
        assert_eq!(GsoMode::from_str_loose("whatever"), GsoMode::Auto);
    }

    #[tokio::test]
    async fn test_udp_sender_strategy_detection() {
        let socket = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Disabled mode
        let sender = UdpSender::new(socket.clone(), GsoMode::Disabled);
        assert!(!sender.capability().is_available());
        #[cfg(target_os = "linux")]
        assert_eq!(sender.strategy(), SendStrategy::SendMmsg);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(sender.strategy(), SendStrategy::Individual);

        // Auto mode
        let sender = UdpSender::new(socket.clone(), GsoMode::Auto);
        let expected = if sender.capability().is_available() {
            SendStrategy::Gso
        } else {
            #[cfg(target_os = "linux")]
            { SendStrategy::SendMmsg }
            #[cfg(not(target_os = "linux"))]
            { SendStrategy::Individual }
        };
        assert_eq!(sender.strategy(), expected);
    }

    #[tokio::test]
    async fn test_udp_sender_send_one() {
        let sender_sock = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender = UdpSender::new(sender_sock, GsoMode::Auto);
        sender.send_one(&[1, 2, 3, 4], dest).await.unwrap();

        let mut buf = [0u8; 100];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_udp_sender_send_batch_empty() {
        let sender_sock = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender = UdpSender::new(sender_sock, GsoMode::Auto);
        let dest: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let sent = sender.send_batch(&[], dest).await.unwrap();
        assert_eq!(sent, 0);
    }

    #[tokio::test]
    async fn test_udp_sender_send_batch_single() {
        let sender_sock = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender = UdpSender::new(sender_sock, GsoMode::Auto);
        let packets = vec![vec![0xAA; 50]];
        let sent = sender.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 1);

        let mut buf = [0u8; 100];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 50);
    }

    // ── GRO tests ───────────────────────────────────────────────────────

    #[test]
    fn test_gro_detection() {
        // On Linux, GRO should be detected as available on modern kernels.
        // On other platforms it should be unavailable.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let cap = detect_gro(&socket);
            // We don't assert a specific value because it depends on the kernel,
            // but the function should not panic.
            println!("GRO capability: {:?}", cap);
        });
    }

    #[test]
    fn test_gro_enable_disable() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let result = enable_gro(&socket);
            // On Linux with kernel >= 5.x, this should succeed.
            // On older kernels or non-Linux, it may fail. Either way, no panic.
            println!("enable_gro result: {:?}", result);
        });
    }

    #[tokio::test]
    async fn test_gro_recv_single_packet() {
        // Receive a single packet with GRO receiver — should work normally.
        let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest = recv_sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut gro_recv = GroReceiver::new(recv_sock, GsoMode::Auto);

        // Send one packet
        sender.send_to(&[0xDE, 0xAD, 0xBE, 0xEF], dest).await.unwrap();

        // Receive it
        let batch = gro_recv.recv().await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.total_bytes(), 4);
        let seg = &batch.segments()[0];
        assert_eq!(seg.offset, 0);
        assert_eq!(seg.len, 4);
        assert_eq!(&batch.buffer()[seg.offset..seg.offset + seg.len], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[tokio::test]
    async fn test_gro_recv_coalesced() {
        // Send multiple same-size packets rapidly; receive with GRO.
        // The kernel may or may not coalesce depending on timing,
        // but the receiver should handle both cases correctly.
        let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest = recv_sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut gro_recv = GroReceiver::new(recv_sock, GsoMode::Auto);

        // Send 10 packets of 100 bytes each
        for i in 0u8..10 {
            let data = vec![i; 100];
            sender.send_to(&data, dest).await.unwrap();
        }

        // Receive all packets (may come as one or more batches)
        let mut total_segments = 0;
        let mut total_bytes = 0;

        for _ in 0..10 {
            if total_segments >= 10 {
                break;
            }
            let batch = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                gro_recv.recv(),
            )
            .await
            .unwrap()
            .unwrap();

            total_segments += batch.len();
            total_bytes += batch.total_bytes();
        }

        assert_eq!(total_segments, 10);
        assert_eq!(total_bytes, 1000);
    }

    #[test]
    fn test_gro_recv_buffer_splitting() {
        // Unit test the buffer splitting logic with known gso_size.
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // 1000 bytes with gso_size = 200 → 5 segments
        let segments = split_gro_segments(1000, Some(200), addr);
        assert_eq!(segments.len(), 5);
        for (i, seg) in segments.iter().enumerate() {
            assert_eq!(seg.offset, i * 200);
            assert_eq!(seg.len, 200);
            assert_eq!(seg.addr, addr);
        }

        // 950 bytes with gso_size = 200 → 5 segments, last is 150
        let segments = split_gro_segments(950, Some(200), addr);
        assert_eq!(segments.len(), 5);
        assert_eq!(segments[4].offset, 800);
        assert_eq!(segments[4].len, 150);

        // 200 bytes with gso_size = 200 → 1 segment
        let segments = split_gro_segments(200, Some(200), addr);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].offset, 0);
        assert_eq!(segments[0].len, 200);
    }

    #[test]
    fn test_gro_segment_iteration() {
        // Verify GroSegment offsets and lengths match expected values.
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();

        // Simulate a 4800-byte coalesced buffer with 1200-byte segments
        let segments = split_gro_segments(4800, Some(1200), addr);
        assert_eq!(segments.len(), 4);

        let expected: Vec<(usize, usize)> = vec![
            (0, 1200),
            (1200, 1200),
            (2400, 1200),
            (3600, 1200),
        ];

        for (seg, (exp_off, exp_len)) in segments.iter().zip(expected.iter()) {
            assert_eq!(seg.offset, *exp_off);
            assert_eq!(seg.len, *exp_len);
            assert_eq!(seg.addr, addr);
        }
    }

    #[tokio::test]
    async fn test_gro_receiver_wrapper() {
        // Test GroReceiver high-level API: create, check state, recv.
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest = sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut gro_recv = GroReceiver::new(sock.clone(), GsoMode::Auto);
        // gro_enabled depends on platform, but the API should work regardless
        println!("GRO enabled: {}", gro_recv.is_gro_enabled());

        // Send and receive
        sender.send_to(b"hello-gro", dest).await.unwrap();
        let batch = gro_recv.recv().await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.buffer(), b"hello-gro");
    }

    #[test]
    fn test_gro_fallback_no_cmsg() {
        // When no GRO cmsg is present (gso_size = None), return single segment.
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let segments = split_gro_segments(512, None, addr);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].offset, 0);
        assert_eq!(segments[0].len, 512);
        assert_eq!(segments[0].addr, addr);
    }

    #[tokio::test]
    async fn test_gro_recv_with_timeout() {
        // GRO recv should respect tokio timeouts.
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut gro_recv = GroReceiver::new(sock, GsoMode::Auto);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            gro_recv.recv(),
        )
        .await;

        // Should timeout since nobody sends anything
        assert!(result.is_err());
    }

    #[test]
    fn test_gro_large_coalesced_buffer() {
        // Test with buffers close to the max size.
        let addr: SocketAddr = "192.168.1.1:443".parse().unwrap();

        // Simulate 64 segments of ~16KB each (close to max GRO buffer)
        let seg_size: u16 = 16384;
        let num_segments = 64;
        let total_len = seg_size as usize * num_segments;

        let segments = split_gro_segments(total_len, Some(seg_size), addr);
        assert_eq!(segments.len(), num_segments);

        // Verify all segments are correct
        for (i, seg) in segments.iter().enumerate() {
            assert_eq!(seg.offset, i * seg_size as usize);
            assert_eq!(seg.len, seg_size as usize);
        }

        // Test with non-aligned total (last segment shorter)
        let total_len = seg_size as usize * 63 + 8000;
        let segments = split_gro_segments(total_len, Some(seg_size), addr);
        assert_eq!(segments.len(), 64);
        assert_eq!(segments[63].len, 8000);
    }

    #[tokio::test]
    async fn test_gro_receiver_disabled_mode() {
        // When mode is Disabled, GRO should not be enabled.
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest = sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut gro_recv = GroReceiver::new(sock, GsoMode::Disabled);
        assert!(!gro_recv.is_gro_enabled());

        sender.send_to(b"plain-recv", dest).await.unwrap();
        let batch = gro_recv.recv().await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.buffer(), b"plain-recv");
    }
}
