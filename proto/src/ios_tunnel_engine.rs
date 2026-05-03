//! iOS fd-backed tunnel engine scaffolding.
//!
//! This is Phase 1/2 groundwork for moving the iOS Network Extension data plane
//! away from Swift `NEPacketTunnelFlow` packet callbacks and toward a Nebula-style
//! Rust owner of the utun file descriptor. Production packet I/O is not switched
//! to this module yet.

#![allow(unsafe_code)]

use std::collections::HashSet;
use std::ffi::c_void;
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Minimal fd-backed utun wrapper for iOS.
///
/// iOS utun reads/writes include a 4-byte address-family header. The payload
/// seen by the ZTLP packet router is the raw IP packet after that header.
pub struct IosUtun {
    fd: RawFd,
    read_buf: Mutex<Vec<u8>>,
    write_buf: Mutex<Vec<u8>>,
}

impl IosUtun {
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            read_buf: Mutex::new(Vec::with_capacity(4096)),
            write_buf: Mutex::new(Vec::with_capacity(4096)),
        }
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Read a raw IP packet from the utun fd, stripping the 4-byte utun header.
    pub fn read_packet(&self, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = self
            .read_buf
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "utun read buffer poisoned"))?;
        let need = out.len().saturating_add(4);
        if buf.len() < need {
            buf.resize(need, 0);
        }

        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), need) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short utun packet header",
            ));
        }

        let payload_len = n - 4;
        if payload_len > out.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun packet larger than output buffer",
            ));
        }
        out[..payload_len].copy_from_slice(&buf[4..n]);
        Ok(payload_len)
    }

    /// Write a raw IP packet to the utun fd, prepending the 4-byte utun header.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        let frame = self.build_write_frame(packet)?;
        let n = unsafe { libc::write(self.fd, frame.as_ptr().cast(), frame.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((n as usize).saturating_sub(4))
    }

    /// Build the bytes written to utun. Exposed inside crate for unit tests.
    pub(crate) fn build_write_frame(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if packet.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty IP packet",
            ));
        }

        let family = match packet[0] >> 4 {
            4 => libc::AF_INET,
            6 => libc::AF_INET6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unable to determine IP version",
                ))
            }
        };

        let mut buf = self
            .write_buf
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "utun write buffer poisoned"))?;
        buf.clear();
        buf.resize(packet.len() + 4, 0);
        // Match Nebula's iOS utun behavior: Darwin AF value in the low byte of
        // the 4-byte header (`wBuf[3] = AF_INET/AF_INET6`).
        buf[3] = family as u8;
        buf[4..].copy_from_slice(packet);
        Ok(buf.clone())
    }
}

/// Opaque future owner for the Rust iOS tunnel engine.
#[derive(Clone, Copy)]
pub struct RouterActionCallback {
    callback: crate::ffi::ZtlpIosRouterActionCallback,
    user_data: usize,
}

impl RouterActionCallback {
    fn dispatch(&self, action_type: u8, stream_id: u32, data: *const u8, data_len: usize) {
        (self.callback)(
            self.user_data as *mut c_void,
            action_type,
            stream_id,
            data,
            data_len,
        );
    }
}

pub struct IosTunnelEngine {
    utun: Arc<IosUtun>,
    stop: Arc<AtomicBool>,
    read_thread: Mutex<Option<JoinHandle<()>>>,
    router_action_callback: Mutex<Option<RouterActionCallback>>,
}

impl IosTunnelEngine {
    pub fn start(utun_fd: RawFd) -> io::Result<Self> {
        if utun_fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid utun fd",
            ));
        }
        Ok(Self {
            utun: Arc::new(IosUtun::new(utun_fd)),
            stop: Arc::new(AtomicBool::new(false)),
            read_thread: Mutex::new(None),
            router_action_callback: Mutex::new(None),
        })
    }

    pub fn utun_fd(&self) -> RawFd {
        self.utun.fd()
    }

    /// Debug-only fd-owner smoke test: Rust becomes the sole utun reader and
    /// logs packet metadata, but intentionally drops packets instead of routing
    /// them. Swift must not run packetFlow.readPackets while this is active.
    pub fn start_read_metadata_loop(&self) -> io::Result<()> {
        self.start_read_loop(None)
    }

    /// Phase 3/4: Rust owns utun reads and feeds the PacketRouter.
    /// Router actions are dispatched through the optional Swift transport callback.
    pub fn start_router_ingress_loop(
        &self,
        router: *mut crate::ffi::ZtlpPacketRouter,
    ) -> io::Result<()> {
        if router.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "router is null",
            ));
        }
        self.start_read_loop(Some(router as usize))
    }

    pub fn set_router_action_callback(
        &self,
        callback: Option<crate::ffi::ZtlpIosRouterActionCallback>,
        user_data: *mut c_void,
    ) -> io::Result<()> {
        let mut guard = self.router_action_callback.lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "router action callback state poisoned",
            )
        })?;
        *guard = callback.map(|cb| RouterActionCallback {
            callback: cb,
            user_data: user_data as usize,
        });
        Ok(())
    }

    fn start_read_loop(&self, router_ptr: Option<usize>) -> io::Result<()> {
        let mut guard = self
            .read_thread
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "read thread state poisoned"))?;
        if guard.is_some() {
            return Ok(());
        }

        self.stop.store(false, Ordering::SeqCst);
        let utun = Arc::clone(&self.utun);
        let stop = Arc::clone(&self.stop);
        let callback = self
            .router_action_callback
            .lock()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "router action callback state poisoned",
                )
            })?
            .clone();
        let close_suppression_marker = format!(
            "Rust fd startup marker close_suppression_enabled=1 version={} git={} marker=close_suppression_v3",
            env!("CARGO_PKG_VERSION"),
            option_env!("ZTLP_GIT_COMMIT").unwrap_or("unknown")
        );
        crate::ffi::ios_log(&close_suppression_marker);

        *guard = Some(thread::spawn(move || {
            let mode = if router_ptr.is_some() {
                "router_ingress"
            } else {
                "read_drop_log"
            };
            let startup_diag = format!(
                "Rust fd read loop startup mode={} close_suppression_enabled=1 version={} git={} marker=close_suppression_v3",
                mode,
                env!("CARGO_PKG_VERSION"),
                option_env!("ZTLP_GIT_COMMIT").unwrap_or("unknown")
            );
            crate::ffi::ios_log(&startup_diag);
            if let Some(cb) = callback {
                cb.dispatch(250, 0, startup_diag.as_ptr(), startup_diag.len());
            }
            let mut packet = vec![0u8; 4096];
            let mut action_buf = vec![0u8; 65536];
            let mut outbound_packet_buf = vec![0u8; 4096];
            let mut packets: u64 = 0;
            let mut bytes: u64 = 0;
            let mut actions_total: u64 = 0;
            let mut action_bytes_total: u64 = 0;
            let mut closed_streams = HashSet::new();
            let mut utun_write_packets: u64 = 0;
            let mut utun_write_bytes: u64 = 0;
            let mut utun_write_errors: u64 = 0;
            let mut errors: u64 = 0;
            let mut tcp_syn_packets: u64 = 0;
            let mut tcp_payload_packets: u64 = 0;
            let mut tcp_fin_packets: u64 = 0;
            let mut tcp_rst_packets: u64 = 0;
            let mut non_tcp_packets: u64 = 0;
            let mut last_log = Instant::now();
            crate::ffi::ios_log(&format!(
                "Rust iOS tunnel engine fd read loop started mode={}",
                mode
            ));
            while !stop.load(Ordering::Relaxed) {
                match utun.read_packet(&mut packet) {
                    Ok(n) => {
                        packets += 1;
                        bytes += n as u64;
                        let version = packet.first().map(|b| b >> 4).unwrap_or(0);
                        let meta = PacketMeta::parse(&packet[..n]);
                        if let Some(meta) = meta {
                            if meta.protocol == 6 {
                                if meta.tcp_payload_len > 0 {
                                    tcp_payload_packets += 1;
                                }
                                if meta.tcp_syn {
                                    tcp_syn_packets += 1;
                                }
                                if meta.tcp_fin {
                                    tcp_fin_packets += 1;
                                }
                                if meta.tcp_rst {
                                    tcp_rst_packets += 1;
                                }
                            } else {
                                non_tcp_packets += 1;
                            }
                        } else {
                            non_tcp_packets += 1;
                        }
                        if let (Some(cb), Some(meta)) = (callback, meta) {
                            let should_report = packets <= 30
                                || meta.tcp_payload_len > 0
                                || meta.tcp_syn
                                || meta.tcp_fin
                                || meta.tcp_rst
                                || packets % 25 == 0;
                            if should_report {
                                let diag = format!(
                                    "proto={} flags={} tcp_payload={} src={}:{} dst={}:{} packets={} totals_syn={} payload={} fin={} rst={} non_tcp={}",
                                    meta.protocol,
                                    meta.flags_string(),
                                    meta.tcp_payload_len,
                                    meta.src_addr,
                                    meta.src_port,
                                    meta.dst_addr,
                                    meta.dst_port,
                                    packets,
                                    tcp_syn_packets,
                                    tcp_payload_packets,
                                    tcp_fin_packets,
                                    tcp_rst_packets,
                                    non_tcp_packets
                                );
                                cb.dispatch(250, 0, diag.as_ptr(), diag.len());
                            }
                        }
                        if let Some(response) = build_ios_dns_response(&packet[..n]) {
                            match utun.write_packet(&response) {
                                Ok(written) => {
                                    utun_write_packets += 1;
                                    utun_write_bytes += written as u64;
                                    if let Some(cb) = callback {
                                        let diag = format!(
                                            "Rust fd dns responder wrote response bytes={} packets={} totals_bytes={}",
                                            written, utun_write_packets, utun_write_bytes
                                        );
                                        cb.dispatch(251, 0, diag.as_ptr(), diag.len());
                                    }
                                }
                                Err(e) => {
                                    utun_write_errors += 1;
                                    crate::ffi::ios_log(&format!(
                                        "Rust fd dns responder utun write error: {} errors={}",
                                        e, utun_write_errors
                                    ));
                                }
                            }
                            continue;
                        }

                        let mut action_count: i32 = 0;
                        let mut action_written: usize = 0;
                        if let Some(router_addr) = router_ptr {
                            let router = router_addr as *mut crate::ffi::ZtlpPacketRouter;
                            // Directly call the existing FFI-safe router function so Swift and
                            // Rust use the same PacketRouter behavior during migration.
                            action_count = crate::ffi::ztlp_router_write_packet_sync(
                                router,
                                packet.as_ptr(),
                                n,
                                action_buf.as_mut_ptr(),
                                action_buf.len(),
                                &mut action_written as *mut usize,
                            );
                            if action_count < 0 {
                                errors += 1;
                            } else {
                                actions_total += action_count as u64;
                                action_bytes_total += action_written as u64;
                                if let Some(cb) = callback {
                                    let pre_diag = format!(
                                        "Rust fd dispatch pre action_count={} action_written={} close_suppression_enabled=1 marker=close_suppression_v3",
                                        action_count,
                                        action_written
                                    );
                                    if action_written > 0 {
                                        crate::ffi::ios_log(&pre_diag);
                                        cb.dispatch(250, 0, pre_diag.as_ptr(), pre_diag.len());
                                    }
                                    let summary = dispatch_router_actions(
                                        router,
                                        &action_buf[..action_written],
                                        cb,
                                        &mut closed_streams,
                                    );
                                    let post_diag = format!(
                                        "Rust fd dispatch post actions={} open={} send={} close={} suppressed_close={} unknown={} payload_bytes={} action_bytes={} close_suppression_enabled=1 marker=close_suppression_v3",
                                        summary.total,
                                        summary.open,
                                        summary.send,
                                        summary.close,
                                        summary.suppressed_close,
                                        summary.unknown,
                                        summary.payload_bytes,
                                        action_written
                                    );
                                    if action_written > 0 || summary.suppressed_close > 0 {
                                        crate::ffi::ios_log(&post_diag);
                                        cb.dispatch(250, 0, post_diag.as_ptr(), post_diag.len());
                                    }
                                    if summary.total > 0 {
                                        crate::ffi::ios_log(&format!(
                                            "Rust router action summary open={} send={} close={} suppressed_close={} unknown={} payload_bytes={} action_bytes={}",
                                            summary.open,
                                            summary.send,
                                            summary.close,
                                            summary.suppressed_close,
                                            summary.unknown,
                                            summary.payload_bytes,
                                            action_written
                                        ));
                                    }
                                }

                                let drain_summary = drain_router_outbound_to_utun(
                                    router,
                                    &utun,
                                    &mut outbound_packet_buf,
                                );
                                if drain_summary.packets > 0 || drain_summary.errors > 0 {
                                    utun_write_packets += drain_summary.packets;
                                    utun_write_bytes += drain_summary.bytes;
                                    utun_write_errors += drain_summary.errors;
                                    let diag = drain_summary.app_log_diag(
                                        utun_write_packets,
                                        utun_write_bytes,
                                        utun_write_errors,
                                    );
                                    crate::ffi::ios_log(&format!("Rust fd router {}", diag));
                                    if let Some(cb) = callback {
                                        cb.dispatch(251, 0, diag.as_ptr(), diag.len());
                                    }
                                }
                            }
                        }

                        if packets <= 5
                            || action_count > 0
                            || utun_write_packets > 0
                            || last_log.elapsed() >= Duration::from_secs(1)
                        {
                            if let Some(meta) = meta {
                                crate::ffi::ios_log(&format!(
                                    "Rust fd ingress packet packets={} bytes={} last_len={} ip_version={} proto={} tcp_flags={} tcp_payload={} src={}:{} dst={}:{} mode={} actions={} action_bytes={} utun_write_packets={} utun_write_bytes={} utun_write_errors={} totals_syn={} payload={} fin={} rst={} non_tcp={} errors={}",
                                    packets,
                                    bytes,
                                    n,
                                    version,
                                    meta.protocol,
                                    meta.flags_string(),
                                    meta.tcp_payload_len,
                                    meta.src_addr,
                                    meta.src_port,
                                    meta.dst_addr,
                                    meta.dst_port,
                                    mode,
                                    action_count,
                                    action_written,
                                    utun_write_packets,
                                    utun_write_bytes,
                                    utun_write_errors,
                                    tcp_syn_packets,
                                    tcp_payload_packets,
                                    tcp_fin_packets,
                                    tcp_rst_packets,
                                    non_tcp_packets,
                                    errors
                                ));
                            } else {
                                crate::ffi::ios_log(&format!(
                                    "Rust fd ingress packet packets={} bytes={} last_len={} ip_version={} proto=? mode={} actions={} action_bytes={} utun_write_packets={} utun_write_bytes={} utun_write_errors={} totals_syn={} payload={} fin={} rst={} non_tcp={} errors={}",
                                    packets,
                                    bytes,
                                    n,
                                    version,
                                    mode,
                                    action_count,
                                    action_written,
                                    utun_write_packets,
                                    utun_write_bytes,
                                    utun_write_errors,
                                    tcp_syn_packets,
                                    tcp_payload_packets,
                                    tcp_fin_packets,
                                    tcp_rst_packets,
                                    non_tcp_packets,
                                    errors
                                ));
                            }
                            last_log = Instant::now();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        errors += 1;
                        crate::ffi::ios_log(&format!(
                            "Rust fd read loop error: {} mode={} errors={}",
                            e, mode, errors
                        ));
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
            crate::ffi::ios_log(&format!(
                "Rust iOS tunnel engine fd read loop stopped packets={} bytes={} actions={} action_bytes={} utun_write_packets={} utun_write_bytes={} utun_write_errors={} tcp_syn={} tcp_payload={} tcp_fin={} tcp_rst={} non_tcp={} errors={} mode={}",
                packets,
                bytes,
                actions_total,
                action_bytes_total,
                utun_write_packets,
                utun_write_bytes,
                utun_write_errors,
                tcp_syn_packets,
                tcp_payload_packets,
                tcp_fin_packets,
                tcp_rst_packets,
                non_tcp_packets,
                errors,
                mode
            ));
        }));
        Ok(())
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.read_thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for IosTunnelEngine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.read_thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

#[derive(Clone, Copy)]
struct PacketMeta {
    protocol: u8,
    src_addr: IpAddrText,
    dst_addr: IpAddrText,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    tcp_payload_len: usize,
    tcp_syn: bool,
    tcp_fin: bool,
    tcp_rst: bool,
}

#[derive(Clone, Copy)]
struct IpAddrText([u8; 40], usize);

impl std::fmt::Display for IpAddrText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = std::str::from_utf8(&self.0[..self.1]).unwrap_or("?");
        write!(f, "{}", s)
    }
}

impl PacketMeta {
    fn parse(packet: &[u8]) -> Option<Self> {
        let version = packet.first()? >> 4;
        match version {
            4 => Self::parse_ipv4(packet),
            6 => Self::parse_ipv6(packet),
            _ => None,
        }
    }

    fn parse_ipv4(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        if ihl < 20 || packet.len() < ihl {
            return None;
        }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let total_len = total_len.min(packet.len());
        let protocol = packet[9];
        let src_addr = ipv4_text(&packet[12..16]);
        let dst_addr = ipv4_text(&packet[16..20]);
        Self::parse_l4(
            protocol,
            &packet[ihl..total_len],
            total_len.saturating_sub(ihl),
            src_addr,
            dst_addr,
        )
    }

    fn parse_ipv6(packet: &[u8]) -> Option<Self> {
        if packet.len() < 40 {
            return None;
        }
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let total_len = (40 + payload_len).min(packet.len());
        let protocol = packet[6];
        let src_addr = ipv6_text(&packet[8..24]);
        let dst_addr = ipv6_text(&packet[24..40]);
        Self::parse_l4(
            protocol,
            &packet[40..total_len],
            total_len.saturating_sub(40),
            src_addr,
            dst_addr,
        )
    }

    fn parse_l4(
        protocol: u8,
        l4: &[u8],
        l4_len: usize,
        src_addr: IpAddrText,
        dst_addr: IpAddrText,
    ) -> Option<Self> {
        if protocol != 6 || l4.len() < 20 {
            return Some(Self {
                protocol,
                src_addr,
                dst_addr,
                src_port: 0,
                dst_port: 0,
                tcp_flags: 0,
                tcp_payload_len: 0,
                tcp_syn: false,
                tcp_fin: false,
                tcp_rst: false,
            });
        }
        let src_port = u16::from_be_bytes([l4[0], l4[1]]);
        let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
        let data_offset = ((l4[12] >> 4) as usize) * 4;
        let tcp_flags = l4[13];
        let tcp_payload_len = l4_len.saturating_sub(data_offset);
        Some(Self {
            protocol,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            tcp_flags,
            tcp_payload_len,
            tcp_syn: tcp_flags & 0x02 != 0,
            tcp_fin: tcp_flags & 0x01 != 0,
            tcp_rst: tcp_flags & 0x04 != 0,
        })
    }

    fn flags_string(&self) -> &'static str {
        match (self.tcp_flags & 0x3f, self.tcp_payload_len > 0) {
            (0x02, _) => "SYN",
            (0x12, _) => "SYNACK",
            (0x10, false) => "ACK",
            (0x10, true) => "ACK+DATA",
            (0x18, false) => "PSHACK",
            (0x18, true) => "PSHACK+DATA",
            (0x11, _) => "FINACK",
            (0x01, _) => "FIN",
            (0x04, _) => "RST",
            _ => "OTHER",
        }
    }
}

fn ipv4_text(bytes: &[u8]) -> IpAddrText {
    let s = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
    text_to_fixed(&s)
}

fn ipv6_text(bytes: &[u8]) -> IpAddrText {
    let mut parts = [0u16; 8];
    for i in 0..8 {
        parts[i] = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }
    let s = format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]
    );
    text_to_fixed(&s)
}

fn text_to_fixed(s: &str) -> IpAddrText {
    let mut buf = [0u8; 40];
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    IpAddrText(buf, len)
}

const IOS_DNS_ADDR: [u8; 4] = [10, 122, 0, 1];
const DNS_TTL_SECONDS: u32 = 60;

fn build_ios_dns_response(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 || packet[9] != 17 || packet[16..20] != IOS_DNS_ADDR {
        return None;
    }
    let total_len = (u16::from_be_bytes([packet[2], packet[3]]) as usize).min(packet.len());
    if total_len < ihl + 8 {
        return None;
    }
    let udp = &packet[ihl..total_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || ihl + udp_len > total_len {
        return None;
    }
    let dns = &packet[ihl + 8..ihl + udp_len];
    let dns_resp = build_dns_payload_response(dns)?;

    let udp_resp_len = 8 + dns_resp.len();
    if udp_resp_len > u16::MAX as usize || ihl + udp_resp_len > u16::MAX as usize {
        return None;
    }
    let mut out = Vec::with_capacity(ihl + udp_resp_len);
    out.extend_from_slice(&packet[..ihl]);
    out[1] = 0;
    let total = (ihl + udp_resp_len) as u16;
    out[2..4].copy_from_slice(&total.to_be_bytes());
    out[6] = 0;
    out[7] = 0;
    out[8] = 64;
    out[9] = 17;
    out[10] = 0;
    out[11] = 0;
    out[12..16].copy_from_slice(&packet[16..20]);
    out[16..20].copy_from_slice(&packet[12..16]);
    let ip_sum = ipv4_checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&(udp_resp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&dns_resp);
    let udp_sum = udp_ipv4_checksum(&out[12..16], &out[16..20], &out[ihl..]);
    out[ihl + 6..ihl + 8].copy_from_slice(&udp_sum.to_be_bytes());
    Some(out)
}

fn build_dns_payload_response(dns: &[u8]) -> Option<Vec<u8>> {
    if dns.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    if flags & 0x8000 != 0 || u16::from_be_bytes([dns[4], dns[5]]) != 1 {
        return None;
    }
    let mut off = 12usize;
    let qname_start = off;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *dns.get(off)? as usize;
        off += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || len > 63 || off + len > dns.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&dns[off..off + len])
                .ok()?
                .to_ascii_lowercase(),
        );
        off += len;
    }
    if off + 4 > dns.len() {
        return None;
    }
    let question_end = off + 4;
    let qtype = u16::from_be_bytes([dns[off], dns[off + 1]]);
    let qclass = u16::from_be_bytes([dns[off + 2], dns[off + 3]]);
    let answer_ip = resolve_ztlp_name(&labels);
    let is_a_in = qtype == 1 && qclass == 1;
    let rcode = if answer_ip.is_some() && is_a_in { 0 } else { 3 };
    let ancount = if rcode == 0 { 1u16 } else { 0u16 };

    let mut out = Vec::with_capacity(question_end + 16);
    out.extend_from_slice(&dns[0..2]);
    out.extend_from_slice(&(0x8000u16 | 0x0400u16 | 0x0080u16 | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&dns[qname_start..question_end]);
    if let Some(ip) = answer_ip.filter(|_| is_a_in) {
        out.extend_from_slice(&0xc00cu16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&DNS_TTL_SECONDS.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip);
    }
    Some(out)
}

fn resolve_ztlp_name(labels: &[String]) -> Option<[u8; 4]> {
    if labels.last().map(String::as_str) != Some("ztlp") || labels.len() < 2 {
        return None;
    }
    match labels.first().map(String::as_str) {
        Some("vault") => Some([10, 122, 0, 4]),
        Some("http") | Some("proxy") => Some([10, 122, 0, 3]),
        Some(_) => Some([10, 122, 0, 2]),
        None => None,
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    finalize_checksum(sum_words(header))
}

fn udp_ipv4_checksum(src: &[u8], dst: &[u8], udp: &[u8]) -> u16 {
    let sum = sum_words(src) + sum_words(dst) + 17 + udp.len() as u32 + sum_words(udp);
    let c = finalize_checksum(sum);
    if c == 0 {
        0xffff
    } else {
        c
    }
}

fn sum_words(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += (b as u32) << 8;
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Default)]
struct RouterActionSummary {
    total: u64,
    open: u64,
    send: u64,
    close: u64,
    suppressed_close: u64,
    unknown: u64,
    payload_bytes: u64,
}

#[derive(Default, Clone, Copy)]
struct OutboundDrainSummary {
    packets: u64,
    bytes: u64,
    errors: u64,
    last_meta: Option<PacketMeta>,
}

impl OutboundDrainSummary {
    fn app_log_diag(&self, total_packets: u64, total_bytes: u64, total_errors: u64) -> String {
        if let Some(meta) = self.last_meta {
            format!(
                "outbound_wrote packets={} bytes={} errors={} last_proto={} last_flags={} last_tcp_payload={} last_src={}:{} last_dst={}:{} totals_packets={} totals_bytes={} totals_errors={}",
                self.packets,
                self.bytes,
                self.errors,
                meta.protocol,
                meta.flags_string(),
                meta.tcp_payload_len,
                meta.src_addr,
                meta.src_port,
                meta.dst_addr,
                meta.dst_port,
                total_packets,
                total_bytes,
                total_errors
            )
        } else {
            format!(
                "outbound_wrote packets={} bytes={} errors={} last_proto=? last_flags=? last_tcp_payload=0 last_src=?:0 last_dst=?:0 totals_packets={} totals_bytes={} totals_errors={}",
                self.packets,
                self.bytes,
                self.errors,
                total_packets,
                total_bytes,
                total_errors
            )
        }
    }
}

const MAX_ROUTER_OUTBOUND_DRAIN_PER_INGRESS: usize = 64;

fn drain_router_outbound_to_utun(
    router: *mut crate::ffi::ZtlpPacketRouter,
    utun: &IosUtun,
    packet_buf: &mut [u8],
) -> OutboundDrainSummary {
    let mut summary = OutboundDrainSummary::default();

    for _ in 0..MAX_ROUTER_OUTBOUND_DRAIN_PER_INGRESS {
        let n = crate::ffi::ztlp_router_read_packet_sync(
            router,
            packet_buf.as_mut_ptr(),
            packet_buf.len(),
        );
        if n == 0 {
            break;
        }
        if n < 0 {
            summary.errors += 1;
            break;
        }

        let n = n as usize;
        let meta = PacketMeta::parse(&packet_buf[..n]);
        match utun.write_packet(&packet_buf[..n]) {
            Ok(written) => {
                summary.packets += 1;
                summary.bytes += written as u64;
                summary.last_meta = meta;
            }
            Err(e) => {
                summary.errors += 1;
                crate::ffi::ios_log(&format!(
                    "Rust fd router outbound utun write error: {} packet_len={} errors={}",
                    e, n, summary.errors
                ));
                break;
            }
        }
    }

    summary
}

fn dispatch_router_actions(
    router: *mut crate::ffi::ZtlpPacketRouter,
    action_buf: &[u8],
    callback: RouterActionCallback,
    closed_streams: &mut HashSet<u32>,
) -> RouterActionSummary {
    let mut offset = 0usize;
    let mut summary = RouterActionSummary::default();
    while offset + 7 <= action_buf.len() {
        let action_type = action_buf[offset];
        offset += 1;

        let stream_id = u32::from_be_bytes([
            action_buf[offset],
            action_buf[offset + 1],
            action_buf[offset + 2],
            action_buf[offset + 3],
        ]);
        offset += 4;

        let data_len = u16::from_be_bytes([action_buf[offset], action_buf[offset + 1]]) as usize;
        offset += 2;

        if offset + data_len > action_buf.len() {
            crate::ffi::ios_log(&format!(
                "Rust router action callback parse truncated offset={} len={} data_len={}",
                offset,
                action_buf.len(),
                data_len
            ));
            break;
        }

        if action_type == 0 {
            // A new stream id is live again; any prior close marker is stale.
            closed_streams.remove(&stream_id);
        }

        if action_type == 2 {
            // Only suppress exact duplicate CloseStream callbacks. Do not consult
            // router_has_stream here: process_gateway_close can legitimately
            // remove the local mapping before emitting the close action. Dropping
            // that first close leaks gateway streams and causes browser loads to
            // churn/stall with many active flows.
            if closed_streams.contains(&stream_id) {
                summary.suppressed_close += 1;
                offset += data_len;
                continue;
            }
            closed_streams.insert(stream_id);
        }

        let data_ptr = if data_len == 0 {
            std::ptr::null()
        } else {
            action_buf[offset..].as_ptr()
        };
        callback.dispatch(action_type, stream_id, data_ptr, data_len);
        summary.total += 1;
        summary.payload_bytes += data_len as u64;
        match action_type {
            0 => summary.open += 1,
            1 => summary.send += 1,
            2 => summary.close += 1,
            _ => summary.unknown += 1,
        }
        offset += data_len;
    }
    if summary.total > 0 || summary.suppressed_close > 0 {
        crate::ffi::ios_log(&format!(
            "Rust router action callback dispatched actions={} open={} send={} close={} suppressed_close={} unknown={} payload_bytes={} action_bytes={}",
            summary.total,
            summary.open,
            summary.send,
            summary.close,
            summary.suppressed_close,
            summary.unknown,
            summary.payload_bytes,
            action_buf.len()
        ));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_write_frame_prepends_ipv4_utun_header() {
        let utun = IosUtun::new(-1);
        let packet = [0x45, 0x00, 0x00, 0x14];
        let frame = utun.build_write_frame(&packet).unwrap();
        assert_eq!(&frame[..4], &[0, 0, 0, libc::AF_INET as u8]);
        assert_eq!(&frame[4..], &packet);
    }

    #[test]
    fn build_write_frame_prepends_ipv6_utun_header() {
        let utun = IosUtun::new(-1);
        let packet = [0x60, 0x00, 0x00, 0x00];
        let frame = utun.build_write_frame(&packet).unwrap();
        assert_eq!(&frame[..4], &[0, 0, 0, libc::AF_INET6 as u8]);
        assert_eq!(&frame[4..], &packet);
    }

    #[test]
    fn build_write_frame_rejects_unknown_ip_version() {
        let utun = IosUtun::new(-1);
        let err = utun.build_write_frame(&[0x10]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn dns_query_packet(name: &str) -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&0x1234u16.to_be_bytes());
        dns.extend_from_slice(&0x0100u16.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());

        let udp_len = 8 + dns.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 122, 0, 9]);
        packet[16..20].copy_from_slice(&IOS_DNS_ADDR);
        let ip_sum = ipv4_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        packet[20..22].copy_from_slice(&55555u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(&dns);
        let udp_sum = udp_ipv4_checksum(&packet[12..16], &packet[16..20], &packet[20..]);
        packet[26..28].copy_from_slice(&udp_sum.to_be_bytes());
        packet
    }

    #[test]
    fn dns_response_maps_vault_ztlp_to_vault_vip() {
        let response =
            build_ios_dns_response(&dns_query_packet("vault.techrockstars.ztlp")).unwrap();
        assert_eq!(&response[12..16], &IOS_DNS_ADDR);
        assert_eq!(&response[16..20], &[10, 122, 0, 9]);
        assert_eq!(u16::from_be_bytes([response[20], response[21]]), 53);
        assert_eq!(u16::from_be_bytes([response[22], response[23]]), 55555);
        let dns = &response[28..];
        assert_eq!(&dns[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([dns[2], dns[3]]) & 0x000f, 0);
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1);
        assert_eq!(&dns[dns.len() - 4..], &[10, 122, 0, 4]);
    }

    #[test]
    fn dns_response_maps_http_and_default_ztlp() {
        let http = build_ios_dns_response(&dns_query_packet("http.ztlp")).unwrap();
        assert_eq!(&http[http.len() - 4..], &[10, 122, 0, 3]);
        let other = build_ios_dns_response(&dns_query_packet("app.ztlp")).unwrap();
        assert_eq!(&other[other.len() - 4..], &[10, 122, 0, 2]);
    }

    #[test]
    fn dns_response_returns_nxdomain_for_non_ztlp() {
        let response = build_ios_dns_response(&dns_query_packet("example.com")).unwrap();
        let dns = &response[28..];
        assert_eq!(u16::from_be_bytes([dns[2], dns[3]]) & 0x000f, 3);
        assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 0);
    }

    #[test]
    fn engine_rejects_negative_fd() {
        match IosTunnelEngine::start(-1) {
            Ok(_) => panic!("negative fd should be rejected"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
        }
    }
}
