//! Integration test: fake-NS server + sync NS resolver + RelayPool FFI
//!
//! Spins up a local UDP server that speaks the ZTLP-NS wire protocol,
//! then exercises the full NE code path:
//!
//!   ztlp_ns_resolve_sync → ZtlpNsResult
//!   ztlp_ns_resolve_relays_sync → ZtlpRelayList
//!   ztlp_relay_pool_update_from_ns → pool
//!   ztlp_relay_pool_select → best relay address
//!
//! All testable on Linux, no tokio, no Xcode needed.

use std::ffi::{CString, CStr};
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ztlp_proto::ffi::*;
use ztlp_proto::ns_cbor;

// ── CBOR helpers ───────────────────────────────────────────────────────

/// Build a CBOR text string header + payload for a given string.
fn cbor_text(s: &str) -> Vec<u8> {
    let len = s.len();
    let mut out = Vec::with_capacity(1 + len);
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len < 256 {
        out.push(0x78);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        panic!("string too long for test CBOR");
    }
    out.extend_from_slice(s.as_bytes());
    out
}

/// Build a CBOR map from key-value string pairs.
fn cbor_map(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    if entries.len() < 24 {
        out.push(0xA0 | entries.len() as u8);
    } else {
        panic!("too many entries for test CBOR map");
    }
    for (k, v) in entries {
        out.extend_from_slice(&cbor_text(k));
        out.extend_from_slice(&cbor_text(v));
    }
    out
}

/// Build a CBOR map with mixed string/uint values.
fn cbor_map_mixed(entries: &[(&str, Option<&str>, Option<u64>)]) -> Vec<u8> {
    let mut out = Vec::new();
    if entries.len() < 24 {
        out.push(0xA0 | entries.len() as u8);
    } else {
        panic!("too many entries for test CBOR map");
    }
    for (k, str_val, uint_val) in entries {
        out.extend_from_slice(&cbor_text(k));
        if let Some(s) = str_val {
            out.extend_from_slice(&cbor_text(s));
        } else if let Some(n) = uint_val {
            if *n < 24 {
                out.push(*n as u8);
            } else if *n < 256 {
                out.push(0x18);
                out.push(*n as u8);
            } else {
                out.push(0x19);
                out.extend_from_slice(&(*n as u16).to_be_bytes());
            }
        } else {
            out.extend_from_slice(&cbor_text("")); // fallback
        }
    }
    out
}

// ── NS wire protocol ──────────────────────────────────────────────────

/// Build a ZTLP-NS FOUND response for a given record type.
fn ns_found_response(name: &str, record_type: u8, cbor_data: &[u8]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let data_len = cbor_data.len() as u32;
    let mut resp = Vec::with_capacity(1 + 1 + 2 + name_bytes.len() + 4 + cbor_data.len());
    resp.push(0x02); // FOUND
    resp.push(record_type);
    resp.extend_from_slice(&name_len.to_be_bytes());
    resp.extend_from_slice(name_bytes);
    resp.extend_from_slice(&data_len.to_be_bytes());
    resp.extend_from_slice(cbor_data);
    resp
}

/// Build a NOT_FOUND response.
fn ns_not_found_response() -> Vec<u8> {
    vec![0x03]
}

/// Build a REVOKED response.
fn ns_revoked_response() -> Vec<u8> {
    vec![0x04]
}

// ── Fake NS server ────────────────────────────────────────────────────

struct FakeNs {
    addr: std::net::SocketAddr,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeNs {
    fn start<F>(responder: F) -> Self
    where
        F: Fn(&str, u8) -> Vec<u8> + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind fake NS");
        let addr = socket.local_addr().expect("get local addr");
        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let responder = Arc::new(responder);

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while running_clone.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        let data = &buf[..len];
                        if data.len() < 4 || data[0] != 0x01 {
                            continue;
                        }
                        let name_len = u16::from_be_bytes([data[1], data[2]]) as usize;
                        if data.len() < 3 + name_len + 1 {
                            continue;
                        }
                        let name = String::from_utf8_lossy(&data[3..3 + name_len]).to_string();
                        let record_type = data[3 + name_len];
                        let resp = responder(&name, record_type);
                        let _ = socket.send_to(&resp, src);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });

        Self { addr, running, handle: Some(handle) }
    }
}

impl Drop for FakeNs {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn test_ns_resolve_sync_with_fake_server() {
    let cbor = cbor_map(&[("address", "10.0.0.1:443")]);
    let response = ns_found_response("beta.techrockstars", 0x02, &cbor);

    let server = FakeNs::start(move |_name, _rtype| {
        response.clone()
    });

    let ns_addr = CString::new(server.addr.to_string()).unwrap();
    let name = CString::new("beta.techrockstars").unwrap();

    let result = ztlp_ns_resolve_sync(ns_addr.as_ptr(), name.as_ptr(), 0x02, 2000);
    assert!(!result.is_null());

    let r = unsafe { &*result };
    assert!(r.error.is_null(), "NS query should succeed");
    assert_eq!(r.count, 1);

    // Extract address from CBOR data
    if !r.record_data.is_null() && !r.record_data_lens.is_null() {
        let data_ptrs = unsafe { std::slice::from_raw_parts(r.record_data, r.count) };
        let lens = unsafe { std::slice::from_raw_parts(r.record_data_lens, r.count) };
        if !data_ptrs[0].is_null() && lens[0] > 0 {
            let data = unsafe { std::slice::from_raw_parts(data_ptrs[0], lens[0]) };
            let addr = ns_cbor::cbor_extract_string(data, "address");
            assert_eq!(addr, Some("10.0.0.1:443".to_string()));
        }
    }

    ztlp_ns_result_free(result as *mut ZtlpNsResult);
}

#[test]
fn test_ns_resolve_relays_sync_with_fake_server() {
    let cbor = cbor_map_mixed(&[
        ("address", Some("34.219.64.205:443"), None),
        ("region", Some("us-west-2"), None),
        ("latency_ms", None, Some(25)),
        ("load_pct", None, Some(30)),
        ("active_connections", None, Some(5)),
        ("health", Some("healthy"), None),
    ]);
    let response = ns_found_response("techrockstars", 0x03, &cbor);

    let server = FakeNs::start(move |_name, _rtype| {
        response.clone()
    });

    let ns_addr = CString::new(server.addr.to_string()).unwrap();
    let name = CString::new("techrockstars").unwrap();

    let result = ztlp_ns_resolve_relays_sync(ns_addr.as_ptr(), name.as_ptr(), 2000);
    assert!(!result.is_null());

    let r = unsafe { &*result };
    assert!(r.error.is_null(), "relay query should succeed");
    assert_eq!(r.count, 1);

    // Check relay fields
    let addrs = unsafe { std::slice::from_raw_parts(r.addresses, r.count) };
    assert!(!addrs[0].is_null());
    let addr_str = unsafe { CStr::from_ptr(addrs[0]) }.to_string_lossy().to_string();
    assert_eq!(addr_str, "34.219.64.205:443");

    let regions = unsafe { std::slice::from_raw_parts(r.regions, r.count) };
    let region_str = unsafe { CStr::from_ptr(regions[0]) }.to_string_lossy().to_string();
    assert_eq!(region_str, "us-west-2");

    let latencies = unsafe { std::slice::from_raw_parts(r.latency_ms, r.count) };
    assert_eq!(latencies[0], 25);

    let loads = unsafe { std::slice::from_raw_parts(r.load_pct, r.count) };
    assert_eq!(loads[0], 30);

    let conns = unsafe { std::slice::from_raw_parts(r.active_connections, r.count) };
    assert_eq!(conns[0], 5);

    let health = unsafe { std::slice::from_raw_parts(r.health, r.count) };
    assert_eq!(health[0], 0); // Healthy

    ztlp_relay_list_free(result);
}

#[test]
fn test_full_ne_relay_pipeline() {
    // Full NE pipeline: NS resolve → RelayList → Pool update → Select best
    let cbor = cbor_map_mixed(&[
        ("address", Some("34.219.64.205:443"), None),
        ("region", Some("us-west-2"), None),
        ("latency_ms", None, Some(15)),
        ("load_pct", None, Some(20)),
        ("active_connections", None, Some(3)),
        ("health", Some("healthy"), None),
    ]);
    let response = ns_found_response("techrockstars", 0x03, &cbor);

    let server = FakeNs::start(move |_name, _rtype| {
        response.clone()
    });

    // Create relay pool with us-west-2 region preference
    let region = CString::new("us-west-2").unwrap();
    let pool = ztlp_relay_pool_new(region.as_ptr());
    assert!(!pool.is_null());

    // Resolve relays from NS
    let ns_addr = CString::new(server.addr.to_string()).unwrap();
    let name = CString::new("techrockstars").unwrap();

    let relay_list = ztlp_ns_resolve_relays_sync(ns_addr.as_ptr(), name.as_ptr(), 2000);
    assert!(!relay_list.is_null());
    let rl = unsafe { &*relay_list };
    let err_msg = if !rl.error.is_null() {
        unsafe { CStr::from_ptr(rl.error) }.to_string_lossy().to_string()
    } else {
        "none".to_string()
    };
    assert!(rl.error.is_null(), "relay list has error: {}", err_msg);
    assert!(rl.count >= 1, "relay list count = {}", rl.count);

    // Update pool with relay data
    let rc = ztlp_relay_pool_update_from_ns(pool, relay_list);
    assert_eq!(rc, 0);

    // Pool should have at least 1 relay
    let total = ztlp_relay_pool_total_count(pool);
    let healthy = ztlp_relay_pool_healthy_count(pool);
    assert!(total >= 1, "pool should have relays after update (total={}, healthy={}, list_count={})", total, healthy, rl.count);

    // Select best
    let addr = ztlp_relay_pool_select(pool);
    assert!(!addr.is_null());
    let addr_str = unsafe { CStr::from_ptr(addr) }.to_string_lossy().to_string();
    assert!(
        addr_str.contains("34.219.64.205"),
        "Expected us-west-2 relay, got: {}",
        addr_str
    );
    let _ = unsafe { CString::from_raw(addr as *mut i8) };

    // Report success
    let relay_addr = CString::new("34.219.64.205:443").unwrap();
    ztlp_relay_pool_report_success(pool, relay_addr.as_ptr(), 15);

    // Verify healthy count
    assert!(ztlp_relay_pool_healthy_count(pool) >= 1);

    ztlp_relay_list_free(relay_list);
    ztlp_relay_pool_free(pool);
}

#[test]
fn test_ns_resolve_sync_not_found() {
    let server = FakeNs::start(move |_name, _rtype| {
        ns_not_found_response()
    });

    let ns_addr = CString::new(server.addr.to_string()).unwrap();
    let name = CString::new("nonexistent").unwrap();

    let result = ztlp_ns_resolve_sync(ns_addr.as_ptr(), name.as_ptr(), 0x02, 2000);
    assert!(!result.is_null());

    let r = unsafe { &*result };
    assert!(r.error.is_null());
    assert_eq!(r.count, 0);

    ztlp_ns_result_free(result as *mut ZtlpNsResult);
}

#[test]
fn test_ns_resolve_sync_revoked() {
    let server = FakeNs::start(move |_name, _rtype| {
        ns_revoked_response()
    });

    let ns_addr = CString::new(server.addr.to_string()).unwrap();
    let name = CString::new("revoked-key").unwrap();

    let result = ztlp_ns_resolve_sync(ns_addr.as_ptr(), name.as_ptr(), 0x01, 2000);
    assert!(!result.is_null());

    let r = unsafe { &*result };
    assert!(r.error.is_null());
    assert_eq!(r.count, 0);

    ztlp_ns_result_free(result as *mut ZtlpNsResult);
}

#[test]
fn test_relay_pool_failover_pipeline() {
    // Test: primary relay, then report failure
    let cbor = cbor_map_mixed(&[
        ("address", Some("10.0.0.1:443"), None),
        ("region", Some("us-west-2"), None),
        ("latency_ms", None, Some(10)),
        ("load_pct", None, Some(10)),
        ("active_connections", None, Some(1)),
        ("health", Some("healthy"), None),
    ]);
    let response = ns_found_response("test-zone", 0x03, &cbor);

    let server = FakeNs::start(move |_name, _rtype| {
        response.clone()
    });

    let region = CString::new("us-west-2").unwrap();
    let pool = ztlp_relay_pool_new(region.as_ptr());

    let ns_addr = CString::new(server.addr.to_string()).unwrap();
    let name = CString::new("test-zone").unwrap();
    let relay_list = ztlp_ns_resolve_relays_sync(ns_addr.as_ptr(), name.as_ptr(), 2000);
    assert!(!relay_list.is_null());
    let rc = ztlp_relay_pool_update_from_ns(pool, relay_list);
    assert_eq!(rc, 0);

    // Primary should be selected
    let addr = ztlp_relay_pool_select(pool);
    assert!(!addr.is_null());
    let addr_str = unsafe { CStr::from_ptr(addr) }.to_string_lossy().to_string();
    assert!(addr_str.contains("10.0.0.1"));
    let _ = unsafe { CString::from_raw(addr as *mut i8) };

    // Report failure on primary
    let primary_addr = CString::new("10.0.0.1:443").unwrap();
    ztlp_relay_pool_report_failure(pool, primary_addr.as_ptr());

    // Relay should still be in the pool
    let total = ztlp_relay_pool_total_count(pool);
    assert_eq!(total, 1, "relay should still be in pool after failure");

    ztlp_relay_list_free(relay_list);
    ztlp_relay_pool_free(pool);
}