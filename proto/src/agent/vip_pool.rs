//! Virtual IP allocator — maps ZTLP names to loopback addresses.
//!
//! Allocates IPs from a configurable pool (default: `127.100.0.0/16`)
//! in the loopback range. Each ZTLP name gets a unique virtual IP that
//! the TCP proxy listens on. IPs are reclaimed when TTL expires and no
//! active tunnels exist.
//!
//! ## Why loopback VIPs?
//!
//! - No root/CAP_NET_ADMIN required (unlike TUN/TAP)
//! - Works with any TCP application transparently
//! - 127.0.0.0/8 is fully routable on loopback on Linux and macOS
//! - 127.100.0.0/16 avoids conflicts with 127.0.0.1

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A virtual IP allocation entry.
#[derive(Debug, Clone)]
pub struct VipEntry {
    /// The allocated virtual IP.
    pub ip: Ipv4Addr,
    /// The ZTLP name this IP maps to.
    pub ztlp_name: String,
    /// The resolved peer endpoint (from NS SVC record).
    pub peer_addr: Option<std::net::SocketAddr>,
    /// The resolved peer's NodeID (from NS KEY record), when available.
    ///
    /// Needed for the automatic VIP tunnel dialer's CLIENT_ROUTE frame:
    /// a shared relay's fallback-by-NodeID lookup (used when the plain
    /// service-name lookup misses — e.g. a gateway registered under a
    /// zone key like "gw:demo.spongebob.ztlp" rather than the bare
    /// service name) requires the PEER's NodeID, not the client's own.
    /// Without caching this alongside `peer_addr`, every VIP-proxied
    /// connection after the first DNS resolution had no NodeID to fall
    /// back to and its CLIENT_ROUTE was rejected by the relay — found
    /// live 2026-08-30 while debugging why the automatic tunnel dial
    /// still failed even after fixing NS NodeID resolution itself.
    pub peer_node_id: Option<crate::identity::NodeId>,
    /// When this allocation was created.
    pub created_at: Instant,
    /// When this allocation expires (based on NS record TTL).
    pub expires_at: Option<Instant>,
    /// Number of active TCP connections using this VIP.
    pub active_connections: u32,
}

/// Virtual IP pool manager.
///
/// Allocates IPs from a configurable CIDR range in the loopback space.
/// Thread-safe when wrapped in a lock (the daemon holds `Arc<Mutex<VipPool>>`).
#[derive(Debug)]
pub struct VipPool {
    /// Base IP address of the pool (e.g., 127.100.0.0).
    base: u32,
    /// Number of usable addresses in the pool.
    pool_size: u32,
    /// Next candidate offset to try (round-robin allocation).
    next_offset: u32,
    /// Map of ZTLP name → VIP entry.
    name_to_vip: HashMap<String, VipEntry>,
    /// Map of IP → ZTLP name (reverse lookup).
    ip_to_name: HashMap<Ipv4Addr, String>,
}

impl VipPool {
    /// Create a new VIP pool from a CIDR string (e.g., "127.100.0.0/16").
    ///
    /// The first address (.0) and last address (.255 for /24, broadcast)
    /// are reserved. Actual usable range is base+1 to base+size-2.
    pub fn new(cidr: &str) -> Result<Self, String> {
        let (base, prefix_len) = parse_cidr(cidr)?;

        if prefix_len > 30 {
            return Err(format!(
                "prefix length /{} too long (need at least /30)",
                prefix_len
            ));
        }

        let host_bits = 32 - prefix_len;
        let total_addresses = 1u32 << host_bits;
        // Reserve .0 (network) and last (broadcast) — usable = total - 2
        let pool_size = total_addresses.saturating_sub(2);

        if pool_size == 0 {
            return Err("pool too small (need at least 2 addresses)".to_string());
        }

        Ok(Self {
            base,
            pool_size,
            next_offset: 0,
            name_to_vip: HashMap::new(),
            ip_to_name: HashMap::new(),
        })
    }

    /// Allocate (or return existing) a VIP for a ZTLP name.
    ///
    /// If the name already has a VIP, returns it. Otherwise allocates
    /// a new one from the pool. Returns `None` if the pool is exhausted.
    pub fn allocate(&mut self, ztlp_name: &str, ttl: Option<Duration>) -> Option<Ipv4Addr> {
        // Return existing allocation
        if let Some(entry) = self.name_to_vip.get(ztlp_name) {
            return Some(entry.ip);
        }

        // Find a free IP (scan up to pool_size attempts)
        for _ in 0..self.pool_size {
            let offset = self.next_offset;
            self.next_offset = (self.next_offset + 1) % self.pool_size;

            // +1 to skip .0 (network address)
            let ip_u32 = self.base + offset + 1;
            let ip = Ipv4Addr::from(ip_u32);

            if !self.ip_to_name.contains_key(&ip) {
                let name = ztlp_name.to_lowercase();
                let now = Instant::now();

                let entry = VipEntry {
                    ip,
                    ztlp_name: name.clone(),
                    peer_addr: None,
                    peer_node_id: None,
                    created_at: now,
                    expires_at: ttl.map(|d| now + d),
                    active_connections: 0,
                };

                self.name_to_vip.insert(name.clone(), entry);
                self.ip_to_name.insert(ip, name);
                return Some(ip);
            }
        }

        None // Pool exhausted
    }

    /// Look up the ZTLP name for a virtual IP.
    pub fn lookup_ip(&self, ip: &Ipv4Addr) -> Option<&str> {
        self.ip_to_name.get(ip).map(|s| s.as_str())
    }

    /// Look up the VIP entry for a ZTLP name.
    pub fn lookup_name(&self, ztlp_name: &str) -> Option<&VipEntry> {
        self.name_to_vip.get(&ztlp_name.to_lowercase())
    }

    /// Get a mutable reference to a VIP entry by name.
    pub fn lookup_name_mut(&mut self, ztlp_name: &str) -> Option<&mut VipEntry> {
        self.name_to_vip.get_mut(&ztlp_name.to_lowercase())
    }

    /// Look up the VIP entry for an IP address.
    pub fn lookup_ip_entry(&self, ip: &Ipv4Addr) -> Option<&VipEntry> {
        let name = self.ip_to_name.get(ip)?;
        self.name_to_vip.get(name)
    }

    /// Release a VIP allocation by name.
    pub fn release(&mut self, ztlp_name: &str) -> bool {
        let name = ztlp_name.to_lowercase();
        if let Some(entry) = self.name_to_vip.remove(&name) {
            self.ip_to_name.remove(&entry.ip);
            true
        } else {
            false
        }
    }

    /// Release expired VIP allocations that have no active connections.
    ///
    /// Returns the number of entries released.
    pub fn gc_expired(&mut self) -> usize {
        let now = Instant::now();
        let expired: Vec<String> = self
            .name_to_vip
            .iter()
            .filter(|(_, entry)| {
                entry.active_connections == 0 && entry.expires_at.is_some_and(|exp| now >= exp)
            })
            .map(|(name, _)| name.clone())
            .collect();

        let count = expired.len();
        for name in expired {
            if let Some(entry) = self.name_to_vip.remove(&name) {
                self.ip_to_name.remove(&entry.ip);
            }
        }
        count
    }

    /// Increment the active connection count for a VIP.
    pub fn inc_connections(&mut self, ip: &Ipv4Addr) {
        if let Some(name) = self.ip_to_name.get(ip).cloned() {
            if let Some(entry) = self.name_to_vip.get_mut(&name) {
                entry.active_connections += 1;
            }
        }
    }

    /// Decrement the active connection count for a VIP.
    pub fn dec_connections(&mut self, ip: &Ipv4Addr) {
        if let Some(name) = self.ip_to_name.get(ip).cloned() {
            if let Some(entry) = self.name_to_vip.get_mut(&name) {
                entry.active_connections = entry.active_connections.saturating_sub(1);
            }
        }
    }

    /// Number of allocated VIPs.
    pub fn allocated_count(&self) -> usize {
        self.name_to_vip.len()
    }

    /// Total pool capacity.
    pub fn capacity(&self) -> u32 {
        self.pool_size
    }

    /// Iterate over all allocations.
    pub fn entries(&self) -> impl Iterator<Item = &VipEntry> {
        self.name_to_vip.values()
    }

    // ─── persistence across agent restarts ──────────────────────────────
    //
    // Allocations used to live only in memory, so after an agent restart
    // 127.100.0.x had no listener until something did DNS again. Anything
    // that had cached the A record (browsers, `curl --resolve`, long-lived
    // apps) got ECONNREFUSED. We persist just name→ip; peer_addr / node_id
    // are deliberately NOT persisted and are re-resolved lazily by the
    // connection handler (it already does `ns_resolve` when peer_addr is
    // None).

    /// Save the current name→ip map to `path` (JSON, mode 0600).
    pub fn save_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        let state = PersistedVipState {
            cidr: self.cidr_string(),
            entries: self
                .name_to_vip
                .values()
                .map(|e| PersistedVipEntry {
                    name: e.ztlp_name.clone(),
                    ip: e.ip,
                })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&state).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Restore allocations saved by [`save_to`]. Returns how many were
    /// restored. Missing / unparseable files and files written for a
    /// different CIDR are not errors (0 restored; a stale-CIDR file is
    /// removed). Restored entries have no TTL (sticky until a fresh DNS
    /// resolve refreshes them) and no peer info.
    pub fn restore_from(&mut self, path: &std::path::Path) -> std::io::Result<usize> {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let state: PersistedVipState = match serde_json::from_str(&raw) {
            Ok(s) => s,
            Err(_) => return Ok(0),
        };
        if state.cidr != self.cidr_string() {
            let _ = std::fs::remove_file(path);
            return Ok(0);
        }
        let mut restored = 0;
        for pe in state.entries {
            let name = pe.name.to_lowercase();
            if self.name_to_vip.contains_key(&name) || self.ip_to_name.contains_key(&pe.ip) {
                continue;
            }
            let ip_u32 = u32::from(pe.ip);
            // must be inside the usable range (base+1 ..= base+pool_size)
            if ip_u32 <= self.base || ip_u32 > self.base + self.pool_size {
                continue;
            }
            self.name_to_vip.insert(
                name.clone(),
                VipEntry {
                    ip: pe.ip,
                    ztlp_name: name.clone(),
                    peer_addr: None,
                    peer_node_id: None,
                    created_at: Instant::now(),
                    expires_at: None,
                    active_connections: 0,
                },
            );
            self.ip_to_name.insert(pe.ip, name);
            restored += 1;
        }
        Ok(restored)
    }

    fn cidr_string(&self) -> String {
        let prefix_len = 32 - (self.pool_size + 2).trailing_zeros();
        format!("{}/{}", Ipv4Addr::from(self.base), prefix_len)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedVipState {
    cidr: String,
    entries: Vec<PersistedVipEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedVipEntry {
    name: String,
    ip: Ipv4Addr,
}

/// Parse a CIDR string like "127.100.0.0/16" into (base_u32, prefix_len).
fn parse_cidr(cidr: &str) -> Result<(u32, u32), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR: '{}' (expected a.b.c.d/N)", cidr));
    }

    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|e| format!("invalid IP in CIDR '{}': {}", cidr, e))?;

    let prefix_len: u32 = parts[1]
        .parse()
        .map_err(|e| format!("invalid prefix length in '{}': {}", cidr, e))?;

    if prefix_len > 32 {
        return Err(format!("prefix length {} exceeds 32", prefix_len));
    }

    let base = u32::from(ip);
    // Mask off host bits to get the network address
    let mask = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let masked_base = base & mask;

    if masked_base != base {
        return Err(format!(
            "IP {} has host bits set for /{} (network address is {})",
            ip,
            prefix_len,
            Ipv4Addr::from(masked_base)
        ));
    }

    Ok((base, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default_pool() {
        let pool = VipPool::new("127.100.0.0/16").unwrap();
        assert_eq!(pool.capacity(), 65534); // 2^16 - 2
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_new_small_pool() {
        let pool = VipPool::new("127.100.0.0/24").unwrap();
        assert_eq!(pool.capacity(), 254); // 2^8 - 2
    }

    #[test]
    fn test_allocate_and_lookup() {
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();

        let ip1 = pool.allocate("server.corp.ztlp", None).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(127, 100, 0, 1));
        assert_eq!(pool.allocated_count(), 1);

        // Same name returns same IP
        let ip1b = pool.allocate("server.corp.ztlp", None).unwrap();
        assert_eq!(ip1, ip1b);
        assert_eq!(pool.allocated_count(), 1);

        // Different name gets different IP
        let ip2 = pool.allocate("db.corp.ztlp", None).unwrap();
        assert_eq!(ip2, Ipv4Addr::new(127, 100, 0, 2));
        assert_eq!(pool.allocated_count(), 2);

        // Reverse lookup
        assert_eq!(pool.lookup_ip(&ip1), Some("server.corp.ztlp"));
        assert_eq!(pool.lookup_ip(&ip2), Some("db.corp.ztlp"));

        // Forward lookup
        assert!(pool.lookup_name("server.corp.ztlp").is_some());
        assert_eq!(pool.lookup_name("server.corp.ztlp").unwrap().ip, ip1);
    }

    #[test]
    fn test_case_insensitive() {
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        let ip1 = pool.allocate("Server.Corp.ZTLP", None).unwrap();
        let ip2 = pool.allocate("server.corp.ztlp", None).unwrap();
        assert_eq!(ip1, ip2);
        assert_eq!(pool.allocated_count(), 1);
    }

    #[test]
    fn test_release() {
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        let ip = pool.allocate("server.corp.ztlp", None).unwrap();
        assert_eq!(pool.allocated_count(), 1);

        assert!(pool.release("server.corp.ztlp"));
        assert_eq!(pool.allocated_count(), 0);
        assert_eq!(pool.lookup_ip(&ip), None);

        // Release non-existent returns false
        assert!(!pool.release("nonexistent.ztlp"));
    }

    #[test]
    fn test_pool_exhaustion() {
        // Tiny pool: /30 = 4 addresses, 2 usable
        let mut pool = VipPool::new("127.100.0.0/30").unwrap();
        assert_eq!(pool.capacity(), 2);

        let ip1 = pool.allocate("a.ztlp", None);
        assert!(ip1.is_some());

        let ip2 = pool.allocate("b.ztlp", None);
        assert!(ip2.is_some());

        // Pool full
        let ip3 = pool.allocate("c.ztlp", None);
        assert!(ip3.is_none());
    }

    #[test]
    fn test_gc_expired() {
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();

        // Allocate with very short TTL
        pool.allocate("old.ztlp", Some(Duration::from_millis(0)));
        pool.allocate("fresh.ztlp", Some(Duration::from_secs(3600)));
        pool.allocate("no-ttl.ztlp", None);

        assert_eq!(pool.allocated_count(), 3);

        // Small sleep to ensure the 0ms TTL has expired
        std::thread::sleep(Duration::from_millis(1));

        let freed = pool.gc_expired();
        assert_eq!(freed, 1); // only "old.ztlp" expired
        assert_eq!(pool.allocated_count(), 2);
        assert!(pool.lookup_name("fresh.ztlp").is_some());
        assert!(pool.lookup_name("no-ttl.ztlp").is_some());
        assert!(pool.lookup_name("old.ztlp").is_none());
    }

    #[test]
    fn test_gc_skips_active_connections() {
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        let ip = pool
            .allocate("busy.ztlp", Some(Duration::from_millis(0)))
            .unwrap();
        pool.inc_connections(&ip);

        std::thread::sleep(Duration::from_millis(1));

        // Shouldn't gc because there are active connections
        let freed = pool.gc_expired();
        assert_eq!(freed, 0);
        assert_eq!(pool.allocated_count(), 1);

        // Drop connection, now it can be gc'd
        pool.dec_connections(&ip);
        let freed = pool.gc_expired();
        assert_eq!(freed, 1);
    }

    #[test]
    fn test_connection_counting() {
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        let ip = pool.allocate("server.ztlp", None).unwrap();

        assert_eq!(pool.lookup_ip_entry(&ip).unwrap().active_connections, 0);

        pool.inc_connections(&ip);
        pool.inc_connections(&ip);
        assert_eq!(pool.lookup_ip_entry(&ip).unwrap().active_connections, 2);

        pool.dec_connections(&ip);
        assert_eq!(pool.lookup_ip_entry(&ip).unwrap().active_connections, 1);

        // Saturating sub
        pool.dec_connections(&ip);
        pool.dec_connections(&ip);
        assert_eq!(pool.lookup_ip_entry(&ip).unwrap().active_connections, 0);
    }

    #[test]
    fn test_parse_cidr_valid() {
        let (base, prefix) = parse_cidr("127.100.0.0/16").unwrap();
        assert_eq!(base, u32::from(Ipv4Addr::new(127, 100, 0, 0)));
        assert_eq!(prefix, 16);
    }

    #[test]
    fn test_parse_cidr_host_bits_set() {
        let result = parse_cidr("127.100.0.1/16");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("not-an-ip/16").is_err());
        assert!(parse_cidr("127.0.0.0").is_err()); // no /prefix
        assert!(parse_cidr("127.0.0.0/33").is_err()); // prefix too big
    }

    #[test]
    fn test_entries_iterator() {
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        pool.allocate("a.ztlp", None);
        pool.allocate("b.ztlp", None);
        pool.allocate("c.ztlp", None);

        let names: Vec<&str> = pool.entries().map(|e| e.ztlp_name.as_str()).collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"a.ztlp"));
        assert!(names.contains(&"b.ztlp"));
        assert!(names.contains(&"c.ztlp"));
    }

    #[test]
    fn test_reuse_after_release() {
        let mut pool = VipPool::new("127.100.0.0/30").unwrap(); // 2 usable
        let ip1 = pool.allocate("a.ztlp", None).unwrap();
        let _ip2 = pool.allocate("b.ztlp", None).unwrap();

        // Pool full
        assert!(pool.allocate("c.ztlp", None).is_none());

        // Release one
        pool.release("a.ztlp");

        // Now we can allocate again (gets the freed IP)
        let ip3 = pool.allocate("c.ztlp", None).unwrap();
        assert_eq!(ip3, ip1); // reused the released IP
    }

    // ── persistence across agent restarts ──────────────────────────────
    fn tmp_state_file(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ztlp-vip-state-{}-{}-{}.json",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn save_then_restore_gives_same_ip_to_same_name_in_a_fresh_pool() {
        let path = tmp_state_file("roundtrip");
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        let ip_dash = pool
            .allocate("demo-dashboard.defcon.ztlp", Some(Duration::from_secs(300)))
            .unwrap();
        let ip_api = pool
            .allocate("api.defcon.ztlp", Some(Duration::from_secs(300)))
            .unwrap();
        pool.save_to(&path).unwrap();

        // "agent restart": brand new pool, restore from disk
        let mut fresh = VipPool::new("127.100.0.0/24").unwrap();
        let restored = fresh.restore_from(&path).unwrap();
        assert_eq!(restored, 2);
        assert_eq!(
            fresh.lookup_name("demo-dashboard.defcon.ztlp").unwrap().ip,
            ip_dash
        );
        assert_eq!(fresh.lookup_name("api.defcon.ztlp").unwrap().ip, ip_api);
        // listeners are what matters: the proxy iterates entries()
        assert_eq!(fresh.entries().count(), 2);
        // peer info must be re-resolved lazily, never trusted from disk
        assert!(fresh
            .lookup_name("api.defcon.ztlp")
            .unwrap()
            .peer_addr
            .is_none());
        // a later DNS resolve for the same name keeps its IP (browser cache stays valid)
        assert_eq!(
            fresh.allocate("demo-dashboard.defcon.ztlp", None).unwrap(),
            ip_dash
        );
        // and a brand-new name does not collide with a restored one
        let ip_new = fresh.allocate("new.defcon.ztlp", None).unwrap();
        assert_ne!(ip_new, ip_dash);
        assert_ne!(ip_new, ip_api);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restored_entries_are_not_garbage_collected() {
        let path = tmp_state_file("nogc");
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        pool.allocate("a.z.ztlp", Some(Duration::from_millis(1)))
            .unwrap();
        pool.save_to(&path).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let mut fresh = VipPool::new("127.100.0.0/24").unwrap();
        fresh.restore_from(&path).unwrap();
        assert_eq!(
            fresh.gc_expired(),
            0,
            "restored allocations must be sticky until re-resolved"
        );
        assert!(fresh.lookup_name("a.z.ztlp").is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restore_discards_state_written_for_a_different_cidr() {
        let path = tmp_state_file("cidr");
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        pool.allocate("a.z.ztlp", None).unwrap();
        pool.save_to(&path).unwrap();
        let mut other = VipPool::new("127.200.0.0/24").unwrap();
        assert_eq!(other.restore_from(&path).unwrap(), 0);
        assert_eq!(other.allocated_count(), 0);
        assert!(
            !path.exists(),
            "stale file for another range must be removed"
        );
    }

    #[test]
    fn restore_tolerates_missing_and_garbage_files() {
        let path = tmp_state_file("garbage");
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        assert_eq!(
            pool.restore_from(&path).unwrap(),
            0,
            "missing file is not an error"
        );
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(
            pool.restore_from(&path).unwrap(),
            0,
            "garbage file is not an error"
        );
        assert_eq!(pool.allocated_count(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_writes_only_name_and_ip_with_owner_only_mode() {
        let path = tmp_state_file("shape");
        let mut pool = VipPool::new("127.100.0.0/24").unwrap();
        pool.allocate("a.z.ztlp", None).unwrap();
        pool.lookup_name_mut("a.z.ztlp").unwrap().peer_addr = Some("1.2.3.4:5".parse().unwrap());
        pool.save_to(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("a.z.ztlp") && raw.contains("127.100.0.1"),
            "{raw}"
        );
        assert!(
            !raw.contains("1.2.3.4"),
            "peer address must not be persisted: {raw}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_file(&path);
    }
}
