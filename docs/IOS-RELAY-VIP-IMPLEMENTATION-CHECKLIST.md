# iOS Relay-side VIP Implementation Checklist

Date: 2026-04-10
Status: Working checklist
Related design: `docs/RELAY-VIP-ARCHITECTURE.md`

## Purpose

This is the one-page engineering checklist for implementing the iOS-first relay-side VIP architecture with no ambiguity about component ownership.

## Non-negotiable architecture rules

- Classic relay mode remains opaque SessionID forwarding.
- iOS relay-side VIP mode is a separate mode for designated mobile VIP services.
- In iOS relay-side VIP mode, the relay can see plaintext for proxied VIP services.
- NS is the source of truth for relay discovery metadata.
- The relay is not the authority for namespace, identity, or policy.
- Phase 1 failover resets active proxied TCP streams; it does not migrate them.
- Routing is by trusted ZTLP service metadata, not HTTP Host/SNI sniffing.

## Deliverables by component

### 1. NS

Required:
- [ ] RELAY record query path available to iOS sync client path
- [ ] Rich RELAY record format returned with:
  - [ ] `address`
  - [ ] `region`
  - [ ] `latency_ms`
  - [ ] `load_pct`
  - [ ] `active_connections`
  - [ ] `health`
- [ ] Backward-compat behavior chosen and documented
- [ ] Relay health/load publication path defined
- [ ] Fake NS test coverage for rich CBOR response

Acceptance:
- [ ] iPhone/Swift or Rust sync path can request RELAY type 3 and parse all fields
- [ ] At least 2 relays can be ranked deterministically from NS data alone
- [ ] Missing/invalid fields fail safely

### 2. Rust proto / shared client logic

Required:
- [ ] `ztlp_ns_resolve_sync`
- [ ] `ztlp_ns_resolve_relays_sync`
- [ ] `RelayEntry` includes region/load/active connection metadata
- [ ] `RelayPool` scoring updated to load-aware selection
- [ ] `ztlp_relay_pool_*` FFI exported
- [ ] tests for selection, degrade/dead handling, refresh decisions

Acceptance:
- [ ] best relay selection reproducible in unit tests
- [ ] failover excludes dead relay and picks next candidate
- [ ] `NeedNsRefresh` and `NoRelaysAvailable` behavior covered by tests

### 3. iPhone / Network Extension

Required:
- [ ] Remove `ZTLPVIPProxy.swift` from active iOS NE architecture
- [ ] Remove localhost `NWListener` VIP port registrations
- [ ] Add RELAY query support to `ZTLPNSClient.swift` or wire through sync Rust resolver
- [ ] Create/update relay selection path: NS -> RelayPool -> selected relay
- [ ] Route VIP traffic through packetFlow -> encrypted tunnel -> relay
- [ ] Add relay failure detection tied to ACK advance / timeout behavior
- [ ] Reconnect through next relay after failover
- [ ] User-visible logging for selected relay, failover, and tunnel recovery

Acceptance:
- [ ] NE memory is below target range under benchmark load
- [ ] phone can reach designated VIP services without localhost listeners
- [ ] relay failure drops active flows and new flows recover after reselection
- [ ] no silent direct-to-gateway bypass when relay-side VIP mode is enabled

### 4. Relay

Required:
- [ ] server-side VIP proxy module exists
- [ ] decrypt proxied client tunnel payload
- [ ] parse trusted ZTLP service metadata from frame
- [ ] explicit service routing table exists (`service -> backend`)
- [ ] backend TCP connect / request / response proxy path exists
- [ ] encrypt responses back to client tunnel
- [ ] relay metrics emitted for NS publication
- [ ] relay->backend TLS/mTLS supported where applicable

Acceptance:
- [ ] relay can proxy at least one service end-to-end on Linux
- [ ] routing works without Host/SNI sniffing
- [ ] unhealthy relay is removed or deprioritized by NS/client selection logic
- [ ] proxied service behavior survives reconnect as new connections after failover

## Phase order

### Phase 1: NS + selection primitives
- [ ] rich RELAY records
- [ ] sync NS resolution
- [ ] RelayPool FFI
- [ ] selection/failover tests

### Phase 2: relay-side VIP on Linux
- [ ] relay VIP proxy module
- [ ] service routing config
- [ ] local fake backend tests
- [ ] metrics for NS publication

### Phase 3: iPhone migration
- [ ] remove NE VIP listeners
- [ ] wire relay selection into PacketTunnelProvider
- [ ] route VIP traffic to relay
- [ ] verify memory reduction and service reachability

### Phase 4: production hardening
- [ ] relay->backend TLS/mTLS
- [ ] observability/logging
- [ ] fault injection for relay death / NS stale data / degraded load
- [ ] rollback procedure documented

## Test matrix

- [ ] single healthy relay
- [ ] two relays, lower latency wins
- [ ] two relays, lower load wins after score adjustment
- [ ] selected relay becomes degraded
- [ ] selected relay dies during active traffic
- [ ] NS returns stale relay still marked healthy
- [ ] relay routing table missing service
- [ ] backend connect timeout
- [ ] backend TLS failure
- [ ] no relays available

## Explicit out-of-scope for phase 1

- transparent migration of active TCP streams across relay failover
- double-encrypted relay-side VIP payloads
- app-layer routing by Host/SNI
- changing gateway into the source of truth for relay selection
- making the relay the policy authority

## Ship criteria

Do not call this feature done until all are true:
- [ ] docs match implementation
- [ ] trust-model exception is documented everywhere relevant
- [ ] iOS benchmarks show memory savings in expected range
- [ ] relay failover behavior is observable and deterministic
- [ ] at least one real service works end-to-end through relay-side VIP on iPhone
