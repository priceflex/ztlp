# Unified Audit & Logging System

> Status: Planned | Priority: Phase 0.9 (after production hardening)

## Overview

A centralized logging and audit system where all ZTLP components (gateway, relay, NS, agents/clients) report structured events to a single searchable dashboard. Operators can search by date/time, hostname, username, service, event type, and free-text details.

## Current State

Each component already has structured logging and audit infrastructure:

| Component | Structured Log | Audit Trail | Log Format | Storage |
|---|---|---|---|---|
| **NS** | `ZtlpNs.StructuredLog` | `ZtlpNs.Audit` (ETS ring buffer, 10K entries) | JSON/structured/console via `ZTLP_LOG_FORMAT` | In-memory (ETS) |
| **Gateway** | `ZtlpGateway.LogFormatter` | `ZtlpGateway.AuditLog` (ETS ordered_set) | JSON/structured/console via `ZTLP_LOG_FORMAT` | In-memory (ETS) |
| **Relay** | `ZtlpRelay.StructuredLog` | Per-session stats | JSON/structured/console via `ZTLP_LOG_FORMAT` | In-memory |
| **Clients** | Rust `tracing` crate | None | Text | Local file/stdout |

### What's Missing

1. **No central collection** — each component logs locally, no aggregation
2. **No persistent audit storage** — ETS tables lost on restart
3. **No search UI** — must SSH into each box and grep logs
4. **No cross-component correlation** — can't trace a request from client → relay → gateway → backend
5. **No agent/client log reporting** — phones and desktops don't ship logs anywhere

---

## Architecture

### Option A: Lightweight (Built-in, Zero Dependencies)

Add an **Audit Collector** GenServer to the gateway that:
- Receives audit events from all components via ZTLP wire protocol
- Stores events in Mnesia (disc_copies) with indexes on timestamp, hostname, username, event type
- Exposes a simple HTTP API for querying
- Ships with a single-page HTML dashboard (like the existing `docs/index.html` pattern)

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────────┐
│  Client   │     │  Relay   │     │   NS     │     │   Gateway    │
│  (phone)  │     │          │     │          │     │              │
└─────┬─────┘     └─────┬────┘     └─────┬────┘     │ ┌──────────┐│
      │                 │               │           │ │  Audit   ││
      │    ZTLP audit   │  ZTLP audit   │  local    │ │Collector ││
      └────events───────┴───events──────┴──calls────│ │ (Mnesia) ││
                                                    │ └────┬─────┘│
                                                    │      │      │
                                                    │ ┌────▼─────┐│
                                                    │ │ HTTP API ││
                                                    │ │/audit/*  ││
                                                    │ └──────────┘│
                                                    └──────────────┘
                                                          │
                                                    ┌─────▼──────┐
                                                    │  Dashboard │
                                                    │  (HTML/JS) │
                                                    └────────────┘
```

**Pros:** Zero external dependencies, pure OTP, ships as part of the gateway.
**Cons:** Single-node storage, limited to Mnesia capacity (~1M events practical).

### Option B: Production-Grade (External Stack)

Use standard log aggregation:
- All components output JSON logs (`ZTLP_LOG_FORMAT=json`)
- Docker log driver ships to **Loki** (lightweight) or **Elasticsearch**
- **Grafana** dashboard for search and visualization
- Audit events also written to Loki/ES via HTTP push from each component

**Pros:** Proven at scale, rich query language, alerting built-in.
**Cons:** External dependencies (Loki/Grafana or ELK stack), more infrastructure.

### Recommendation

**Start with Option A** (built-in) for simplicity and zero-dependency ethos. Migrate to Option B when scale demands it. The wire protocol and event format are the same either way.

---

## Wire Protocol

New opcode `0x15` for audit event submission:

```
Request:  <<0x15, event_len::32-big, event_json::binary>>
Response: <<0x15, 0x00>>  (accepted)
          <<0x15, 0x01>>  (rejected — rate limited)
          <<0x15, 0x02>>  (rejected — unauthorized)
```

Events are JSON-encoded maps with a standard envelope:

```json
{
  "ts": "2026-03-29T16:48:00.000Z",
  "component": "gateway",
  "hostname": "gw-prod-1",
  "event": "session_established",
  "level": "info",
  "session_id": "a1b2c3d4...",
  "source_ip": "174.236.97.20",
  "source_port": 52341,
  "username": "steve@techrockstars.ztlp",
  "node_id": "0x1234abcd...",
  "service": "vault.techrockstars.ztlp",
  "details": {
    "handshake_ms": 299,
    "relay": "34.219.64.205:23095"
  }
}
```

### Standard Envelope Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `ts` | ISO 8601 | ✅ | Event timestamp (UTC) |
| `component` | string | ✅ | `gateway`, `relay`, `ns`, `agent`, `client` |
| `hostname` | string | ✅ | Machine hostname or container ID |
| `event` | string | ✅ | Event type (see Event Catalog below) |
| `level` | string | ✅ | `debug`, `info`, `warn`, `error` |
| `session_id` | hex string | | ZTLP session ID (if applicable) |
| `source_ip` | string | | Client/peer IP address |
| `username` | string | | Authenticated user/node name |
| `node_id` | hex string | | ZTLP 128-bit NodeID |
| `service` | string | | Target service name |
| `zone` | string | | ZTLP zone (e.g., `techrockstars.ztlp`) |
| `details` | object | | Event-specific key/value pairs |

---

## Event Catalog

### Gateway Events
| Event | Level | Description |
|---|---|---|
| `session_established` | info | Noise_XX handshake completed |
| `session_terminated` | info | Session ended (reason in details) |
| `session_dedup` | warn | Old session killed for same {ip, port} |
| `stream_opened` | info | Mux stream opened to backend service |
| `stream_closed` | info | Mux stream closed |
| `tls_terminated` | info | TLS termination started for stream |
| `tls_cert_issued` | info | Certificate issued by CA |
| `tls_cert_renewed` | info | Certificate renewed |
| `tls_cert_expiring` | warn | Certificate approaching expiry |
| `tls_cert_expired` | error | Certificate expired |
| `policy_denied` | warn | Connection denied by policy engine |
| `backend_connect` | info | TCP connection to backend |
| `backend_error` | error | Backend connection/forwarding failure |
| `keepalive_received` | debug | Keepalive frame from client |
| `registration_success` | info | NS service registration succeeded |
| `registration_failed` | warn | NS service registration rejected |
| `zone_bootstrapped` | info | Zone delegation key registered |

### NS Events
| Event | Level | Description |
|---|---|---|
| `registration_accepted` | info | Record registration accepted |
| `registration_rejected` | warn | Record registration rejected (reason) |
| `query_resolved` | debug | Name lookup succeeded |
| `query_not_found` | debug | Name lookup miss |
| `cert_issued` | info | CA issued a certificate |
| `cert_revoked` | warn | Certificate revoked |
| `zone_delegated` | info | Zone delegation created |
| `enrollment_success` | info | Device enrollment completed |
| `enrollment_failed` | warn | Device enrollment rejected |
| `rate_limited` | warn | Request rate limited |
| `federation_sync` | info | Anti-entropy sync with peer |

### Relay Events
| Event | Level | Description |
|---|---|---|
| `session_admitted` | info | New session via admission token |
| `session_forwarded` | debug | Packet forwarded between peers |
| `admission_rejected` | warn | Invalid/expired admission token |
| `mesh_peer_joined` | info | New relay joined mesh |
| `mesh_peer_departed` | info | Relay left mesh |
| `mesh_failover` | warn | Traffic rerouted due to peer failure |

### Client/Agent Events
| Event | Level | Description |
|---|---|---|
| `tunnel_connected` | info | Tunnel established to gateway |
| `tunnel_disconnected` | warn | Tunnel lost (reason) |
| `tunnel_reconnected` | info | Tunnel re-established after failure |
| `vip_request` | debug | VIP proxy handled a connection |
| `dns_resolved` | debug | ZTLP DNS resolution |
| `enrollment_completed` | info | Device enrolled successfully |
| `ca_cert_installed` | info | CA root cert installed |

---

## HTTP Query API

The Audit Collector exposes a REST API on the gateway's metrics port (default 9102) or a dedicated audit port.

### `GET /audit/events`

Query parameters:
| Param | Type | Example | Description |
|---|---|---|---|
| `since` | ISO 8601 | `2026-03-29T00:00:00Z` | Start time (required) |
| `until` | ISO 8601 | `2026-03-29T23:59:59Z` | End time (default: now) |
| `component` | string | `gateway` | Filter by component |
| `hostname` | string | `gw-prod-1` | Filter by hostname |
| `username` | string | `steve@*` | Filter by username (glob) |
| `event` | string | `session_established` | Filter by event type |
| `level` | string | `warn` | Minimum level (`debug`/`info`/`warn`/`error`) |
| `service` | string | `vault.*` | Filter by service (glob) |
| `q` | string | `timeout` | Free-text search in details |
| `limit` | integer | `100` | Max results (default 100, max 10000) |
| `offset` | integer | `0` | Pagination offset |

Response:
```json
{
  "total": 1523,
  "offset": 0,
  "limit": 100,
  "events": [
    {
      "ts": "2026-03-29T16:19:05.462Z",
      "component": "gateway",
      "hostname": "gw-prod-1",
      "event": "registration_success",
      "level": "info",
      "service": "vault.techrockstars.ztlp",
      "details": { "ns": "34.217.62.46:23096" }
    }
  ]
}
```

### `GET /audit/stats`

Aggregate statistics:
```json
{
  "total_events": 15234,
  "by_component": { "gateway": 8000, "ns": 5000, "relay": 2234 },
  "by_level": { "info": 14000, "warn": 1100, "error": 134 },
  "by_event": { "session_established": 500, "stream_opened": 3000, ... },
  "oldest_event": "2026-03-29T05:06:09Z",
  "newest_event": "2026-03-29T16:48:00Z"
}
```

### `GET /audit/dashboard`

Serves the single-page HTML dashboard (embedded, no external deps).

---

## Dashboard UI

Single HTML file with embedded CSS/JS (same pattern as `docs/index.html`):

- **Search bar** at top: date range picker, component filter, hostname, username, free-text search
- **Event timeline** below: scrollable list of events with color-coded severity
- **Event detail panel**: click an event to see full details JSON
- **Live tail**: WebSocket or polling mode to watch events in real-time
- **Stats sidebar**: event counts by component, level, event type
- **Export**: CSV/JSON download of filtered results

### Mockup

```
┌─────────────────────────────────────────────────────────────────┐
│ ZTLP Audit Dashboard                              [Live ●]     │
├─────────────────────────────────────────────────────────────────┤
│ From: [2026-03-29 00:00] To: [2026-03-29 23:59]  [Search]     │
│ Component: [All ▼] Host: [________] User: [________]           │
│ Level: [info+ ▼]  Event: [All ▼]  Details: [________________]  │
├──────┬──────────────────────────────────────────────────────────┤
│Stats │ Time       │ Component │ Event              │ Details    │
│      │────────────┼───────────┼────────────────────┼────────────│
│ GW:  │ 16:19:05   │ gateway   │ zone_bootstrapped  │ techroc... │
│ 8000 │ 16:19:05   │ gateway   │ registration_succ  │ vault.t... │
│      │ 16:19:05   │ gateway   │ registration_succ  │ http.te... │
│ NS:  │ 16:19:09   │ gateway   │ tls_cert_issued    │ default... │
│ 5000 │ 16:19:09   │ gateway   │ tls_cert_issued    │ http.te... │
│      │ 16:20:00   │ ns        │ registration_acc   │ default... │
│ RLY: │ 16:22:30   │ relay     │ session_admitted   │ from:17... │
│ 2234 │ 16:22:31   │ gateway   │ session_establish  │ steve@t... │
│      │ 16:22:31   │ gateway   │ stream_opened      │ vault.t... │
│ ERR: │            │           │                    │            │
│  134 │            │           │                    │            │
├──────┴──────────────────────────────────────────────────────────┤
│ ► Event Detail: session_established                             │
│   ts: 2026-03-29T16:22:31.000Z                                 │
│   session_id: a1b2c3d4e5f6...                                  │
│   source_ip: 174.236.97.20                                     │
│   username: steve@techrockstars.ztlp                            │
│   service: vault.techrockstars.ztlp                             │
│   handshake_ms: 299, relay: 34.219.64.205:23095                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1: Audit Collector (gateway-side)
- New `ZtlpGateway.AuditCollector` GenServer
- Mnesia table `ztlp_audit_events` (disc_copies) with compound indexes
- Wire protocol handler for `0x15` events in `session.ex`
- HTTP API endpoints on metrics port
- Migrate existing `AuditLog` ETS events into the new Mnesia store
- **Estimated: ~600 lines**

### Phase 2: Component Reporters
- NS: `ZtlpNs.AuditReporter` — ships structured log events to gateway via UDP `0x15`
- Relay: `ZtlpRelay.AuditReporter` — same pattern
- Gateway: local events go directly to AuditCollector (no network hop)
- Config: `ZTLP_AUDIT_COLLECTOR=54.149.48.6:23097` on each component
- **Estimated: ~200 lines per component**

### Phase 3: Client Reporting
- Rust: `audit.rs` module — batches events, sends via existing ZTLP transport
- iOS: `AuditService.swift` — forwards tunnel events to gateway
- Agent/desktop: same Rust module via existing tunnel connection
- **Estimated: ~300 lines Rust + ~100 lines Swift**

### Phase 4: Dashboard
- Single HTML file with embedded JS (Vanilla JS, no framework)
- Fetch API for queries, EventSource for live tail
- Date range picker, filters, event list, detail panel
- Dark/light mode (match existing docs site)
- **Estimated: ~1500 lines HTML/CSS/JS**

### Phase 5: Retention & Maintenance
- Configurable retention period (`ZTLP_AUDIT_RETENTION_DAYS`, default 30)
- Periodic cleanup GenServer (hourly sweep of expired events)
- Export to external systems: webhook push, syslog forwarding
- Compression for archived events

---

## Configuration

| Env Var | Default | Description |
|---|---|---|
| `ZTLP_AUDIT_ENABLED` | `true` | Enable/disable audit collection |
| `ZTLP_AUDIT_COLLECTOR` | (local) | Audit collector address (`host:port`) |
| `ZTLP_AUDIT_RETENTION_DAYS` | `30` | Days to retain audit events |
| `ZTLP_AUDIT_MAX_EVENTS` | `1000000` | Max events before oldest are pruned |
| `ZTLP_AUDIT_PORT` | `9103` | HTTP API port (0 = use metrics port) |
| `ZTLP_AUDIT_LEVEL` | `info` | Minimum level to collect |
| `ZTLP_AUDIT_BATCH_SIZE` | `50` | Events batched before sending |
| `ZTLP_AUDIT_BATCH_INTERVAL_MS` | `5000` | Max time between batch sends |

---

## Security

- Audit events sent via ZTLP encrypted transport (same Noise_XX tunnel as data)
- HTTP dashboard protected by auth token (`ZTLP_AUDIT_TOKEN`) or mTLS
- Write access (submitting events) requires component authentication
- Read access (dashboard) requires operator credentials
- Sensitive fields (passwords, keys) must be redacted before submission
- Rate limiting on event submission (prevent log flooding attacks)
