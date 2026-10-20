# Relay: carry many concurrent QUIC flows per gateway (2026-10-20)

## Problem (seen live, ChooseForce first client)
Remote clients reach a NAT'd gateway through the relay. On v0.35.18/19:
1. `do_install_client_route` deletes every other `{:client_map, {ip, _}}` entry from the
   same client IP to the same gateway (v0.29.3 stale-port cleanup). The agent opens one QUIC
   connection (fresh UDP socket) per browser TCP connection, so a page load's 4-6 parallel
   connections delete each other's routes; only the last survives.
2. Gateway->client packets all arrive from the one gateway address. The reverse arm sends them
   to the most recently installed client_map entry for that gateway, across ALL clients.
Net: the relay carries one QUIC flow per gateway at a time. Logs: bursts of N
`CLIENT_ROUTE accepted ... purged_stale=1`, one gateway `handshake success` per burst,
`handshake failed ... connection lost`, pages crawl. Two remote users break each other.

## Fix (relay only; no wire-format change, no client/gateway change)
- Learn QUIC connection IDs on the client->gateway arm: for long-header packets record
  `{:cid, gateway_addr, scid} -> {client_addr, last_seen}`. The gateway addresses every
  reply to the client's SCID (quinn default CID length 8).
- Reverse arm: parse the DCID (long header: explicit length; short header: try known CID
  lengths, 8 first) and look up `{:cid, sender_gateway, dcid}`. Hit -> send to that client.
  Miss -> existing most-recent fallback (keeps legacy/non-QUIC behaviour).
- Stop purging concurrent same-IP routes on CLIENT_ROUTE. Dead ports are already removed by
  the 5-minute idle sweeper, which now also sweeps `{:cid, ...}` entries.
- CID keys include the gateway address, so one tenant's gateway can never steer packets
  to another gateway's client.

## Tests (relay/test/ztlp_relay/udp_listener_test.exs)
- concurrent CLIENT_ROUTEs from one IP to one gateway are all kept
- gateway replies (short + long header) reach the client whose SCID they carry, with two
  clients on the same gateway
- a CID learned for gateway A does not route packets from gateway B
- sweeper drops idle `{:cid, ...}` entries

## Findings from the end-to-end A/B (real v0.35.18 gateway + 5 concurrent clients, one IP)
- Old relay: 5/25 requests succeed (1 of 5 connections per round) — the production symptom.
- Direct to gateway (no relay): 40/40, 2-10 ms.
- This branch: 23/25. Remaining stalls: quinn 0.11 servers switch to a new client-issued
  connection ID as soon as the client's first NEW_CONNECTION_ID arrives
  (quinn-proto connection/mod.rs "switch immediately to enable clientside stateless resets").
  That ID travels encrypted, so a relay cannot learn it; after the switch replies fall back
  to "most recent client". Also: quinn greases the fixed bit, so short headers must be
  matched on the first bit only.
- Complete relay fix therefore needs the CLIENT to make its connection IDs routable: a
  custom quinn ConnectionIdGenerator giving every CID of one client endpoint the same
  random 4-byte prefix; the relay learns prefix -> client from the Initial SCID and routes
  by DCID prefix (the QUIC-LB idea, applied to clients). Agent + CLI release required.
- Alternative that avoids the relay for remote clients: gateway advertises the office public
  address (needs a new listen flag; `--stun-server` is unused in cmd_listen) plus a UDP 23097
  forward on the office firewall. Note agents rank other-RFC1918 (200) above public (160),
  so remote clients still spend 750 ms on the LAN candidate per dial until the agent changes.

## Complete fix (implemented)
- proto `quic_transport::RelayRoutableCidGenerator` + `client_endpoint_config()`: every
  client endpoint (all 4 constructors) issues 8-byte CIDs = 4-byte random per-endpoint
  prefix + 4 random bytes. Gateways (servers) unchanged.
- relay learns `{:cidp, gateway, prefix}` from 8-byte Initial SCIDs; reverse order: exact
  CID -> prefix -> legacy most-recent. Sweeper clears `:cidp` entries.
- A/B, real binaries, unmodified v0.35.18 gateway, 5 concurrent connections from one IP:
  | relay \ clients | v0.35.18 | this branch |
  |---|---|---|
  | v0.35.19 (prod today) | 5/25 | 4/20 (no regression) |
  | this branch | 29/30 | 40/40; 120/120 with 12 concurrent |
  Direct (no relay) baseline 40/40. Harness: relay_ab.py (see skill ztlp-architecture-and-debugging).
- Deploy order is free (each side is backward compatible); full benefit needs both.

## Out of scope / follow-ups
- Agent: one QUIC connection per gateway with a stream per TCP connection, and remember a
  failed direct candidate (removes ~1 s setup per browser connection).
- Advertising the gateway's public address so remote clients can skip the relay.

## Rollout
Prod relay 44.227.148.151 (ztlp-relay container) is shared by every TRS gateway. Build the
image from this branch, deploy in a window with Steven's OK, watch `CLIENT_ROUTE` +
gateway handshakes for ChooseForce and Blitz, roll back by retagging the previous image.
