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

## Out of scope / follow-ups
- Agent: one QUIC connection per gateway with a stream per TCP connection, and remember a
  failed direct candidate (removes ~1 s setup per browser connection).
- Advertising the gateway's public address so remote clients can skip the relay.

## Rollout
Prod relay 44.227.148.151 (ztlp-relay container) is shared by every TRS gateway. Build the
image from this branch, deploy in a window with Steven's OK, watch `CLIENT_ROUTE` +
gateway handshakes for ChooseForce and Blitz, roll back by retagging the previous image.
