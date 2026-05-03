# iOS Vaultwarden Capture Runbook

Purpose: capture phone, gateway, and relay evidence for one WKWebView/Vaultwarden run without restarting production services.

## Before test

1. Make sure Steve is not running another benchmark.
2. Run server preflight:

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Must end with `PRECHECK GREEN`.

## Capture after a failed or successful Vaultwarden attempt

Default last 15 minutes:

```bash
/home/trs/ztlp/scripts/ztlp-ios-vault-capture.sh
```

Custom window:

```bash
SINCE=5m /home/trs/ztlp/scripts/ztlp-ios-vault-capture.sh
```

Optional encrypted UDP tcpdump capture. This does not identify HTTP assets, but proves packet flow/gaps:

```bash
TCPDUMP_SECONDS=60 /home/trs/ztlp/scripts/ztlp-ios-vault-capture.sh
```

Outputs go to:

```text
/home/trs/ztlp/captures/vault-YYYYmmdd-HHMMSS/
```

Key files:

- `ztlp-phone.log` — app-group iOS logs
- `gateway.log` — gateway container logs
- `relay.log` — relay container logs
- `summary.txt` — counts and recent key lines
- `*.pcap` — optional tcpdump captures

## What to look for

Good signs:

- `Rust fd dns responder wrote response`
- `WKWebView session=... didCommit` then `didFinish`
- gateway `CLIENT_ACK ... rwnd=12` or `rwnd=16` during page load
- gateway queue stays shallow, no queue thousands
- no automatic VPN disconnect

Bad signs:

- `WKWebView ... code=-999` without an intentional reload/dismiss
- gateway `FRAME_CLOSE ... stream_queue_bytes>0` or `dropped_bytes>0`
- `RTO retransmit` storm
- `STALL` with active vault streams
- phone `replayDelta` increasing

Interpretation rule: if Vaultwarden still does not load, the next action must be based on the capture's exact failed stream/resource/close initiator, not another blind rwnd or gateway queue tweak.
