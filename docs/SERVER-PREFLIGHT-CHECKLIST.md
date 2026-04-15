# ZTLP Server Preflight Checklist

Use this before asking Steve to test on the phone.

Script:
- `~/ztlp/scripts/ztlp-server-preflight.sh`

What it checks:
1. NS container is up and exposed on UDP 23096 / TCP 9103
2. NS relay record typo is fixed (`techrockstars`)
3. NS registration auth is disabled for current bootstrap path
4. Relay container is up and receiving fresh gateway registrations
5. Gateway container is up
6. Gateway is running with `--network host`
7. Gateway runtime NS config resolves to `172.26.13.85:23096`
8. Gateway can connect to host backends:
   - `127.0.0.1:8080`
   - `127.0.0.1:8180`
9. No recent gateway backend `econnrefused`
10. No recent send_queue overload rejections
11. Gateway can make a synthetic UDP NS query successfully
12. Bootstrap benchmark API is reachable

Run:
```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

Success criteria:
- Script exits 0
- Final line says: `PRECHECK GREEN server-side stack is ready for phone testing`

Current expected warnings:
- `Did not see relay seeding in recent NS logs` is acceptable if NS has been up for a while
- `No recent handshake activity observed` is acceptable when nobody is currently testing

Interpretation:
- GREEN means server-side stack is ready and Steve can test on phone
- RED means do not ask Steve to test yet; fix infra first
