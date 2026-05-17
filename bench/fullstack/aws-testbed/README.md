# ZTLP AWS Full-Stack Testbed

This directory contains idempotent scripts to rebuild the local ZTLP workspace Docker images from source, transfer them to the bench infra via SSH, and restart the temporary containers.

**DO NOT RUN THESE AGAINST PRODUCTION.**
These hardcode the testbed IPs (`18.236.150.73`, `44.243.42.123`, `54.190.82.255`).

Requirements:
- `ns`: UDP 23096, TCP 9103 (metrics)
- `relay`: UDP 23095, TCP 9101 (metrics)
- `gateway`: UDP 23097, TCP 9102 (metrics) -- uses `--network host`.

Scripts:
- `./run-ns.sh`
- `./run-relay.sh`
- `./run-gateway.sh`
