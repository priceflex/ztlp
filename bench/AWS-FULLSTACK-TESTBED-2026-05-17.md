# ZTLP AWS Full-Stack Testbed State — 2026-05-17

Captured: 2026-05-17 04:33:16

> Read-only snapshot of the temporary AWS testbed (NS / Relay / Gateway). This is **not** the production fleet (`34.217.62.46` / `34.219.64.205` / `44.246.33.34`) and must not be confused with it. See `bench/NEXT-TASKS-PRODUCTION-READY-2026-05-17.md`.

---

## 1. Hosts & Listen Ports

| Role    | Public IP        | Container       | Port        |
|---------|------------------|-----------------|-------------|
| NS      | 18.236.150.73    | ztlp-ns         | 23096/udp   |
| Relay   | 44.243.42.123    | ztlp-relay      | 23095/udp   |
| Gateway | 54.190.82.255    | ztlp-gateway    | 23097/udp   |
| Backend | 54.190.82.255    | http-bench      | tcp 7777 (host net, gateway-local) |

SSH: `ssh ubuntu@<ip>` (default key).

---

## 2. `docker ps` on each host

### NS — 18.236.150.73
```
ztlp-ns	ztlp-ns:bench-2026-05-17	Up 50 minutes (healthy)	0.0.0.0:9103->9103/tcp, [::]:9103->9103/tcp, 0.0.0.0:23096->23096/udp, [::]:23096->23096/udp
```

### Relay — 44.243.42.123
```
ztlp-relay	ztlp-relay:bench-2026-05-17	Up 50 minutes (healthy)	0.0.0.0:9101->9101/tcp, [::]:9101->9101/tcp, 0.0.0.0:23095->23095/udp, [::]:23095->23095/udp
```

### Gateway — 54.190.82.255
```
http-bench	python:3.11-alpine	Up 20 minutes	
ztlp-gateway	ztlp-gateway:bench-2026-05-17	Up 48 minutes (healthy)
```

---

## 3. UDP sysctls

### Client (bench harness host)
```
net.core.rmem_max = 7340032
net.core.wmem_max = 7340032
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
```

### NS — 18.236.150.73
```
net.core.rmem_max = 7340032
net.core.wmem_max = 7340032
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
```

### Relay — 44.243.42.123
```
net.core.rmem_max = 7340032
net.core.wmem_max = 7340032
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
```

### Gateway — 54.190.82.255
```
net.core.rmem_max = 7340032
net.core.wmem_max = 7340032
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
```

---

## 4. Container env vars

### ztlp-ns (18.236.150.73)
```
["ZTLP_NS_PORT=23096","ZTLP_NS_STORAGE_MODE=ram_copies","ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false"...er"]
```

### ztlp-relay (44.243.42.123)
```
ZTLP_LOG_FORMAT=json
RELEASE_COOKIE=ztlp_relay_docker
ZTLP_RELAY_PORT=23095
ZTLP_RELAY_LISTEN_PORT=23095
ZTLP_RELAY_METRICS_ENABLED=true
ZTLP_RELAY_METRICS_PORT=9101
ZTLP_LOG_LEVEL=info
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=en_US.UTF-8
LC_ALL=en_US.UTF-8
```

### ztlp-gateway (54.190.82.255)
```
ZTLP_GATEWAY_PORT=23097
ZTLP_NS_SERVER=18.236.150.73:23096
ZTLP_RELAY_SERVER=44.243.42.123:23095
ZTLP_GATEWAY_BACKENDS=echo:127.0.0.1:7777
ZTLP_GATEWAY_SERVICE_NAMES=echo
ZTLP_GATEWAY_POLICIES=*:echo
ZTLP_LOG_LEVEL=info
ZTLP_LOG_FORMAT=json
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=en_US.UTF-8
LC_ALL=en_US.UTF-8
ZTLP_GATEWAY_METRICS_ENABLED=true
ZTLP_GATEWAY_METRICS_PORT=9102
RELEASE_COOKIE=ztlp_gateway_docker
```

---

## 5. Gateway backend service

### http-bench container (54.190.82.255)
```
["python3","/app/http_bench.py"]|||host|||["PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D","PYTHON_VERSION=3.11.15","PYTHON_SHA256=272179ddd9a2e41a0fc8e42e33dfbdca0b3711aa5abf372d3f2d51543d09b625"]
```

### /tmp/http_bench.py on gateway host
```python
#!/usr/bin/env python3
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import time

CHUNK = (b'0123456789abcdef' * 4096)  # 64 KiB

class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        size = int(q.get('size', [10*1024*1024])[0])
        if urlparse(self.path).path not in ('/', '/bytes'):
            self.send_error(404); return
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        left = size
        while left > 0:
            n = min(left, len(CHUNK))
            self.wfile.write(CHUNK[:n])
            left -= n
    def log_message(self, fmt, *args):
        return

if __name__ == '__main__':
    print('http_bench listening on 127.0.0.1:7777', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 7777), H).serve_forever()
```

---

## 6. AWS Security Group ports

Inbound rules required on each instance's SG:

- NS (18.236.150.73):      UDP 23096
- Relay (44.243.42.123):   UDP 23095
- Gateway (54.190.82.255): UDP 23097
- Optional metrics (TCP): 9101 (NS) / 9102 (Gateway) / 9103 (Relay)
- SSH:                     TCP 22 from operator IP

---

## 7. Recreating from scratch

1. Launch 3 Ubuntu instances, open the UDP ports above in each SG.
2. Install docker + raise UDP buffers on every host:
   ```bash
   sudo sysctl -w net.core.rmem_max=8388608
   sudo sysctl -w net.core.wmem_max=8388608
   sudo sysctl -w net.core.rmem_default=2097152
   sudo sysctl -w net.core.wmem_default=2097152
   ```
   (Persist in `/etc/sysctl.d/99-ztlp.conf`.)
3. Build/push the three ZTLP images (ns / relay / gateway) — see existing `gateway/Dockerfile`, `relay/Dockerfile`, `ns/Dockerfile`.
4. Launch each container with `--network host` and the env vars listed in §4 above. Substitute IPs as needed.
5. On the gateway host, start the HTTP byte-server backend (§5) on 127.0.0.1:7777 — the simplest path is `python3 /tmp/http_bench.py` inside a small `http-bench` container or directly under systemd.
6. Verify with `python3 bench/run_fullstack_multistream.py --size 65536 --ns 1` from the bench harness host.

The Task 8 follow-up turns this into checked-in run scripts under `bench/fullstack/aws-testbed/`.

---

## 8. Known-good baselines

- Loopback rcvbuf fix on `main` (`c6947e0`): 214 MB/s at N=32, zero `UdpRcvbufErrors`. See `bench/RESULTS-2026-05-17.md`.
- Real WAN smoke: 64 KiB single-stream completes. 1 MiB single-stream receives ~513 KiB then stalls. See `bench/RESULTS-FULLSTACK-2026-05-17.md` and `bench/NEXT-TASKS-PRODUCTION-READY-2026-05-17.md`.
