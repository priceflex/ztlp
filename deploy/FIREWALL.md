# ZTLP Production Firewall Rules

## Gateway Box (54.149.48.6)

### Port 9102 — Prometheus Metrics
Metrics endpoint restricted to localhost only. Prevents external scraping.

```bash
sudo iptables -A INPUT -p tcp --dport 9102 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9102 -j DROP
```

### Port 8180 — HTTP Echo Server
Echo server accessible only from the Docker bridge network (172.18.0.0/16) and localhost.
The ZTLP gateway container forwards traffic to the echo server via the Docker bridge.

```bash
sudo iptables -A INPUT -p tcp --dport 8180 -s 172.18.0.0/16 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8180 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8180 -j DROP
```

## NS Box (34.217.62.46)

### Port 9103 — Prometheus Metrics
Metrics endpoint restricted to localhost only.

```bash
sudo iptables -A INPUT -p tcp --dport 9103 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9103 -j DROP
```

## Persistence

Rules are persisted via `iptables-persistent`:

```bash
sudo sh -c "iptables-save > /etc/iptables/rules.v4"
```

## Ports Left Open (not firewalled here)

| Port | Protocol | Service | Why |
|------|----------|---------|-----|
| 22 | TCP | SSH | Remote access |
| 443 | UDP | ZTLP Gateway | Client tunnel traffic |
| 53 | UDP/TCP | NS (34.217.62.46) | DNS resolution |

These are handled by the cloud provider's security groups.
