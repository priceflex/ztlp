#!/usr/bin/env bash
set -euo pipefail

ROOT=${ROOT:-/home/trs/ztlp}
MAC=${MAC:-stevenprice@10.78.72.234}
PHONE_UDID=${PHONE_UDID:-39659E7B-0554-518C-94B1-094391466C12}
GATEWAY=${GATEWAY:-ubuntu@44.246.33.34}
RELAY=${RELAY:-ubuntu@34.219.64.205}
OUT_BASE=${OUT_BASE:-$ROOT/captures}
STAMP=${STAMP:-$(date -u +%Y%m%d-%H%M%S)}
OUT="$OUT_BASE/vault-$STAMP"
SINCE=${SINCE:-15m}
TCPDUMP_SECONDS=${TCPDUMP_SECONDS:-0}

mkdir -p "$OUT"
echo "capture_dir=$OUT"
date -u +%FT%TZ > "$OUT/capture-start-utc.txt"

# Phone app-group log via Steve's Mac.
ssh "$MAC" "rm -f /tmp/ztlp-phone.log; xcrun devicectl device copy from --device $PHONE_UDID --domain-type appGroupDataContainer --domain-identifier group.com.ztlp.shared --source ztlp.log --destination /tmp/ztlp-phone.log >/tmp/ztlp-devcopy.out 2>&1; echo COPY_STATUS=\$?; cat /tmp/ztlp-devcopy.out" > "$OUT/phone-copy.txt" 2>&1 || true
scp "$MAC:/tmp/ztlp-phone.log" "$OUT/ztlp-phone.log" >/dev/null 2>&1 || true

# Server logs. Do not restart anything here.
ssh "$GATEWAY" "docker logs --since '$SINCE' ztlp-gateway 2>&1" > "$OUT/gateway.log" 2>&1 || true
ssh "$RELAY" "docker logs --since '$SINCE' ztlp-relay 2>&1" > "$OUT/relay.log" 2>&1 || true

if [[ "$TCPDUMP_SECONDS" != "0" ]]; then
  ssh "$GATEWAY" "sudo timeout $TCPDUMP_SECONDS tcpdump -i any -n -tttt -s 200 udp port 23097 -w /tmp/ztlp-gw-vault.pcap" > "$OUT/gateway-tcpdump.txt" 2>&1 || true
  scp "$GATEWAY:/tmp/ztlp-gw-vault.pcap" "$OUT/ztlp-gw-vault.pcap" >/dev/null 2>&1 || true
  ssh "$RELAY" "sudo timeout $TCPDUMP_SECONDS tcpdump -i any -n -tttt -s 200 udp port 23095 -w /tmp/ztlp-relay-vault.pcap" > "$OUT/relay-tcpdump.txt" 2>&1 || true
  scp "$RELAY:/tmp/ztlp-relay-vault.pcap" "$OUT/ztlp-relay-vault.pcap" >/dev/null 2>&1 || true
fi

python3 - "$OUT" > "$OUT/summary.txt" <<'PY'
import sys,re, pathlib
out=pathlib.Path(sys.argv[1])
phone=(out/'ztlp-phone.log').read_text(errors='ignore') if (out/'ztlp-phone.log').exists() else ''
gw=(out/'gateway.log').read_text(errors='ignore') if (out/'gateway.log').exists() else ''
patterns={
 'phone_wk': r'WKWebView', 'phone_wk_fail': r'WKWebView .*failed', 'phone_dns': r'Rust fd dns responder wrote response',
 'phone_open': r'RouterAction send OpenStream', 'phone_close': r'RouterAction send CloseStream',
 'phone_rwnd16': r'Advertised rwnd=16', 'phone_rwnd12': r'Advertised rwnd=12', 'phone_rwnd8': r'Advertised rwnd=8', 'phone_rwnd4': r'Advertised rwnd=4',
 'phone_reconnect': r'Reconnect', 'phone_vpn': r'VPN status changed', 'phone_bench_ok': r'Benchmark upload complete', 'phone_bench_fail': r'Benchmark upload failed',
 'gw_open': r'FRAME_OPEN', 'gw_close': r'FRAME_CLOSE', 'gw_ack_rwnd': r'CLIENT_ACK .*rwnd=', 'gw_rto': r'RTO retransmit', 'gw_stall': r'STALL', 'gw_overload': r'send_queue already overloaded|queue=6\d{3,}'
}
for name,pat in patterns.items():
    text=phone if name.startswith('phone') else gw
    print(f'{name}={len(re.findall(pat,text))}')
qs=[int(m.group(1)) for m in re.finditer(r'queue=(\d+)', gw)]
print('gw_queue_max=' + (str(max(qs)) if qs else 'NA'))
for title,text,pat in [('recent_phone_failures',phone,r'WKWebView|Benchmark .*failed|VPN status changed|Session health|Advertised rwnd='),('recent_gateway_close',gw,r'FRAME_CLOSE|FRAME_OPEN|CLIENT_ACK .*rwnd=|Backpressure|STALL|RTO')]:
    print('\n## '+title)
    lines=[l for l in text.splitlines() if re.search(pat,l)]
    for l in lines[-80:]: print(l[:1000])
PY

echo "summary=$OUT/summary.txt"
