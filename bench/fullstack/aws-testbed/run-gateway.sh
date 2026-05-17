#!/usr/bin/env bash
set -euo pipefail

# Build locally and push via SSH to gateway host
echo "Building ztlp-gateway:bench-2026-05-17..."
cd /home/trs/ztlp
docker build -t ztlp-gateway:bench-2026-05-17 -f gateway/Dockerfile .

echo "Saving and transferring image to 54.190.82.255..."
docker save ztlp-gateway:bench-2026-05-17 | ssh -C ubuntu@54.190.82.255 "docker load"

echo "Restarting ztlp-gateway container..."
ssh ubuntu@54.190.82.255 << 'EOF'
  sudo docker stop ztlp-gateway || true
  sudo docker rm ztlp-gateway || true
  
  sudo docker run -d --name ztlp-gateway --network host --restart unless-stopped     -e ZTLP_GATEWAY_PORT=23097     -e ZTLP_NS_SERVER=18.236.150.73:23096     -e ZTLP_RELAY_SERVER=44.243.42.123:23095     -e ZTLP_GATEWAY_BACKENDS=echo:127.0.0.1:7777     -e ZTLP_GATEWAY_SERVICE_NAMES=echo     -e 'ZTLP_GATEWAY_POLICIES=*:echo'     -e ZTLP_LOG_LEVEL=debug     -e ZTLP_LOG_FORMAT=text     ztlp-gateway:bench-2026-05-17

  sudo docker ps | grep ztlp-gateway
EOF
echo "Gateway deployed."
