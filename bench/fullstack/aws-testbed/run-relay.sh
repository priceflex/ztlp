#!/usr/bin/env bash
set -euo pipefail

echo "Building ztlp-relay:bench-2026-05-17..."
cd /home/trs/ztlp
docker build -t ztlp-relay:bench-2026-05-17 -f relay/Dockerfile .

echo "Saving and transferring image to 44.243.42.123..."
docker save ztlp-relay:bench-2026-05-17 | ssh -C ubuntu@44.243.42.123 "docker load"

echo "Restarting ztlp-relay container..."
ssh ubuntu@44.243.42.123 << 'EOF'
  sudo docker stop ztlp-relay || true
  sudo docker rm ztlp-relay || true
  
  sudo docker run -d --name ztlp-relay -p 23095:23095/udp -p 9101:9101/tcp --restart unless-stopped     -e ZTLP_RELAY_PORT=23095     -e ZTLP_LOG_LEVEL=info     ztlp-relay:bench-2026-05-17

  sudo docker ps | grep ztlp-relay
EOF
echo "Relay deployed."
