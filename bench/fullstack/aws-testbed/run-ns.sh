#!/usr/bin/env bash
set -euo pipefail

echo "Building ztlp-ns:bench-2026-05-17..."
cd /home/trs/ztlp
docker build -t ztlp-ns:bench-2026-05-17 -f ns/Dockerfile .

echo "Saving and transferring image to 18.236.150.73..."
docker save ztlp-ns:bench-2026-05-17 | ssh -C ubuntu@18.236.150.73 "docker load"

echo "Restarting ztlp-ns container..."
ssh ubuntu@18.236.150.73 << 'EOF'
  sudo docker stop ztlp-ns || true
  sudo docker rm ztlp-ns || true
  
  sudo docker run -d --name ztlp-ns -p 23096:23096/udp -p 9103:9103/tcp --restart unless-stopped     -e ZTLP_NS_PORT=23096     -e ZTLP_LOG_LEVEL=info     ztlp-ns:bench-2026-05-17

  sudo docker ps | grep ztlp-ns
EOF
echo "NS deployed."
