#!/usr/bin/env bash
# scripts/test-ns.sh — start/stop a throwaway local NS for the ZTLP_TEST_NS
# roundtrip integration test (admin test/integration/ns_roundtrip_test.rb).
#
# Usage:
#   scripts/test-ns.sh up    start ztlp-ns:v0.35.20 on 127.0.0.1:23196/udp + 9203
#   scripts/test-ns.sh down  stop + remove the container
#
# Throwaway secrets are generated at runtime and written to an env file under
# the scratch dir; they are NEVER printed to stdout (skill: never print secrets).
# The test reads the same file to reach the NS.
#
# Ports (non-default, chosen to avoid colliding with a real prod NS):
#   UDP   23196   ZTLP_NS_PORT
#   HTTP  9203    ZTLP_NS_METRICS_PORT (admin /admin/records + metrics)
#
# This build's NS (ztlp-ns:v0.35.20) has no enrollment-secret env var; the
# roundtrip only needs the admin API secret for /admin/records and registration
# auth enabled so the authorization checks (zone authority vs non-authority)
# actually run.

set -euo pipefail

NS_IMAGE="${NS_IMAGE:-ztlp-ns:v0.35.20}"
NS_CTR="ztlp-admin-test-ns"
NS_UDP_PORT="23196"
NS_HTTP_PORT="9203"
SCRATCH="${SCRATCH_DIR:-/home/trs/.hermes/profiles/cb-1321-34b7/cache/scratch}"
ENV_FILE="${SCRATCH}/test_ns.env"

cmd="${1:-}"
case "${cmd}" in
  up)
    mkdir -p "${SCRATCH}"
    # Throwaway secrets, 64 hex chars each (= 32 raw bytes the NS accepts).
    admin_secret="$(openssl rand -hex 32)"
    # Write to the env file WITHOUT echoing the value. The test sources this.
    {
      printf 'ZTLP_TEST_NS=1\n'
      printf 'ZTLP_TEST_NS_ADDR=127.0.0.1:%s\n' "${NS_UDP_PORT}"
      printf 'ZTLP_TEST_NS_ADMIN_API_PORT=%s\n' "${NS_HTTP_PORT}"
      printf 'ZTLP_TEST_NS_ADMIN_API_SECRET=%s\n' "${admin_secret}"
    } > "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"

    docker rm -f "${NS_CTR}" >/dev/null 2>&1 || true
    docker run -d \
      --name "${NS_CTR}" \
      -p "127.0.0.1:${NS_UDP_PORT}:23196/udp" \
      -p "127.0.0.1:${NS_HTTP_PORT}:9203" \
      -e ZTLP_NS_PORT=23196 \
      -e ZTLP_NS_METRICS_PORT=9203 \
      -e ZTLP_NS_METRICS_BIND=0.0.0.0 \
      -e ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true \
      -e ZTLP_NS_STORAGE_MODE=ram_copies \
      -e ZTLP_NS_ADMIN_API_SECRET="${admin_secret}" \
      "${NS_IMAGE}" >/dev/null

    # Wait for the healthcheck (bounded). The NS is ready when `rpc IO.puts(:ok)`
    # works, which the image's healthcheck does.
    ready=0
    for _ in $(seq 1 30); do
      if docker exec "${NS_CTR}" /app/bin/ztlp_ns rpc "IO.puts(:ok)" 2>/dev/null | grep -q "ok"; then
        ready=1
        break
      fi
      sleep 1
    done
    if [ "${ready}" != "1" ]; then
      docker logs --tail 40 "${NS_CTR}" 2>&1 || true
      echo "ERROR: test NS did not become ready in time" >&2
      docker rm -f "${NS_CTR}" >/dev/null 2>&1 || true
      exit 1
    fi
    echo "NS up: container ${NS_CTR} (udp 127.0.0.1:${NS_UDP_PORT}, http 127.0.0.1:${NS_HTTP_PORT}); env at ${ENV_FILE}"
    ;;
  down)
    docker rm -f "${NS_CTR}" >/dev/null 2>&1 || true
    rm -f "${ENV_FILE}" 2>/dev/null || true
    echo "NS down: ${NS_CTR} removed"
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
