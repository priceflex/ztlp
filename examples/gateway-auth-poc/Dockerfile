# ZTLP Gateway-Auth PoC backend
#
# Stdlib-only Python app — no pip dependencies. Renders the X-ZTLP-* headers
# injected by the ZTLP gateway (`ztlp listen --http-inject-headers`) and
# re-verifies the HMAC-SHA256 signature, audience binding, and timestamp
# freshness (see app.py header for the full contract).
#
# Build:
#   docker build -t ztlp-poc .
#
# Run (the two ZTLP_* env vars MUST match the gateway's launch args):
#   docker run -d --name ztlp-poc -p 18080:8080 \
#     -e ZTLP_HEADER_HMAC_SECRET=<the gateway's --header-hmac-secret> \
#     -e ZTLP_EXPECTED_AUDIENCE=web \
#     ztlp-poc

FROM python:3.12-slim

ENV PORT=8080
WORKDIR /app

COPY app.py /app/app.py

EXPOSE 8080

# Same healthcheck the live demo container uses: /up is a plain 200 endpoint
# that does NOT require ZTLP headers (used by docker healthchecks, not by the
# tunnel path).
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/up',timeout=3)" || exit 1

CMD ["python", "app.py"]
