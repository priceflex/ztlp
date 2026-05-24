#!/usr/bin/env ruby
# frozen_string_literal: true

# Z2LS reference client — gateway-auth enrollment token (Option C).
#
# Self-contained example of how a Z2LS host requests a single-device
# enrollment token from ZTLP Bootstrap WITHOUT HMAC signing and
# WITHOUT CSRF tokens. Auth is provided by the ZTLP tunnel itself:
# the per-tenant ZTLP gateway injects authoritative admin-identity
# headers (`X-ZTLP-Authenticated`, `X-ZTLP-Admin-Email`, etc.) on
# every request that comes through it. Bootstrap verifies those
# headers via `Ztlp::HeaderVerifier`.
#
# In other words: open the tunnel, make a plain HTTP POST, get a
# token back. No shared secrets on the Z2LS host. No signing.
#
# Documented in detail in `bootstrap/docs/z2ls_gateway_auth_runbook.md`.
#
# Topology:
#
#   Z2LS host (ZTLP-enrolled admin device)
#         │
#         │ ZTLP tunnel  (`ztlp connect bootstrap.<zone>`)
#         ▼  binds to a local forward port (default 8000)
#   ZTLP gateway → injects X-ZTLP-* identity headers
#         │
#         ▼
#   Rails: POST /api/admin/enrollment_tokens
#
# Usage:
#
#   # 1. Open the tunnel in another terminal (out of scope here):
#   #    ztlp connect bootstrap.acme.ztlp --local 127.0.0.1:8000
#   #
#   # 2. Mint a token:
#   export BOOTSTRAP_URL="http://127.0.0.1:8000"
#   ruby bootstrap/script/z2ls_gateway_auth_token_request.rb \
#     alice-laptop os=macOS owner=alice@acme.com
#
# Optional env vars:
#   BOOTSTRAP_URL   — local-forward URL the tunnel terminates at
#                     (default: http://127.0.0.1:8000).
#   Z2LS_MAX_USES   — override max_uses on the minted token (default 1).
#   Z2LS_EXPIRES_IN — override token TTL (default "24h"). Allowed:
#                     "1h", "6h", "12h", "24h", "1d", "3d", "7d", "1w".
#   Z2LS_ZONE       — pass through `zone` in the body to disambiguate
#                     when this Bootstrap host serves more than one
#                     Network row (Launch containers are single-zone,
#                     so this is normally unnecessary).

require "json"
require "net/http"
require "uri"

def request_enrollment_token(bootstrap_url:, computer_name:, metadata: nil,
                             max_uses: nil, expires_in: nil, zone: nil,
                             timeout: 10)
  path = "/api/admin/enrollment_tokens"

  payload = { computer_name: computer_name }
  payload[:metadata]   = metadata   if metadata && !metadata.empty?
  payload[:max_uses]   = max_uses   if max_uses
  payload[:expires_in] = expires_in if expires_in
  payload[:zone]       = zone       if zone
  body = payload.to_json

  uri = URI(bootstrap_url.chomp("/") + path)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  http.open_timeout = 5
  http.read_timeout = timeout

  req = Net::HTTP::Post.new(uri.path)
  req["Content-Type"] = "application/json"
  req["Accept"]       = "application/json"
  req.body = body

  resp = http.request(req)
  unless resp.is_a?(Net::HTTPSuccess)
    raise "Bootstrap returned #{resp.code}: #{resp.body}"
  end

  JSON.parse(resp.body)
end

if __FILE__ == $PROGRAM_NAME
  if ARGV.empty?
    warn "usage: #{$PROGRAM_NAME} <computer_name> [key=value ...]"
    warn ""
    warn "Optional env vars: BOOTSTRAP_URL, Z2LS_MAX_USES, Z2LS_EXPIRES_IN, Z2LS_ZONE"
    exit 2
  end

  computer_name = ARGV.shift
  metadata = {}
  ARGV.each do |kv|
    k, v = kv.split("=", 2)
    metadata[k] = v if k && v
  end

  bootstrap_url = ENV.fetch("BOOTSTRAP_URL", "http://127.0.0.1:8000")
  max_uses      = ENV["Z2LS_MAX_USES"]   && Integer(ENV["Z2LS_MAX_USES"])
  expires_in    = ENV["Z2LS_EXPIRES_IN"] # nil → server default (24h)
  zone          = ENV["Z2LS_ZONE"]

  result = request_enrollment_token(
    bootstrap_url: bootstrap_url,
    computer_name: computer_name,
    metadata:      metadata,
    max_uses:      max_uses,
    expires_in:    expires_in,
    zone:          zone
  )

  puts JSON.pretty_generate(result)
end
