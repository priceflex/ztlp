#!/usr/bin/env ruby
# frozen_string_literal: true

# ZTLP Bootstrap Z2LS reference client (Ruby).
#
# Self-contained example of how to sign and POST a request to the
# ZTLP-secured Bootstrap API. Designed to be copied into a Z2LS
# codebase verbatim and adapted.
#
# Documented in detail in `bootstrap/docs/z2ls_enrollment_runbook.md`.
#
# Usage:
#
#   export BOOTSTRAP_URL="https://bootstrap.acme.ztlp"
#   export ZTLP_ZONE="acme.ztlp"
#   export ZTLP_CLIENT="z2ls.acme"
#   export ZTLP_HMAC_SECRET_ACME_ZTLP="<64-char hex OR raw bytes>"
#
#   ruby bootstrap/script/z2ls_request_token.rb alice-laptop os=macOS

require "digest"
require "json"
require "net/http"
require "openssl"
require "uri"

# Match the Bootstrap authenticator's decoding rule: a 64-character
# pure-hex string is decoded to its 32 raw bytes; anything else is
# returned as-is.
def decode_secret(secret)
  if secret.is_a?(String) && secret.length == 64 && secret.match?(/\A[0-9a-fA-F]+\z/)
    [secret].pack("H*")
  else
    secret
  end
end

# Return the hex HMAC-SHA256 for a ZTLP-secured Bootstrap request.
# See `bootstrap/docs/api_v1_ztlp_secured.md` § "Request signing"
# for the canonical 6-line message.
def ztlp_sign(method:, path:, zone:, client:, timestamp:, body:, secret:)
  key = decode_secret(secret)
  body_str = body.is_a?(String) ? body : body.to_s
  body_digest = Digest::SHA256.hexdigest(body_str)

  message = [
    method.to_s.upcase,
    path,
    zone,
    client,
    timestamp.to_s,
    body_digest
  ].join("\n")

  OpenSSL::HMAC.hexdigest("SHA256", key, message)
end

def request_enrollment_token(bootstrap_url:, zone:, client:, secret:,
                             computer_name:, metadata: nil, timeout: 10)
  path = "/api/v1/enrollment_tokens"
  payload = { computer_name: computer_name }
  payload[:metadata] = metadata if metadata && !metadata.empty?
  body = payload.to_json

  ts = Time.now.to_i
  sig = ztlp_sign(
    method: "POST", path: path, zone: zone, client: client,
    timestamp: ts, body: body, secret: secret
  )

  uri = URI(bootstrap_url.chomp("/") + path)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  http.open_timeout = 5
  http.read_timeout = timeout

  req = Net::HTTP::Post.new(uri.path)
  req["Content-Type"]     = "application/json"
  req["X-ZTLP-Zone"]      = zone
  req["X-ZTLP-Client"]    = client
  req["X-ZTLP-Timestamp"] = ts.to_s
  req["X-ZTLP-Signature"] = sig
  req.body = body

  resp = http.request(req)
  unless resp.is_a?(Net::HTTPSuccess)
    raise "Bootstrap returned #{resp.code}: #{resp.body}"
  end

  JSON.parse(resp.body)
end

# Look up the per-zone secret env var by the same slugify rule
# the gateway/relay use.
def env_secret_for_zone(zone)
  slug = zone.upcase.gsub(/[^A-Z0-9]+/, "_").sub(/\A_/, "").sub(/_\z/, "")
  ENV.fetch("ZTLP_HMAC_SECRET_#{slug}")
end

if __FILE__ == $PROGRAM_NAME
  if ARGV.empty?
    warn "usage: #{$PROGRAM_NAME} <computer_name> [key=value ...]"
    exit 2
  end

  computer_name = ARGV.shift
  bootstrap_url = ENV.fetch("BOOTSTRAP_URL", "http://localhost:3000")
  zone   = ENV.fetch("ZTLP_ZONE")
  client = ENV.fetch("ZTLP_CLIENT")
  secret = env_secret_for_zone(zone)

  metadata = {}
  ARGV.each do |kv|
    k, v = kv.split("=", 2)
    metadata[k] = v if k && v
  end

  result = request_enrollment_token(
    bootstrap_url: bootstrap_url,
    zone:          zone,
    client:        client,
    secret:        secret,
    computer_name: computer_name,
    metadata:      metadata
  )

  puts JSON.pretty_generate(result)
end
