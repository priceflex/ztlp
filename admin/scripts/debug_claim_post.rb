# frozen_string_literal: true
# DEBUG probe: replicate smoke-claim-login.rb's claim POST and dump the
# response body + request state. Run:
#   docker exec ztlp-admin-web-smoke2 /rails/bin/docker-entrypoint \
#     ./bin/rails runner scripts/debug_claim_post.rb
require "net/http"
require "json"

BASE = "http://127.0.0.1:3000"
SESSION_COOKIE = [nil]

def store_cookie(resp)
  Array(resp.get_fields("Set-Cookie")).each do |c|
    SESSION_COOKIE[0] = c.split(";").first if c.start_with?("_ztlp_admin_session=")
  end
end

uri = URI("#{BASE}/claim")
req = Net::HTTP::Get.new(uri)
resp = Net::HTTP.start(uri.hostname, uri.port) { |h| h.request(req) }
store_cookie(resp)
body = resp.body
tok = body[/name="authenticity_token"[^>]*value="([^"]+)"/, 1]
puts "GET /claim -> #{resp.code}; cookie present: #{!SESSION_COOKIE[0].nil?}; token: #{tok&.length}"

claim_code = Claim.issue!
seed, pub = Ztlp::Ed25519.generate
now = Time.current.to_i
b = { "claim_code" => claim_code, "username" => "smoke", "display_name" => "Smoke",
      "email" => "", "pubkey_hex" => pub, "timestamp" => now }
sig = Ztlp::Ed25519.sign(seed_hex: seed, message: Ztlp::Ed25519.claim_message(b))

fields = {
  "claim[claim_code]" => claim_code, "claim[username]" => "smoke",
  "claim[display_name]" => "Smoke", "claim[email]" => "",
  "claim[pubkey_hex]" => pub, "claim[timestamp]" => now.to_s,
  "claim[signature]" => sig, "authenticity_token" => tok
}
uri2 = URI("#{BASE}/claim")
req2 = Net::HTTP::Post.new(uri2)
fields.each { |k, v| req2[k] = v.to_s }
req2["Cookie"] = SESSION_COOKIE[0]
puts "POST cookie: #{SESSION_COOKIE[0][0, 40]}..."
resp2 = Net::HTTP.start(uri2.hostname, uri2.port) { |h| h.request(req2) }
puts "POST /claim -> #{resp2.code}"
puts "Location: #{resp2['Location']}"
puts "body (first 500): #{resp2.body[0, 500]}"
