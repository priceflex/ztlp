# frozen_string_literal: true
#
# scripts/smoke-claim-login.rb (Slice 12 local smoke) — claim the panel over the
# production entrypoint using the REAL Ed25519 claim path (form POST /claim
# WITH a signature; Claim.perform! verifies it when present), then prove the
# challenge/verify LOGIN round-trip against the same container, asserting the
# signed-in Overview at the end.
#
# Run this file with `rails runner` so Bundler loads the exact locked gem set
# (a bare `ruby scripts/smoke-claim-login.rb` hits a default-gem version clash:
# securerandom 0.2.2 vs the Gemfile's 0.4.1). The claim flow itself is the
# subject of the smoke, so it must run under the app's real boot path.
#
#   docker exec <web> /rails/bin/docker-entrypoint ./bin/rails runner scripts/smoke-claim-login.rb
#
# The claim code it mints is single-use and the smoke DB is destroyed after the
# run (`docker compose -p admintest down -v`); it is printed to stdout and thus
# into the STATUS evidence, which is fine because it is not a standing
# credential.

require "net/http"
require "json"

# The session cookie the app sets on GET /claim must ride into the claim POST
# (the CSRF token binds to the session). Net::HTTP does not follow Set-Cookie
# across requests, so capture it explicitly and send it back.
SESSION_COOKIE = [nil]

BASE = ENV.fetch("SMOKE_BASE", "http://127.0.0.1:3000")
HOST = URI(BASE).host

def http_get(path)
  uri = URI("#{BASE}#{path}")
  req = Net::HTTP::Get.new(uri)
  req["Cookie"] = SESSION_COOKIE[0] if SESSION_COOKIE[0]
  resp = Net::HTTP.start(uri.hostname, uri.port) { |h| h.request(req) }
  store_cookie(resp)
  [ resp.code.to_i, resp.body, resp ]
end

def http_post_form(path, fields)
  uri = URI("#{BASE}#{path}")
  req = Net::HTTP::Post.new(uri)
  # set_form_urlencoded does not exist on Ruby 3.2's Net::HTTP (added later);
  # set_form_data sends the same application/x-www-form-urlencoded body.
  req.set_form_data(fields)
  req["Cookie"] = SESSION_COOKIE[0] if SESSION_COOKIE[0]
  resp = Net::HTTP.start(uri.hostname, uri.port) { |h| h.request(req) }
  store_cookie(resp)
  [ resp.code.to_i, resp.body, resp ]
end

def http_post_json(path, obj)
  uri = URI("#{BASE}#{path}")
  req = Net::HTTP::Post.new(uri)
  req["Content-Type"] = "application/json"
  req.body = JSON.generate(obj)
  req["Cookie"] = SESSION_COOKIE[0] if SESSION_COOKIE[0]
  resp = Net::HTTP.start(uri.hostname, uri.port) { |h| h.request(req) }
  store_cookie(resp)
  [ resp.code.to_i, resp.body, resp ]
end

# The claim POST resets the session (sign_in! -> reset_session), so the cookie
# VALUE changes on every response; always take the newest one.
def store_cookie(resp)
  Array(resp.get_fields("Set-Cookie")).each do |c|
    SESSION_COOKIE[0] = c.split(";").first if c.start_with?("_ztlp_admin_session=")
  end
end

def csrf_of(body)
  m = body[/name="authenticity_token"[^>]*value="([^"]+)"/, 1]
  raise "no authenticity token on the page" if m.nil?

  m
end

# ---- 1. mint a claim code + generate the admin keypair ---------------------
claim_code = Claim.issue!
seed, pub = Ztlp::Ed25519.generate
puts "minted a single-use claim code; generated the smoke admin's Ed25519 keypair"

now = Time.current.to_i
body = {
  "claim_code" => claim_code, "username" => "smoke", "display_name" => "Smoke",
  "email" => "", "pubkey_hex" => pub, "timestamp" => now
}
sig = Ztlp::Ed25519.sign(seed_hex: seed, message: Ztlp::Ed25519.claim_message(body))

# ---- 2. claim over the browser form (signature present -> verified) --------
code, claim_page, = http_get("/claim")
abort "GET /claim -> HTTP #{code}" unless code == 200
token = csrf_of(claim_page)

code, resp, resp_obj = http_post_form(
  "/claim",
  {
    "claim[claim_code]" => claim_code,
    "claim[username]" => "smoke",
    "claim[display_name]" => "Smoke",
    "claim[email]" => "",
    "claim[pubkey_hex]" => pub,
    "claim[timestamp]" => now,
    "claim[signature]" => sig,
    "authenticity_token" => token
  }
)
abort "claim POST -> HTTP #{code}: #{resp[0, 200]}" unless code == 302
redirect = resp_obj["Location"].to_s
abort "claim did not redirect to a path (got #{redirect})" unless redirect.start_with?("/")

code, overview, = http_get("/")
abort "GET / after claim -> HTTP #{code}" unless code == 200
abort "Overview missing the Setup checklist" unless overview.include?("Setup checklist")
abort "Overview missing the tallies" unless overview.include?("USERS")
puts "PASS: signed claim POST -> Overview with Setup checklist"

# ---- 3. challenge/verify LOGIN round-trip (the panel's real login path) ----
code, resp, = http_post_json("/auth/challenge", "pubkey_hex" => pub)
abort "challenge -> HTTP #{code}" unless code == 200
nonce = JSON.parse(resp).fetch("nonce")
abort "challenge returned no 64-hex nonce" unless nonce.to_s.length == 64

lsig = Ztlp::Ed25519.sign(seed_hex: seed, message: Ztlp::Ed25519.login_message(HOST, nonce))

code, resp, = http_post_json(
  "/auth/verify",
  "pubkey_hex" => pub, "nonce" => nonce, "signature" => lsig
)
abort "verify -> HTTP #{code}: #{resp[0, 200]}" unless code == 200
login_url = JSON.parse(resp).fetch("login_url")
abort "verify returned no login_url" unless login_url.present?

path = login_url.start_with?("http") ? URI(login_url).path : login_url
code, page, = http_get(path)
page_ok = (code == 200 && page.include?("Overview"))
abort "login exchange -> HTTP #{code}, no signed-in Overview" unless page_ok
puts "PASS: challenge/verify -> session exchange -> signed-in Overview (host #{HOST})"

puts "smoke-claim-login: all steps passed"
