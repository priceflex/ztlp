# frozen_string_literal: true

# §5 box 3 policy legs, run LIVE inside the web container against the smoke
# panel (same Net::HTTP shape as smoke-claim-login.rb — the Integration
# session can't take a raw request body on this Rails version):
#
#   1. create the smoke app + group rule (group rule = the smokegrp created
#      by smoke-directory.sh's step 2; if absent, create it here)
#   2. assert the RENDERED policy.toml of the gateway contains
#      `group:<g>.groups.<zone>` (the §5 box's exact requirement)
#   3. create the user's device, POST /policies/test (the REAL widget action,
#      real signed session) -> expect `allow`
#   4. remove the group membership, POST the same check -> expect `deny`
#
# Prints one PASS/FAIL line per step; exits non-zero on the first FAIL.
# Run:  docker cp scripts/smoke-policy-toml.rb ztlp-admin-web:/rails/scripts/
#       docker exec ztlp-admin-web /rails/bin/docker-entrypoint \
#         ./bin/rails runner scripts/smoke-policy-toml.rb
require "net/http"
require "json"

BASE = ENV.fetch("SMOKE_BASE", "http://127.0.0.1:3000")
URI_REF = URI(BASE)
COOKIE = [ nil ]

def smoke_fail(msg)
  puts "FAIL: #{msg}"
  exit 1
end

def store_cookie(resp)
  Array(resp.get_fields("Set-Cookie")).each do |c|
    COOKIE[0] = c.split(";").first if c.start_with?("_ztlp_admin_session=")
  end
end

def http_request(method, path, body: nil, json: nil, follow: true)
  uri = URI_REF.dup
  uri.path = path
  uri.query = URI.encode_www_form(body) if body
  req =
    case method
    when :get then Net::HTTP::Get.new(uri)
    when :post
      r = Net::HTTP::Post.new(uri)
      r.set_form_data(body) if body
      r
    end
  if json
    req["Content-Type"] = "application/json"
    req.body = JSON.generate(json)
  end
  req["Cookie"] = COOKIE[0] if COOKIE[0]
  resp = Net::HTTP.start(uri.hostname, uri.port) { |h| h.request(req) }
  store_cookie(resp)
  if follow
    5.times do
      break unless %w[301 302].include?(resp.code)
      loc = resp["Location"]
      break unless loc
      loc_uri = URI(loc)
      g = Net::HTTP::Get.new(loc_uri)
      g["Cookie"] = COOKIE[0] if COOKIE[0]
      resp = Net::HTTP.start(loc_uri.hostname, loc_uri.port) { |h| h.request(g) }
      store_cookie(resp)
    end
  end
  [ resp.code.to_i, resp.body.to_s, resp ]
end

# -- dedicated signed-in admin (real challenge/verify endpoints) -------------
seed, pub = Ztlp::Ed25519.generate
u = "smokepolicy-#{SecureRandom.hex(4)}"
admin = Admin.create!(username: u, display_name: "Smoke Policy", pubkey_hex: pub, role: "super_admin")

code, body, = http_request(:post, "/auth/challenge", json: { "pubkey_hex" => admin.pubkey_hex }, follow: false)
nonce = JSON.parse(body)["nonce"] if code == 200
smoke_fail "challenge: HTTP #{code} body=#{body[0, 200]}" if nonce.to_s.length != 64

host = URI_REF.host
# login_url is generated with the container's default_url_options (empty here:
# bare host "127.0.0.1", no port). The controller verifies against the
# request's Host header (127.0.0.1:3000), so sign with the host the verify
# request carries — the same convention smoke-directory.sh uses.
sig = Ztlp::Ed25519.sign(seed_hex: seed, message: Ztlp::Ed25519.login_message("127.0.0.1", nonce))
code, body, = http_request(:post, "/auth/verify",
                           json: { "pubkey_hex" => admin.pubkey_hex, "nonce" => nonce, "signature" => sig },
                           follow: false)
login_url = JSON.parse(body)["login_url"] if code == 200
smoke_fail "verify: HTTP #{code} body=#{body[0, 200]}" if login_url.to_s.empty?

# The /auth/session token exchange 302s with a Set-Cookie to a ROOT url; the
# redirect's flash then ROTATES the session cookie (the same documented
# rotation smoke-claim-login.rb handles). Follow it and keep the NEWEST
# cookie — the one bound to the session that renders /policies and carries
# the csrf-token the Test access widget sends.
code, body, = http_request(:get, login_url.to_s.sub(%r{\A#{BASE}}, ""))
smoke_fail "session exchange: HTTP #{code}" unless code == 200
root_code, _root_body, = http_request(:get, "/")
smoke_fail "post-exchange root: HTTP #{root_code}" unless root_code == 200
puts "PASS: signed in over the real challenge/verify path"

# -- group + user (reuse smoke-directory.sh's rows when present) -------------
zone = Zone.primary
group = zone.groups.find_by(name: "smokegrp") || zone.groups.create!(name: "smokegrp", description: "smoke policy group")
user = zone.users.find_by(username: "smoketest") || zone.users.create!(username: "smoketest", display_name: "Smoke Test", role: "user", kind: "person")
group.users << user if group.users.exclude?(user)

# -- app + group rule ---------------------------------------------------------
# The smoke panel has no gateway rows yet (gateway rows are created through the
# applications flow; the fresh smoke DB starts empty), so create the zone's
# gateway the same way the operator would: name drives ns_name <name>.<zone>.
gw = zone.gateways.order(:name).first || zone.gateways.create!(name: "smokegw", kind: "rust_listen", status: "planned")
app = gw.applications.find_by(name: "smokeapp") ||
      gw.applications.create!(name: "smokeapp", backend: "10.0.0.9:8000", protocol: "http", min_assurance: 1)
rule = app.policy_rules.find_by(subject_type: "group", subject_id: group.id)
rule ||= app.policy_rules.create!(subject_type: "group", subject_id: group.id, subject_value: group.ns_name, position: 0)
app.update!(enabled: true) unless app.enabled?

toml = Ztlp::PolicyRenderer.render(gw)
needle = "group:#{group.ns_name}"
if toml.include?(needle)
  puts "PASS: rendered policy.toml contains #{needle}"
else
  puts "FAIL: rendered policy.toml missing #{needle} (document head:\n#{toml[0, 600]})"
  exit 1
end

# -- device + the real Test access action ------------------------------------
device = user.devices.order(:id).first ||
         zone.devices.create!(name: "smoketest-pc", user: user, node_id_hex: "11" * 16,
                              noise_pubkey_hex: "22" * 32, key_source: "tpm", assurance: 2, status: "enrolled")

# The Test access widget posts with the csrf-token from the /policies
# meta tag (directory.js reads the same meta tag in the browser).
_page = http_request(:get, "/policies")[1]
token = _page[/<meta[^>]*name="csrf-token"[^>]*content="([^"]+)"/, 1]
smoke_fail "no csrf-token meta on /policies" if token.to_s.empty?

def audit_decision
  AuditLog.where(action: "policy.test").order(:id).last&.details&.dig("decision")
end

# The JSON body must be `params[:device_id]`/`params[:application_id]`.
# NOTE: a POST with `Content-Type: application/json` is NOT recognized as a
# JSON request by Rails (it needs an Accept: application/json header from the
# client, or the body must be form-encoded for `request.format.json?` to be
# true in this app). The HTML form variant re-renders the page with the
# decision inline; the audit row (policy.test, target = the application) is
# the ground truth for the decision either way.
def test_post
  body = JSON.generate({ "device_id" => DEVICE_ID, "application_id" => APP_ID })
  uri = URI("#{BASE}/policies/test")
  req = Net::HTTP::Post.new(uri)
  req["Content-Type"] = "application/json"
  req["X-CSRF-Token"] = CSRF_TOKEN
  req["Cookie"] = COOKIE[0] if COOKIE[0]
  req.body = body
  resp = Net::HTTP.start(uri.hostname, uri.port) { |h| h.request(req) }
  store_cookie(resp)
  [ resp.code.to_i, resp.body.to_s ]
end

DEVICE_ID = device.id
APP_ID = app.id
CSRF_TOKEN = token

code, body = test_post
decision1 = body[/"decision"\s*:\s*"([a-z_]+)"/, 1] || audit_decision
if code == 200 && decision1 == "allow"
  puts "PASS: test-access (member of #{group.name}) -> allow (audit: #{decision1})"
else
  puts "DEBUG body head: #{body[0, 300]}"
  smoke_fail "test-access before removal: HTTP #{code} body=#{body[0, 400]}"
end

group.users.delete(user)

code, body = test_post
decision2 = body[/"decision"\s*:\s*"([a-z_]+)"/, 1] || audit_decision
if code == 200 && decision2 == "deny"
  puts "PASS: test-access after removing membership -> deny (audit: #{decision2})"
else
  smoke_fail "test-access after removal: HTTP #{code} body=#{body[0, 400]}"
end

# restore the membership so later smokes see the same shape
group.users << user

puts "== smoke-policy-toml done"
