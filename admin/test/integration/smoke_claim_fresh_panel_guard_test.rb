# frozen_string_literal: true

require "test_helper"

# smoke-claim-login.rb's failure shape, hermetically: on an already-claimed
# panel /claim bounces (302), and the claim POST with a regular (non-forced)
# code cannot create the smoke admin — the script's "GET /claim -> 200 (fresh
# panel)" guard trips and it must NOT pass against a stale DB. Pins both legs
# so the smoke cannot silently "pass" on a claimed panel.
class SmokeClaimFreshPanelGuardTest < ActionDispatch::IntegrationTest
  # The smoke's happy path: claim form + signed claim POST (exactly the
  # fields smoke-claim-login.rb posts). In the test env, forgery protection
  # is off (config.action_controller.allow_forgery_protection = false), so
  # form_with emits no authenticity_token hidden field — the POST succeeds
  # without one. The live smoke runs against a production container where
  # forgery protection IS on and the token is present.
  def perform_claim(code, seed, pub, username)
    now = Time.current.to_i
    body = { "claim_code" => code, "username" => username, "display_name" => username.capitalize,
             "email" => "", "pubkey_hex" => pub, "timestamp" => now }
    sig = Ztlp::Ed25519.sign(seed_hex: seed, message: Ztlp::Ed25519.claim_message(body))
    post "/claim", params: { claim: body.merge("signature" => sig) }
  end

  test "fresh panel: claim page renders and a signed claim POST succeeds" do
    get "/claim"
    assert_response :success
    # The claim form must be present (form_with emits the form tag).
    assert_select "form[action=?]", claim_path

    seed, pub = Ztlp::Ed25519.generate
    perform_claim(Claim.issue!, seed, pub, "fresh")
    assert_response :redirect
    follow_redirect!
    assert_select "h1", "Overview"
    assert_equal 1, Admin.where(username: "fresh").count
  end

  test "already-claimed panel: the smoke's fresh-panel guard trips (no smoke admin, no pass)" do
    # Establish the claimed state via the smoke's own happy path.
    get "/claim"
    assert_response :success
    seed, pub = Ztlp::Ed25519.generate
    perform_claim(Claim.issue!, seed, pub, "steve")
    assert_response :redirect
    follow_redirect!
    assert_equal 1, Admin.count

    # Replay what smoke-claim-login.rb does against the STALE panel:
    # GET /claim expecting 200. The script aborts when it is not 200.
    get "/claim"
    assert_redirected_to root_path
    assert_equal 0, Admin.where(username: "smoke").count

    # Even a signed POST with a fresh code must NOT create the smoke admin
    # (ensure_unclaimed bounces before the code check): 302 to root, never
    # the claim success path.
    seed2, pub2 = Ztlp::Ed25519.generate
    now = Time.current.to_i
    body2 = { "claim_code" => Claim.issue!, "username" => "smoke", "display_name" => "Smoke",
              "email" => "", "pubkey_hex" => pub2, "timestamp" => now }
    sig2 = Ztlp::Ed25519.sign(seed_hex: seed2, message: Ztlp::Ed25519.claim_message(body2))
    post "/claim", params: { claim: body2.merge("signature" => sig2) }
    assert_redirected_to root_path # ensure_unclaimed bounce, not a claim success
    assert_equal 0, Admin.where(username: "smoke").count
    assert_equal 1, Admin.count
  end
end
