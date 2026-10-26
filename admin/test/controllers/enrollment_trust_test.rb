# frozen_string_literal: true

require "test_helper"

# What a panel-minted token carries, and what the one-time result page tells the user
# (docs/admin-panel/PLAN-enrollment-token-trust.md).
class EnrollmentTrustTest < ActionDispatch::IntegrationTest
  NS_KEY = "58" * 32
  RELAY = "Rk3" + "a" * 45

  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary
    @zone.update!(enrollment_secret_ct: "ab" * 32, relay_secret_ct: RELAY, ns_pubkey_hex: NS_KEY)
    @alice = @zone.users.create!(username: "alice", display_name: "Alice", role: "user", status: "active")
  end

  def mint(extra = {})
    post "/enrollments", params: { enrollment: { kind: "user_device", user_id: @alice.id, expiry_hours: "1",
                                                 device_name: "alice-mbp", embed_relay_secret: "1" }.merge(extra) }
    assert_response :redirect
    @zone.enrollments.order(:id).last
  end

  test "the token carries the relay secret, the NS key and the callback, MAC-valid" do
    tok = Ztlp::TokenMinter.parse(Ztlp::TokenMinter.from_uri(mint.token_uri_ct))
    assert_equal RELAY, tok[:relay_secret]
    assert_equal NS_KEY, tok[:ns_key_hex]
    assert_match %r{/api/enrollment/confirm\z}, tok[:callback_url]
    assert_equal @zone.name, tok[:zone]
    assert_equal @zone.ns_addr, tok[:ns_addr]
    bin = Ztlp::TokenMinter.from_uri(@zone.enrollments.order(:id).last.token_uri_ct)
    assert Ztlp::TokenMinter.valid_mac?(bin, [ @zone.enrollment_secret_ct ].pack("H*"))
  end

  test "unchecking embed leaves the relay secret out but keeps the NS key" do
    tok = Ztlp::TokenMinter.parse(Ztlp::TokenMinter.from_uri(mint(embed_relay_secret: "0").token_uri_ct))
    assert_nil tok[:relay_secret]
    assert_equal NS_KEY, tok[:ns_key_hex]
  end

  test "the setup command is the token plus the device name; the secret is no longer on the command line" do
    mint
    follow_redirect!
    assert_select "pre.code-box", text: /\Aztlp setup --token "ztlp:\/\/enroll\/[A-Za-z0-9_-]+" --name "alice-mbp"\z/
    assert_no_match(/--relay-secret/, response.body)
    refute_includes response.body, RELAY, "the secret is inside the token, never printed beside it"
    assert_select "[data-relay-warning]", /inside the token/i
    assert_select "[data-ns-trust]", /name server/i
  end

  test "a zone without an NS key says the device will fall back to first-use pins" do
    @zone.update!(ns_pubkey_hex: nil)
    tok = Ztlp::TokenMinter.parse(Ztlp::TokenMinter.from_uri(mint.token_uri_ct))
    assert_nil tok[:ns_key_hex]
    follow_redirect!
    assert_select "[data-ns-trust-missing]", /no name server key/i
  end

  test "the audit row never holds the relay secret or the token" do
    mint
    details = AuditLog.where(action: "enrollment.mint").last.details.to_json
    refute_includes details, RELAY
    refute_includes details, "ztlp://enroll/"
    assert_includes details, "ns_key"
  end

  test "a user+device token requires a device name (the panel finds the device by it)" do
    post "/enrollments", params: { enrollment: { kind: "user_device", user_id: @alice.id, expiry_hours: "1",
                                                 device_name: "" } }
    assert_response :unprocessable_entity
    assert_match(/device name/i, response.body)
  end

  test "a device name that is not a valid short label is refused" do
    [ "Alice MBP", "alice-mbp.trs.ztlp", "-x", "a" * 64 ].each do |bad|
      post "/enrollments", params: { enrollment: { kind: "user_device", user_id: @alice.id, expiry_hours: "1",
                                                   device_name: bad } }
      assert_response :unprocessable_entity, bad
    end
  end
end

class ZoneNsKeyTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary
  end

  test "the NS key must be 64 hex characters and is stored lowercase" do
    @zone.ns_pubkey_hex = "AB" * 32
    assert @zone.valid?
    assert_equal "ab" * 32, @zone.ns_pubkey_hex
    [ "ab" * 31, "zz" * 32 ].each do |bad|
      @zone.ns_pubkey_hex = bad
      refute @zone.valid?, bad
    end
    @zone.ns_pubkey_hex = ""
    assert @zone.valid?
    assert_nil @zone.ns_pubkey_hex
  end

  test "the zone page shows the NS key and an operator can set it" do
    get "/zone"
    assert_select "form[action=?]", "/zone/ns_key"
    patch "/zone/ns_key", params: { ns_pubkey_hex: "cd" * 32 }
    assert_redirected_to "/zone"
    assert_equal "cd" * 32, @zone.reload.ns_pubkey_hex
    assert AuditLog.where(action: "zone.ns_key").exists?
    follow_redirect!
    assert_includes response.body, "cd" * 32
  end

  test "an invalid NS key is refused with a message" do
    patch "/zone/ns_key", params: { ns_pubkey_hex: "nope" }
    assert_redirected_to "/zone"
    assert_nil @zone.reload.ns_pubkey_hex
    follow_redirect!
    assert_match(/64 hex/i, response.body)
  end

  test "a helpdesk admin cannot change the NS key" do
    helpdesk, seed = make_admin(role: "helpdesk", username: "hd")
    sign_in_as(helpdesk, seed)
    patch "/zone/ns_key", params: { ns_pubkey_hex: "cd" * 32 }
    assert_includes [ 302, 403 ], response.status
    assert_nil @zone.reload.ns_pubkey_hex
  end

  test "a new zone can be created with its NS key" do
    post "/zones", params: { zone: { name: "new.ztlp", ns_addr: "1.2.3.4:23096", relay_addrs_text: "1.2.3.4:23095",
                                     ns_pubkey_hex: "ef" * 32 } }
    assert_equal "ef" * 32, Zone.find_by(name: "new.ztlp")&.ns_pubkey_hex
  end
end
