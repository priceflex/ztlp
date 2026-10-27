# frozen_string_literal: true

# Gap 3 of the whoami UI walkthrough: show the gateway's QUIC certificate pin on the service page.
#
# The pin is the `quic_cert_sha256` the gateway publishes in its own SVC record. Clients enrolled with a
# v0.5 token trust it because the NAME SERVER signed that record, so the panel reads it the same way
# (NsClient.query_verified with the zone's NS key) and says plainly when it could not check it.
require "test_helper"

class GatewayPinTest < ActionDispatch::IntegrationTest
  NS_KEY = "58" * 32
  PIN = "582ae789" + "0f" * 28
  NEW_PIN = "77" * 32

  setup do
    @zone = Zone.primary
    @zone.update!(ns_addr: "203.0.113.10:23096", relay_addrs: [ "203.0.113.10:23095" ], ns_pubkey_hex: NS_KEY)
    @gw = @zone.gateways.create!(name: "whoami", kind: "rust_listen", status: "planned", inject_headers: true,
                                 header_secret_ct: "ab" * 32, policy_file: true)
    @svc = @gw.services.create!(name: "whoami", backend: "127.0.0.1:8095", protocol: "http")
    Ztlp::ServiceRegistrar.stubs(:lookup).returns({ name: @gw.ns_name, data: { "node_id" => "b1" * 16,
                                                                               "quic_cert_sha256" => "99" * 32 } })
    admin, seed = make_admin(role: "admin", username: "admin-1")
    sign_in_as(admin, seed)
  end

  def signed_svc(pin)
    { name: @gw.ns_name, type: "svc", data: { "quic_cert_sha256" => pin }, signer: NS_KEY }
  end

  test "Check now stores the pin from the name server's signed SVC record" do
    Ztlp::NsClient.expects(:query_verified)
                  .with { |addr, _t, **kw| addr == @zone.ns_addr && kw[:name] == @gw.ns_name && kw[:type] == "svc" && kw[:trusted_keys] == [ NS_KEY ] }
                  .returns(signed_svc(PIN))
    post check_gateway_service_path(@svc)
    @gw.reload
    assert_equal PIN, @gw.quic_cert_sha256
    assert @gw.quic_cert_verified
    assert_not_nil @gw.quic_cert_seen_at
  end

  test "the service page shows the full pin and that it came from the signed record" do
    @gw.update!(status: "online", quic_cert_sha256: PIN, quic_cert_verified: true, quic_cert_status: "verified",
                quic_cert_seen_at: Time.current)
    get service_path(@svc)
    assert_select "[data-gateway-pin]", text: /#{PIN}/
    assert_match(/signed by the name server/i, response.body)
  end

  test "without a zone NS key the pin comes from the admin API and is marked not signature-checked" do
    @zone.update!(ns_pubkey_hex: nil)
    Ztlp::NsClient.expects(:query_verified).never
    post check_gateway_service_path(@svc)
    @gw.reload
    assert_equal "99" * 32, @gw.quic_cert_sha256
    refute @gw.quic_cert_verified
    get service_path(@svc)
    assert_match(/not signature-checked/i, response.body)
  end

  test "a signed record that does not verify stores no pin and says so" do
    Ztlp::NsClient.stubs(:query_verified).raises(Ztlp::NsClient::UntrustedAnswer, "record signed by an untrusted key")
    post check_gateway_service_path(@svc)
    @gw.reload
    assert_nil @gw.quic_cert_sha256
    refute @gw.quic_cert_verified
    assert_equal "online", @gw.status, "the gateway is still on the name server"
    get service_path(@svc)
    assert_match(/did not verify/i, response.body)
  end

  test "a changed pin keeps the previous one so a certificate change is visible" do
    @gw.update!(status: "online", quic_cert_sha256: PIN, quic_cert_verified: true, quic_cert_seen_at: 1.day.ago)
    Ztlp::NsClient.stubs(:query_verified).returns(signed_svc(NEW_PIN))
    post check_gateway_service_path(@svc)
    @gw.reload
    assert_equal NEW_PIN, @gw.quic_cert_sha256
    assert_equal PIN, @gw.quic_cert_previous_sha256
    assert_not_nil @gw.quic_cert_changed_at
    get service_path(@svc)
    assert_match(/changed/i, response.body)
    assert_includes response.body, PIN
  end

  test "the same pin again is not a change" do
    @gw.update!(status: "online", quic_cert_sha256: PIN, quic_cert_verified: true, quic_cert_seen_at: 1.day.ago)
    Ztlp::NsClient.stubs(:query_verified).returns(signed_svc(PIN))
    post check_gateway_service_path(@svc)
    assert_nil @gw.reload.quic_cert_previous_sha256
  end

  test "a pin that is not 64 hex characters is ignored" do
    Ztlp::NsClient.stubs(:query_verified).returns(signed_svc("<script>alert(1)</script>"))
    post check_gateway_service_path(@svc)
    assert_nil @gw.reload.quic_cert_sha256
    get service_path(@svc)
    assert_no_match(/<script>alert/, response.body)
  end

  test "an NS timeout on the signed lookup leaves the stored pin alone and does not 500" do
    @gw.update!(status: "online", quic_cert_sha256: PIN, quic_cert_verified: true, quic_cert_seen_at: 1.day.ago)
    Ztlp::NsClient.stubs(:query_verified).raises(Ztlp::NsClient::NsError.new(0x0C, "timeout"))
    post check_gateway_service_path(@svc)
    assert_redirected_to service_path(@svc)
    assert_equal PIN, @gw.reload.quic_cert_sha256
  end

  test "the status job records pins too" do
    Ztlp::NsClient.stubs(:query_verified).returns(signed_svc(PIN))
    GatewayStatusJob.perform_now
    assert_equal PIN, @gw.reload.quic_cert_sha256
  end
end
