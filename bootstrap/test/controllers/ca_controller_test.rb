# frozen_string_literal: true

require "test_helper"

class CaControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
  end

  test "GET /networks/:id/ca renders CA show page when initialized" do
    CaService.any_instance.stubs(:status).returns({
      initialized: true,
      zone: @network.zone,
      root_key: "test-root-key-fingerprint",
      created_at: Time.current.iso8601,
      active_certs: 5,
      expiring_soon: 1
    })

    get network_ca_path(@network)
    assert_response :success
  end

  test "CA show view renders TLS configuration section when initialized" do
    CaService.any_instance.stubs(:status).returns({
      initialized: true,
      zone: @network.zone,
      root_key: "test-root-key",
      created_at: Time.current.iso8601,
      active_certs: 3,
      expiring_soon: 0
    })

    get network_ca_path(@network)
    assert_response :success
    assert_match /TLS Configuration/, response.body
    assert_match /Agent-Side TLS/, response.body
    assert_match /Internal TLS/, response.body
    assert_match /Signing Oracle/, response.body
  end

  test "CA show view renders software key warning when initialized" do
    CaService.any_instance.stubs(:status).returns({
      initialized: true,
      zone: @network.zone,
      root_key: "test-root-key",
      created_at: Time.current.iso8601,
      active_certs: 2,
      expiring_soon: 0
    })

    get network_ca_path(@network)
    assert_response :success
    assert_match /Root CA Key Stored on Filesystem/, response.body
    assert_match /Signing Oracle documentation/, response.body
  end

  test "CA show view does not render warning or TLS section when not initialized" do
    CaService.any_instance.stubs(:status).returns({
      initialized: false,
      zone: @network.zone
    })

    get network_ca_path(@network)
    assert_response :success
    assert_no_match /Root CA Key Stored on Filesystem/, response.body
    assert_match /No Certificate Authority/, response.body
  end
end
