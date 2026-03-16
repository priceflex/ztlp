# frozen_string_literal: true

require "test_helper"

class ZtlpConnectivityTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @ns_machine = machines(:ns1)
  end

  test "available? returns false when CLI not found" do
    ZtlpTunnel.stubs(:available?).returns(false)
    assert_not ZtlpConnectivity.available?
  end

  test "available? returns false when not enrolled" do
    ZtlpTunnel.stubs(:available?).returns(true)
    ZtlpTunnel.stubs(:enrolled?).returns(false)
    assert_not ZtlpConnectivity.available?
  end

  test "available? returns true when CLI and identity present" do
    ZtlpTunnel.stubs(:available?).returns(true)
    ZtlpTunnel.stubs(:enrolled?).returns(true)
    assert ZtlpConnectivity.available?
  end

  test "check returns not available when ZTLP unavailable" do
    ZtlpTunnel.stubs(:available?).returns(false)
    result = ZtlpConnectivity.check(@ns_machine)
    assert_not result.reachable
    assert_equal "ZTLP not available", result.error
  end

  test "check handles exceptions gracefully" do
    ZtlpTunnel.stubs(:available?).returns(true)
    ZtlpTunnel.stubs(:enrolled?).returns(true)
    Open3.stubs(:popen3).raises(StandardError, "Connection refused")

    result = ZtlpConnectivity.check(@ns_machine)
    assert_not result.reachable
    assert_includes result.error, "Connection refused"
  end

  test "check_network returns results for all machines with roles" do
    ZtlpTunnel.stubs(:available?).returns(false)
    results = ZtlpConnectivity.check_network(@network)
    assert results.is_a?(Hash)
    assert results.size > 0
    results.each_value do |r|
      assert_not r.reachable
    end
  end

  test "Result struct has expected fields" do
    result = ZtlpConnectivity::Result.new(
      reachable: true, latency_ms: 42, metrics_source: "ztlp"
    )
    assert result.reachable
    assert_equal 42, result.latency_ms
    assert_equal "ztlp", result.metrics_source
    assert_nil result.error
  end

  test "Result struct can represent failure" do
    result = ZtlpConnectivity::Result.new(
      reachable: false, error: "Handshake timeout"
    )
    assert_not result.reachable
    assert_equal "Handshake timeout", result.error
  end
end
