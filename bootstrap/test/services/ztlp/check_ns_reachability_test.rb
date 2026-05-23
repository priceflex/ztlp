# frozen_string_literal: true

require "test_helper"
require "socket"

# BS-PR-4: tests for the boot-time NS reachability diagnostic.
#
# This is intentionally a non-blocking log-only check — the bootstrap
# container is useful even if the NS server is briefly down (operators
# can still manage Networks via the dashboard offline). All we care
# about is recording a one-line summary in the boot log so a future
# operator running `docker logs ztlp-bootstrap-<slug>` can see whether
# the NS was reachable at the last boot.
class Ztlp::CheckNsReachabilityTest < ActiveSupport::TestCase
  test "no-op when ZTLP_NS_SERVER is not set" do
    result = Ztlp::CheckNsReachability.call(env: {})
    assert_equal :skipped, result.status
    assert_match(/ZTLP_NS_SERVER/i, result.message)
  end

  test "no-op when ZTLP_NS_SERVER is blank" do
    result = Ztlp::CheckNsReachability.call(env: { "ZTLP_NS_SERVER" => "  " })
    assert_equal :skipped, result.status
  end

  test "returns :reachable when a UDP socket can be created and the host resolves" do
    # Start a real local UDP server so the probe has something to talk
    # to. We don't actually need to receive — the service is a
    # connectivity diagnostic, not a protocol check.
    server = UDPSocket.new
    server.bind("127.0.0.1", 0)
    port = server.addr[1]
    begin
      result = Ztlp::CheckNsReachability.call(env: { "ZTLP_NS_SERVER" => "127.0.0.1:#{port}" })
      assert_equal :reachable, result.status, result.message
      assert_equal "127.0.0.1", result.host
      assert_equal port, result.port
    ensure
      server.close
    end
  end

  test "returns :unreachable when the host cannot be resolved" do
    result = Ztlp::CheckNsReachability.call(
      env: { "ZTLP_NS_SERVER" => "this-host-definitely-does-not-exist.invalid:23096" }
    )
    assert_equal :unreachable, result.status
    assert_match(/resolv|getaddr|address|host/i, result.message)
  end

  test "returns :error when the address string is malformed" do
    result = Ztlp::CheckNsReachability.call(env: { "ZTLP_NS_SERVER" => "missing-port" })
    assert_equal :error, result.status
    assert_match(/port/i, result.message)
  end

  test "never raises, always returns a Result" do
    # Synthetic blow-up: pass something pathological. The service must
    # treat boot-time failures as informational only.
    result = Ztlp::CheckNsReachability.call(env: { "ZTLP_NS_SERVER" => ":::not-a-real-addr:::" })
    assert_kind_of Ztlp::CheckNsReachability::Result, result
    assert_includes [:error, :unreachable], result.status
  end
end
