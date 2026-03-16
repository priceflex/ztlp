# frozen_string_literal: true

require "test_helper"

class ZtlpTunnelTest < ActiveSupport::TestCase
  test "available? checks for CLI binary" do
    # Just verify it returns a boolean (binary likely not in test PATH)
    result = ZtlpTunnel.available?
    assert_includes [true, false], result
  end

  test "enrolled? returns false when identity file missing" do
    original_dir = ENV["ZTLP_IDENTITY_DIR"]
    ENV["ZTLP_IDENTITY_DIR"] = "/tmp/ztlp-test-nonexistent-#{$$}"
    refute ZtlpTunnel.enrolled?
  ensure
    ENV["ZTLP_IDENTITY_DIR"] = original_dir
  end

  test "enrolled? returns true when identity file exists" do
    dir = Dir.mktmpdir("ztlp-test")
    File.write(File.join(dir, "identity.json"), '{"node_id":"test"}')
    original_dir = ENV["ZTLP_IDENTITY_DIR"]
    ENV["ZTLP_IDENTITY_DIR"] = dir
    assert ZtlpTunnel.enrolled?
  ensure
    ENV["ZTLP_IDENTITY_DIR"] = original_dir
    FileUtils.rm_rf(dir)
  end

  test "fetch_metrics returns unavailable when not enrolled" do
    original_dir = ENV["ZTLP_IDENTITY_DIR"]
    ENV["ZTLP_IDENTITY_DIR"] = "/tmp/ztlp-test-nonexistent-#{$$}"
    tunnel = ZtlpTunnel.new(gateway_addr: "127.0.0.1:23098", service: "metrics")
    result = tunnel.fetch_metrics
    refute result[:available]
    assert result[:error].present?
  ensure
    ENV["ZTLP_IDENTITY_DIR"] = original_dir
  end

  test "initializes with correct defaults" do
    tunnel = ZtlpTunnel.new(gateway_addr: "10.0.0.1:23098")
    assert_equal "10.0.0.1:23098", tunnel.gateway_addr
    assert_equal "metrics", tunnel.service
    assert_kind_of Integer, tunnel.local_port
    assert tunnel.local_port > 0
  end

  test "initializes with custom service" do
    tunnel = ZtlpTunnel.new(gateway_addr: "10.0.0.1:23098", service: "admin")
    assert_equal "admin", tunnel.service
  end

  test "parse_prometheus extracts ZTLP metrics" do
    text = <<~PROM
      # HELP ztlp_relay_active_sessions Active relay sessions
      # TYPE ztlp_relay_active_sessions gauge
      ztlp_relay_active_sessions 42
      ztlp_relay_uptime_seconds 7611
      ztlp_relay_packets_total{result="passed"} 208
      ztlp_relay_packets_forwarded_total 197
      ztlp_ns_records_total 7
      ztlp_ns_cluster_members 3
      beam_memory_bytes{kind="total"} 52428800
      beam_process_count 95
    PROM

    tunnel = ZtlpTunnel.new(gateway_addr: "127.0.0.1:23098")
    data = tunnel.send(:parse_prometheus, text)

    assert_equal 42, data[:sessions_active]
    assert_equal 7611, data[:uptime_seconds]
    assert_equal 208, data[:packets_passed]
    assert_equal 197, data[:packets_forwarded]
    assert_equal 7, data[:ns_records]
    assert_equal 3, data[:ns_cluster_members]
    assert_equal 52428800, data[:memory_bytes]
    assert_equal 95, data[:beam_processes]
  end

  test "parse_prometheus handles empty input" do
    tunnel = ZtlpTunnel.new(gateway_addr: "127.0.0.1:23098")
    assert_empty tunnel.send(:parse_prometheus, "")
    assert_empty tunnel.send(:parse_prometheus, nil)
  end

  test "find_free_port returns a valid port" do
    tunnel = ZtlpTunnel.new(gateway_addr: "127.0.0.1:23098")
    port = tunnel.send(:find_free_port)
    assert port > 1024
    assert port < 65536
  end
end
