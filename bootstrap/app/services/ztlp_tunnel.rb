# frozen_string_literal: true

require "open3"
require "net/http"
require "timeout"

# Manages ZTLP tunnels for secure metrics access.
#
# Uses the `ztlp` CLI binary to create encrypted tunnels through
# ZTLP gateways deployed as sidecars on NS/relay machines.
# This replaces raw TCP/SSH for metrics collection — eating our own dogfood.
#
# Usage:
#   tunnel = ZtlpTunnel.new(gateway_addr: "52.39.59.34:23098", service: "metrics")
#   result = tunnel.fetch_metrics
#   # => { available: true, data: { sessions_active: 42, ... } }
#
class ZtlpTunnel
  ZTLP_CLI = ENV.fetch("ZTLP_CLI_PATH", "ztlp")
  IDENTITY_DIR = ENV.fetch("ZTLP_IDENTITY_DIR", File.expand_path("~/.ztlp"))
  CONNECT_TIMEOUT = 8 # seconds to wait for tunnel to be ready
  METRICS_TIMEOUT = 5 # seconds to wait for metrics HTTP response

  attr_reader :gateway_addr, :service, :local_port

  def initialize(gateway_addr:, service: "metrics", ns_server: nil)
    @gateway_addr = gateway_addr
    @service = service
    @ns_server = ns_server
    @local_port = find_free_port
    @pid = nil
    @stdin = nil
    @stdout = nil
    @stderr = nil
    @wait_thread = nil
  end

  # Check if the ztlp CLI binary is available
  def self.available?
    result = system("#{ZTLP_CLI} --version", out: File::NULL, err: File::NULL)
    result == true
  rescue Errno::ENOENT
    false
  end

  # Check if Bootstrap has a ZTLP identity (enrolled)
  def self.enrolled?
    dir = ENV.fetch("ZTLP_IDENTITY_DIR", File.expand_path("~/.ztlp"))
    File.exist?(File.join(dir, "identity.json"))
  end

  # One-shot: open tunnel, fetch metrics, close tunnel
  def fetch_metrics
    return { available: false, data: {}, error: "ztlp CLI not found" } unless self.class.available?
    return { available: false, data: {}, error: "not enrolled" } unless self.class.enrolled?

    open_tunnel
    wait_for_tunnel

    # Fetch metrics through the tunnel
    uri = URI("http://127.0.0.1:#{@local_port}/metrics")
    response = Net::HTTP.start(uri.host, uri.port, read_timeout: METRICS_TIMEOUT, open_timeout: METRICS_TIMEOUT) do |http|
      http.get(uri.path)
    end

    if response.is_a?(Net::HTTPSuccess)
      { available: true, data: parse_prometheus(response.body) }
    else
      { available: false, data: {}, error: "HTTP #{response.code}" }
    end
  rescue Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, StandardError => e
    { available: false, data: {}, error: e.message }
  ensure
    close_tunnel
  end

  # Open the ZTLP tunnel (background process)
  def open_tunnel
    key_path = File.join(IDENTITY_DIR, "identity.json")

    cmd = [
      ZTLP_CLI, "connect", @gateway_addr,
      "--key", key_path,
      "--service", @service,
      "-L", "#{@local_port}:127.0.0.1:0"  # Local forward; remote port from gateway backend
    ]
    cmd += ["--ns", @ns_server] if @ns_server

    @stdin, @stdout, @stderr, @wait_thread = Open3.popen3(*cmd)
    @pid = @wait_thread.pid

    Rails.logger.info("[ZtlpTunnel] Started tunnel pid=#{@pid} #{@gateway_addr} → localhost:#{@local_port}")
  end

  # Wait for the tunnel to be ready (TCP listener accepting connections)
  def wait_for_tunnel
    deadline = Time.now + CONNECT_TIMEOUT
    while Time.now < deadline
      begin
        TCPSocket.new("127.0.0.1", @local_port).close
        return true
      rescue Errno::ECONNREFUSED
        sleep 0.2
      end
    end
    raise Timeout::Error, "ZTLP tunnel did not become ready within #{CONNECT_TIMEOUT}s"
  end

  # Close the tunnel
  def close_tunnel
    return unless @pid

    begin
      Process.kill("TERM", @pid)
      Process.wait(@pid)
    rescue Errno::ESRCH, Errno::ECHILD
      # Already dead
    end

    [@stdin, @stdout, @stderr].each { |io| io&.close rescue nil }
    @pid = nil

    Rails.logger.info("[ZtlpTunnel] Closed tunnel to #{@gateway_addr}")
  end

  private

  def find_free_port
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    server.close
    port
  end

  def parse_prometheus(text)
    data = {}
    return data if text.blank?

    text.each_line do |line|
      line = line.strip
      next if line.empty? || line.start_with?("#")

      parts = line.split(/\s+/)
      next unless parts.length >= 2

      key = parts[0]
      value = parts[1]

      case key
      when /ztlp_sessions_active/
        data[:sessions_active] = value.to_i
      when /ztlp_packets_total/, /ztlp_packets_per_sec/
        data[:packets_per_sec] = value.to_f
      when /ztlp_ns_records_count/
        data[:ns_records_count] = value.to_i
      when /process_cpu_seconds_total/
        data[:cpu_seconds] = value.to_f
      when /process_resident_memory_bytes/
        data[:memory_bytes] = value.to_i
      end
    end

    data
  end
end
