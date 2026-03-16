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

  def initialize(gateway_addr:, service: "metrics", ns_server: nil, relay_addr: nil)
    @gateway_addr = gateway_addr
    @service = service
    @ns_server = ns_server
    @relay_addr = relay_addr
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

  MAX_RETRIES = 2  # Total attempts = 1 + MAX_RETRIES

  # One-shot: open tunnel, fetch metrics, close tunnel.
  # Retries on empty response — large metrics responses (~1.7KB+) can
  # exceed UDP MTU when relayed, causing IP fragmentation. If any fragment
  # is lost, the entire datagram is dropped and curl gets an empty response.
  # Retrying with a fresh tunnel/session typically succeeds.
  def fetch_metrics
    return { available: false, data: {}, error: "ztlp CLI not found" } unless self.class.available?
    return { available: false, data: {}, error: "not enrolled" } unless self.class.enrolled?

    last_error = nil
    (1 + MAX_RETRIES).times do |attempt|
      begin
        @local_port = find_free_port if attempt > 0  # Fresh port for retries
        open_tunnel
        wait_for_tunnel

        body = fetch_via_curl("127.0.0.1", @local_port, "/metrics")

        if body && !body.empty?
          return { available: true, data: parse_prometheus(body) }
        end

        last_error = "empty response"
        Rails.logger.debug("[ZtlpTunnel] Attempt #{attempt + 1}: empty response from #{@gateway_addr}, retrying...") if attempt < MAX_RETRIES
      rescue Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, StandardError => e
        last_error = e.message
        Rails.logger.debug("[ZtlpTunnel] Attempt #{attempt + 1}: #{e.message} from #{@gateway_addr}") if attempt < MAX_RETRIES
      ensure
        close_tunnel
      end
    end

    { available: false, data: {}, error: last_error }
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
    cmd += ["--relay", @relay_addr] if @relay_addr

    @stdin, @stdout, @stderr, @wait_thread = Open3.popen3(*cmd)
    @pid = @wait_thread.pid

    Rails.logger.info("[ZtlpTunnel] Started tunnel pid=#{@pid} #{@gateway_addr} → localhost:#{@local_port}")
  end

  # Wait for the tunnel's TCP listener to be ready.
  # We CANNOT TCP-connect to probe — the tunnel only handles one TCP connection
  # per ZTLP session, and a probe would consume it.
  # Instead, read stderr for the "Listening" marker from the ztlp CLI.
  def wait_for_tunnel
    deadline = Time.now + CONNECT_TIMEOUT
    output = +""
    streams = [@stdout, @stderr].compact

    while Time.now < deadline
      remaining = deadline - Time.now
      break if remaining <= 0

      ready = IO.select(streams, nil, nil, [remaining, 0.3].min)
      if ready && ready[0]
        ready[0].each do |io|
          begin
            chunk = io.read_nonblock(4096)
            output << chunk
            # "Listening" means TCP listener is bound and accepting
            return true if output.include?("Listening")
          rescue IO::WaitReadable
            next
          rescue EOFError
            streams.delete(io)
            next
          end
        end
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

  # Fetch via curl with --http0.9 flag.
  # ZTLP tunnel responses may look like HTTP/0.9 to strict HTTP parsers;
  # curl --http0.9 handles this correctly.
  def fetch_via_curl(host, port, path)
    url = "http://#{host}:#{port}#{path}"
    stdout, status = Open3.capture2(
      "curl", "-sf", "--http0.9",
      "--connect-timeout", "3",
      "--max-time", METRICS_TIMEOUT.to_s,
      url
    )
    status.success? ? stdout : nil
  rescue StandardError => e
    Rails.logger.debug("[ZtlpTunnel] curl fetch failed: #{e.message}")
    nil
  end

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

      # Split metric{labels} value → key includes labels
      if line =~ /^([a-zA-Z_:][a-zA-Z0-9_:{}=",. -]*)\s+([\d.eE+-]+)/
        key = Regexp.last_match(1)
        value = Regexp.last_match(2)

        case key
        # Relay metrics
        when /ztlp_relay_active_sessions/
          data[:sessions_active] = value.to_i
        when /ztlp_relay_uptime_seconds/
          data[:uptime_seconds] = value.to_f.to_i
        when /ztlp_relay_packets_total\{result="passed"\}/
          data[:packets_passed] = value.to_i
        when /ztlp_relay_packets_forwarded_total/
          data[:packets_forwarded] = value.to_i
        when /ztlp_relay_packets_total\{result="dropped_l1"\}/
          data[:dropped_l1] = value.to_i
        when /ztlp_relay_packets_total\{result="dropped_l2"\}/
          data[:dropped_l2] = value.to_i

        # NS metrics
        when /ztlp_ns_records_total/
          data[:ns_records] = value.to_i
        when /ztlp_ns_uptime_seconds/
          data[:uptime_seconds] = value.to_f.to_i
        when /ztlp_ns_ratelimit_rejected_total/
          data[:ns_ratelimit_rejected] = value.to_i
        when /ztlp_ns_cluster_members$/
          data[:ns_cluster_members] = value.to_i

        # Gateway metrics
        when /ztlp_gateway_sessions/
          data[:sessions_active] = value.to_i
        when /ztlp_gateway_handshakes_ok/
          data[:handshakes_ok] = value.to_i
        when /ztlp_gateway_policy_denials/
          data[:policy_denials] = value.to_i

        # BEAM resource metrics
        when /beam_memory_bytes\{kind="total"\}/
          data[:memory_bytes] = value.to_i
        when /beam_process_count/
          data[:beam_processes] = value.to_i
        end
      end
    end

    data
  end
end
