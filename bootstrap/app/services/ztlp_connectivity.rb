# frozen_string_literal: true

# Tests ZTLP overlay connectivity to machines.
#
# Attempts a Noise_XX handshake to the gateway sidecar on each machine.
# This verifies the full ZTLP stack: UDP reachability, handshake success,
# policy authorization, and backend connectivity.
#
# Used by the dashboard to show red/green dots for ZTLP tunnel status.
class ZtlpConnectivity
  ZTLP_CLI = ENV.fetch("ZTLP_CLI_PATH", "ztlp")
  IDENTITY_DIR = ENV.fetch("ZTLP_IDENTITY_DIR", File.expand_path("~/.ztlp"))
  CONNECT_TIMEOUT = 8 # seconds

  Result = Struct.new(:reachable, :latency_ms, :error, :metrics_source, keyword_init: true)

  # Check if Bootstrap has ZTLP capability (CLI + identity)
  def self.available?
    ZtlpTunnel.available? && ZtlpTunnel.enrolled?
  end

  # Test connectivity to a machine's gateway sidecar via ZTLP tunnel.
  # Returns a Result struct.
  def self.check(machine, gateway_port: SshProvisioner::GATEWAY_SIDECAR_PORT)
    return Result.new(reachable: false, error: "ZTLP not available") unless available?

    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    gateway_addr = "#{machine.ip_address}:#{gateway_port}"

    tunnel = ZtlpTunnel.new(gateway_addr: gateway_addr, service: "metrics")
    result = tunnel.fetch_metrics

    elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).to_i

    if result[:available]
      Result.new(reachable: true, latency_ms: elapsed, metrics_source: "ztlp")
    else
      Result.new(reachable: false, latency_ms: elapsed, error: result[:error])
    end
  rescue StandardError => e
    Result.new(reachable: false, error: e.message)
  end

  # Check all machines in a network and return hash of machine_id => Result
  def self.check_network(network)
    results = {}
    network.machines.each do |machine|
      next unless machine.role_list.any?
      results[machine.id] = check(machine)
    end
    results
  end

  # Quick check — just test if the handshake succeeds (no metrics fetch)
  def self.handshake_check(machine, gateway_port: SshProvisioner::GATEWAY_SIDECAR_PORT)
    return Result.new(reachable: false, error: "ZTLP not available") unless available?

    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    gateway_addr = "#{machine.ip_address}:#{gateway_port}"
    identity_path = File.join(IDENTITY_DIR, "identity.json")

    # Use ztlp connect with a very short timeout — we just want to see if handshake succeeds
    cmd = [
      ZTLP_CLI, "connect", gateway_addr,
      "--key", identity_path,
      "--service", "metrics"
    ]

    pid = nil
    begin
      stdin, stdout, stderr, wait_thread = Open3.popen3(*cmd)
      pid = wait_thread.pid

      # Wait a short time — if handshake succeeds, the CLI prints success messages
      output = +""
      deadline = Time.now + CONNECT_TIMEOUT
      while Time.now < deadline
        if IO.select([stderr], nil, nil, 0.5)
          begin
            output << stderr.read_nonblock(4096)
          rescue IO::WaitReadable
            # retry
          rescue EOFError
            break
          end
        end

        # Check for handshake success/failure indicators
        if output.include?("Tunnel ready") || output.include?("Bridge mode") || output.include?("Forwarding")
          elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).to_i
          return Result.new(reachable: true, latency_ms: elapsed)
        elsif output.include?("rejected") || output.include?("denied")
          elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).to_i
          return Result.new(reachable: false, latency_ms: elapsed, error: "Policy denied")
        end
      end

      elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).to_i
      Result.new(reachable: false, latency_ms: elapsed, error: "Handshake timeout")
    ensure
      if pid
        Process.kill("TERM", pid) rescue nil
        Process.wait(pid) rescue nil
      end
      [stdin, stdout, stderr].each { |io| io&.close rescue nil }
    end
  rescue StandardError => e
    Result.new(reachable: false, error: e.message)
  end
end
