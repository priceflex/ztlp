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
  # Automatically routes through the relay if available (for UDP-hostile NATs).
  # Uses role-specific gateway ports (NS=23098, relay=23099).
  # Returns a Result struct.
  def self.check(machine, gateway_port: nil)
    return Result.new(reachable: false, error: "ZTLP not available") unless available?

    gateway_port ||= SshProvisioner.gateway_port_for(machine)
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    gateway_addr = "#{machine.ip_address}:#{gateway_port}"

    relay_addr = find_relay_addr(machine)
    identity_path = File.join(IDENTITY_DIR, "identity.json")

    relay_info = relay_addr ? " via relay #{relay_addr}" : " (direct)"
    Rails.logger.info("[ZtlpConnectivity] Checking #{machine.hostname} → #{gateway_addr}#{relay_info}")

    cmd = [
      ZTLP_CLI, "connect", gateway_addr,
      "--key", identity_path,
      "--service", "metrics"
    ]
    cmd += ["--relay", relay_addr] if relay_addr

    # Run ztlp connect and check if handshake succeeds
    stdin, stdout, stderr, wait_thread = Open3.popen3(*cmd)
    pid = wait_thread.pid

    output = +""
    deadline = Time.now + CONNECT_TIMEOUT
    while Time.now < deadline
      readable = IO.select([stdout, stderr], nil, nil, 0.5)
      if readable
        readable[0].each do |io|
          begin
            output << io.read_nonblock(4096)
          rescue IO::WaitReadable, EOFError
            # continue
          end
        end
      end

      if output.include?("Handshake complete")
        elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).to_i
        if output =~ /Handshake latency:\s*([\d.]+)ms/
          latency = Regexp.last_match(1).to_f.round.to_i
        else
          latency = elapsed
        end
        Process.kill("TERM", pid) rescue nil
        Process.wait(pid) rescue nil
        [stdin, stdout, stderr].each { |io| io&.close rescue nil }
        Rails.logger.info("[ZtlpConnectivity] ✓ #{machine.hostname}: handshake OK in #{latency}ms")
        return Result.new(reachable: true, latency_ms: latency, metrics_source: "ztlp")
      end
    end

    elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).to_i
    clean_output = output.gsub(/\e\[[0-9;]*m/, "").strip.truncate(500)
    Rails.logger.warn("[ZtlpConnectivity] ✗ #{machine.hostname}: handshake timeout after #{CONNECT_TIMEOUT}s. CLI output: #{clean_output}")
    Process.kill("TERM", pid) rescue nil
    Process.wait(pid) rescue nil
    [stdin, stdout, stderr].each { |io| io&.close rescue nil }
    Result.new(reachable: false, latency_ms: elapsed, error: "Handshake timeout")
  rescue StandardError => e
    Rails.logger.error("[ZtlpConnectivity] ✗ #{machine.hostname}: #{e.class}: #{e.message}")
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
  def self.handshake_check(machine, gateway_port: nil)
    return Result.new(reachable: false, error: "ZTLP not available") unless available?

    gateway_port ||= SshProvisioner.gateway_port_for(machine)
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    gateway_addr = "#{machine.ip_address}:#{gateway_port}"
    relay_addr = find_relay_addr(machine)
    identity_path = File.join(IDENTITY_DIR, "identity.json")

    # Use ztlp connect with a very short timeout — we just want to see if handshake succeeds
    cmd = [
      ZTLP_CLI, "connect", gateway_addr,
      "--key", identity_path,
      "--service", "metrics"
    ]
    cmd += ["--relay", relay_addr] if relay_addr

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

  # Find a relay address for routing ZTLP connections.
  # Returns "host:port" string or nil if no relay found.
  #
  # Only use relay routing when the target machine IS a relay — the relay's
  # gateway sidecar (port 23099) may not be reachable directly (firewalled)
  # but is reachable through the relay's own UDP port (23095).
  #
  # For non-relay machines (NS, dedicated gateways), connect directly to their
  # gateway sidecar — the relay only forwards to its LOCAL sidecar, so routing
  # a non-relay HELLO through the relay would connect to the wrong gateway.
  def self.find_relay_addr(machine)
    # Only relay machines need relay routing (self-relay)
    if machine.role_list.include?("relay")
      relay_port = SshProvisioner::ZTLP_PORTS.dig("relay", :udp) || 23095
      return "#{machine.ip_address}:#{relay_port}"
    end

    # Non-relay machines: connect directly (no relay routing)
    nil
  rescue StandardError
    nil
  end

  private_class_method :find_relay_addr
end
