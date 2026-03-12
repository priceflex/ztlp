# frozen_string_literal: true

require "net/ssh"
require "net/http"
require "json"

# Checks health of deployed ZTLP components on remote machines
class HealthChecker
  class HealthCheckError < StandardError; end

  Result = Struct.new(:machine, :component, :healthy, :details, keyword_init: true)

  HEALTH_CHECKS = {
    "ns"      => { port: 23097, protocol: :udp, metrics_port: 9103 },
    "relay"   => { port: 23095, protocol: :udp, metrics_port: 9101 },
    "gateway" => { port: 23098, protocol: :tcp, metrics_port: 9102 }
  }.freeze

  def initialize(machine)
    @machine = machine
  end

  # Check all components on this machine
  def check_all
    results = @machine.role_list.map { |role| check_component(role) }
    @machine.update!(last_health_check_at: Time.current)

    all_healthy = results.all?(&:healthy)
    unless all_healthy
      @machine.update!(status: "error", last_error: results.reject(&:healthy).map { |r|
        "#{r.component}: #{r.details}"
      }.join("; "))
    end

    results
  end

  # Check a single component
  def check_component(component)
    config = HEALTH_CHECKS[component]
    raise HealthCheckError, "Unknown component: #{component}" unless config

    details = {}

    begin
      ssh_opts = build_ssh_options
      Net::SSH.start(@machine.ip_address, @machine.ssh_user, **ssh_opts) do |ssh|
        # Check container running
        container_name = SshProvisioner::CONTAINER_NAMES[component]
        result = exec_ssh(ssh, "docker inspect --format '{{.State.Running}}:{{.State.StartedAt}}' #{container_name} 2>/dev/null")

        if result[:exit_status] != 0 || !result[:stdout].start_with?("true")
          return Result.new(
            machine: @machine, component: component, healthy: false,
            details: "Container not running"
          )
        end

        started_at = result[:stdout].split(":")[1..]&.join(":")&.strip
        details[:started_at] = started_at
        details[:container] = "running"

        # Check port listening
        port = config[:port]
        proto_flag = config[:protocol] == :udp ? "-u" : "-t"
        result = exec_ssh(ssh, "ss #{proto_flag}ln | grep :#{port}")
        details[:port_listening] = result[:exit_status] == 0

        # Check metrics endpoint (HTTP)
        metrics_port = config[:metrics_port]
        result = exec_ssh(ssh, "curl -sf http://localhost:#{metrics_port}/metrics 2>/dev/null | head -5")
        details[:metrics_available] = result[:exit_status] == 0

        # Check recent logs for errors
        result = exec_ssh(ssh, "docker logs --tail 10 --since 5m #{container_name} 2>&1 | grep -i error | wc -l")
        error_count = result[:stdout].strip.to_i
        details[:recent_errors] = error_count

        healthy = details[:port_listening] && error_count < 5
        Result.new(machine: @machine, component: component, healthy: healthy, details: details.to_json)
      end
    rescue StandardError => e
      Result.new(
        machine: @machine, component: component, healthy: false,
        details: "Health check failed: #{e.message}"
      )
    end
  end

  private

  def build_ssh_options
    opts = { port: @machine.ssh_port, non_interactive: true, timeout: 15 }

    case @machine.ssh_auth_method
    when "key"
      key_data = @machine.ssh_private_key_ciphertext
      if key_data.present?
        tempfile = Tempfile.new("ztlp_hc_key")
        tempfile.write(key_data)
        tempfile.close
        File.chmod(0o600, tempfile.path)
        opts[:keys] = [tempfile.path]
        opts[:keys_only] = true
      end
    when "password"
      opts[:password] = @machine.ssh_password_ciphertext
    when "agent"
      opts[:forward_agent] = true
    end

    opts
  end

  def exec_ssh(ssh, command)
    stdout = ""
    stderr = ""
    exit_status = nil

    channel = ssh.open_channel do |ch|
      ch.exec(command) do |_, success|
        return { stdout: "", stderr: "exec failed", exit_status: 1 } unless success
        ch.on_data { |_, data| stdout << data }
        ch.on_extended_data { |_, _, data| stderr << data }
        ch.on_request("exit-status") { |_, buf| exit_status = buf.read_long }
      end
    end
    channel.wait(15)

    { stdout: stdout, stderr: stderr, exit_status: exit_status || 0 }
  end
end
