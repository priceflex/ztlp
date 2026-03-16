# frozen_string_literal: true

require "net/ssh"
require "net/http"
require "json"

# Checks health of deployed ZTLP components on remote machines.
# Enhanced in Phase C with Docker inspection, port checks, Prometheus metrics,
# and structured health data storage.
class HealthChecker
  class HealthCheckError < StandardError; end

  Result = Struct.new(:machine, :component, :status, :details, :metrics, :container_state,
                       :error_message, :response_time_ms, keyword_init: true)

  HEALTH_CHECKS = {
    "ns"      => { port: 23096, protocol: :udp, metrics_port: 9103 },
    "relay"   => { port: 23095, protocol: :udp, metrics_port: 9101 },
    "gateway" => { port: 23098, protocol: :tcp, metrics_port: 9102 }
  }.freeze

  CONTAINER_NAMES = {
    "ns"      => "ztlp-ns",
    "relay"   => "ztlp-relay",
    "gateway" => "ztlp-gateway"
  }.freeze

  def initialize(machine)
    @machine = machine
  end

  # Check all components on this machine and store results
  def check_all
    results = @machine.role_list.map { |role| check_component(role) }
    @machine.update!(last_health_check_at: Time.current)

    # Store each result as a HealthCheck record
    results.each { |result| store_result(result) }

    # Update machine status based on overall health
    all_healthy = results.all? { |r| r.status == "healthy" }
    any_down = results.any? { |r| r.status == "down" }

    if any_down
      @machine.update!(status: "error", last_error: results.select { |r| r.status == "down" }.map { |r|
        "#{r.component}: #{r.error_message || 'down'}"
      }.join("; "))
    elsif !all_healthy
      # Degraded but not down — keep current status, just update error info
      degraded = results.select { |r| r.status == "degraded" }
      if degraded.any?
        @machine.update!(last_error: degraded.map { |r|
          "#{r.component}: #{r.error_message || 'degraded'}"
        }.join("; "))
      end
    end

    results
  end

  # Check a single component with full diagnostics
  def check_component(component)
    config = HEALTH_CHECKS[component]
    raise HealthCheckError, "Unknown component: #{component}" unless config

    start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    metrics = {}
    container_state = "unknown"
    error_message = nil
    status = "unknown"

    begin
      ssh_opts = build_ssh_options
      Net::SSH.start(@machine.ip_address, @machine.ssh_user, **ssh_opts) do |ssh|
        # 1. Check Docker container status via docker inspect
        container_name = CONTAINER_NAMES[component]
        inspect_result = check_container_status(ssh, container_name)
        container_state = inspect_result[:state]
        metrics.merge!(inspect_result[:metrics])

        unless inspect_result[:running]
          elapsed = elapsed_ms(start_time)
          return Result.new(
            machine: @machine, component: component, status: "down",
            details: metrics.to_json, metrics: metrics, container_state: container_state,
            error_message: "Container not running (state: #{container_state})",
            response_time_ms: elapsed
          )
        end

        # 2. Get container logs (recent)
        logs_result = get_container_logs(ssh, container_name)
        metrics[:recent_log_lines] = logs_result[:lines]
        metrics[:recent_errors] = logs_result[:error_count]

        # 3. Check ZTLP port accessibility
        port_check = check_port(ssh, config[:port], config[:protocol])
        metrics[:port_listening] = port_check

        # 4. Query Prometheus metrics endpoint
        prom_result = query_prometheus(ssh, config[:metrics_port])
        metrics[:metrics_available] = prom_result[:available]
        metrics.merge!(prom_result[:data]) if prom_result[:available]

        # 5. Check resource usage
        resource_result = check_resource_usage(ssh, container_name)
        metrics.merge!(resource_result)

        # Determine status
        if !port_check
          status = "degraded"
          error_message = "Port #{config[:port]} not listening"
        elsif logs_result[:error_count] >= 10
          status = "degraded"
          error_message = "High error rate in logs (#{logs_result[:error_count]} errors in last 20 lines)"
        elsif !prom_result[:available]
          status = "degraded"
          error_message = "Metrics endpoint unavailable"
        else
          status = "healthy"
        end
      end
    rescue StandardError => e
      status = "down"
      error_message = "Health check failed: #{e.message}"
      container_state = "unreachable"
    end

    elapsed = elapsed_ms(start_time)

    Result.new(
      machine: @machine, component: component, status: status,
      details: metrics.to_json, metrics: metrics, container_state: container_state,
      error_message: error_message, response_time_ms: elapsed
    )
  end

  private

  # Check Docker container status via docker inspect
  def check_container_status(ssh, container_name)
    result = exec_ssh(ssh, "#{sudo}docker inspect --format '{{.State.Status}}|{{.State.Running}}|{{.State.StartedAt}}|{{.State.Pid}}' #{container_name} 2>/dev/null")

    if result[:exit_status] != 0
      return { running: false, state: "not_found", metrics: {} }
    end

    parts = result[:stdout].strip.split("|")
    state = parts[0] || "unknown"
    running = parts[1] == "true"
    started_at = parts[2]
    pid = parts[3]

    metrics = {
      container_started_at: started_at,
      container_pid: pid&.to_i,
      container_status: state
    }

    # Calculate uptime if running
    if running && started_at.present?
      begin
        start = Time.parse(started_at)
        metrics[:uptime_seconds] = (Time.current - start).to_i
      rescue ArgumentError
        # ignore parse errors
      end
    end

    { running: running, state: state, metrics: metrics }
  end

  # Get recent container logs and count errors
  def get_container_logs(ssh, container_name)
    result = exec_ssh(ssh, "#{sudo}docker logs --tail 20 #{container_name} 2>&1")
    lines = result[:stdout].to_s.lines.map(&:strip)
    error_count = lines.count { |l| l.downcase.include?("error") || l.downcase.include?("fatal") }

    { lines: lines.last(5), error_count: error_count }
  end

  # Check if a port is listening
  def check_port(ssh, port, protocol)
    proto_flag = protocol == :udp ? "-u" : "-t"
    result = exec_ssh(ssh, "ss #{proto_flag}ln | grep :#{port}")
    result[:exit_status] == 0
  end

  # Query Prometheus metrics endpoint
  def query_prometheus(ssh, metrics_port)
    result = exec_ssh(ssh, "curl -sf --max-time 5 http://localhost:#{metrics_port}/metrics 2>/dev/null")

    unless result[:exit_status] == 0
      return { available: false, data: {} }
    end

    data = parse_prometheus_metrics(result[:stdout])
    { available: true, data: data }
  end

  # Parse Prometheus text format into structured data
  def parse_prometheus_metrics(text)
    data = {}
    return data if text.blank?

    text.each_line do |line|
      line = line.strip
      next if line.empty? || line.start_with?("#")

      # Parse key value pairs like: ztlp_sessions_active 42
      parts = line.split(/\s+/)
      next unless parts.length >= 2

      key = parts[0]
      value = parts[1]

      # Extract ZTLP-specific metrics
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

  # Check CPU and memory usage of the container
  def check_resource_usage(ssh, container_name)
    result = exec_ssh(ssh, "#{sudo}docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}' #{container_name} 2>/dev/null")

    return {} if result[:exit_status] != 0

    parts = result[:stdout].strip.split("|")
    return {} if parts.length < 3

    {
      cpu_percent: parts[0]&.gsub("%", "")&.strip&.to_f,
      memory_usage: parts[1]&.strip,
      memory_percent: parts[2]&.gsub("%", "")&.strip&.to_f
    }
  end

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
    channel.wait

    { stdout: stdout, stderr: stderr, exit_status: exit_status || 0 }
  end

  def elapsed_ms(start_time)
    ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time) * 1000).to_i
  end

  # Prefix for privileged commands — sudo when not root
  def sudo
    @sudo ||= (@machine.ssh_user == "root" ? "" : "sudo ")
  end

  # Store a check result as a HealthCheck record and manage alerts
  def store_result(result)
    # Get previous status for this component
    previous = @machine.latest_health_check_for(result.component)
    old_status = previous&.status || "unknown"

    # Create the health check record
    HealthCheck.create!(
      machine: @machine,
      component: result.component,
      status: result.status,
      metrics: result.details,
      container_state: result.container_state,
      error_message: result.error_message,
      response_time_ms: result.response_time_ms,
      checked_at: Time.current
    )

    # Manage alerts based on status transitions
    if result.status == "healthy"
      Alert.auto_resolve(machine: @machine, component: result.component)
    elsif old_status != result.status && (result.status == "degraded" || result.status == "down")
      Alert.create_for_status_change(
        machine: @machine,
        component: result.component,
        new_status: result.status,
        old_status: old_status
      )
    end
  end
end
