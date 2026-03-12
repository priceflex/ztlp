# frozen_string_literal: true

require "net/ssh"
require "net/scp"
require "tempfile"

# Provisions machines via SSH: installs Docker, deploys ZTLP components,
# generates configs, and manages containers.
class SshProvisioner
  class ProvisionError < StandardError; end

  DOCKER_IMAGES = {
    "ns"      => "priceflex/ztlp-ns",
    "relay"   => "priceflex/ztlp-relay",
    "gateway" => "priceflex/ztlp-gateway"
  }.freeze

  CONTAINER_NAMES = {
    "ns"      => "ztlp-ns",
    "relay"   => "ztlp-relay",
    "gateway" => "ztlp-gateway"
  }.freeze

  ZTLP_PORTS = {
    "ns"      => { udp: 23097, metrics: 9103 },
    "relay"   => { udp: 23095, mesh: 23096, metrics: 9101 },
    "gateway" => { tcp: 23098, metrics: 9102 }
  }.freeze

  attr_reader :machine, :deployment, :log_lines

  def initialize(machine, deployment: nil)
    @machine = machine
    @deployment = deployment
    @log_lines = []
  end

  # Full provisioning: check connectivity, install Docker, deploy component
  def provision!(component)
    @deployment ||= machine.deployments.create!(
      component: component,
      status: "running",
      started_at: Time.current,
      docker_image: "#{DOCKER_IMAGES[component]}:latest"
    )

    machine.update!(status: "provisioning")
    log "Starting provisioning of #{component} on #{machine.hostname} (#{machine.ip_address})"

    with_ssh do |ssh|
      check_connectivity(ssh)
      ensure_docker(ssh)
      pull_image(ssh, component)
      generate_and_upload_config(ssh, component)
      start_container(ssh, component)
      verify_health(ssh, component)
    end

    deployment.finish!("success")
    machine.update!(status: "ready", last_error: nil, last_health_check_at: Time.current)
    audit!("deploy", status: "success", details: { component: component })
    log "✅ Provisioning complete for #{component}"
    true
  rescue StandardError => e
    log "❌ Provisioning failed: #{e.message}"
    deployment&.update!(status: "failed", finished_at: Time.current)
    deployment&.append_log("ERROR: #{e.message}")
    deployment&.save
    machine.update!(status: "error", last_error: e.message)
    audit!("deploy", status: "failure", details: { component: component, error: e.message })
    raise ProvisionError, e.message
  end

  # Test SSH connectivity only
  def test_connection!
    with_ssh do |ssh|
      check_connectivity(ssh)
    end
    audit!("ssh_test", status: "success")
    true
  rescue StandardError => e
    audit!("ssh_test", status: "failure", details: { error: e.message })
    raise ProvisionError, "SSH connection failed: #{e.message}"
  end

  # Check if Docker is installed on remote
  def check_docker
    with_ssh do |ssh|
      result = exec_remote(ssh, "docker --version 2>/dev/null")
      result[:exit_status] == 0
    end
  rescue StandardError
    false
  end

  private

  def with_ssh(&block)
    options = ssh_options
    log "Connecting to #{machine.ssh_user}@#{machine.ip_address}:#{machine.ssh_port}"

    Net::SSH.start(machine.ip_address, machine.ssh_user, **options) do |ssh|
      yield ssh
    end
  end

  def ssh_options
    opts = {
      port: machine.ssh_port,
      non_interactive: true,
      timeout: 30
    }

    case machine.ssh_auth_method
    when "key"
      key_data = machine.ssh_private_key_ciphertext
      raise ProvisionError, "No SSH key configured" if key_data.blank?
      # Write key to temp file for net-ssh
      @key_tempfile = Tempfile.new("ztlp_ssh_key")
      @key_tempfile.write(key_data)
      @key_tempfile.close
      File.chmod(0o600, @key_tempfile.path)
      opts[:keys] = [@key_tempfile.path]
      opts[:keys_only] = true
    when "password"
      password = machine.ssh_password_ciphertext
      raise ProvisionError, "No SSH password configured" if password.blank?
      opts[:password] = password
    when "agent"
      opts[:forward_agent] = true
    end

    opts
  ensure
    # Cleanup is handled in with_ssh after block completes
  end

  def check_connectivity(ssh)
    log "Checking connectivity..."
    result = exec_remote(ssh, "echo 'ztlp-bootstrap-ok' && uname -a")
    unless result[:stdout].include?("ztlp-bootstrap-ok")
      raise ProvisionError, "Connectivity check failed"
    end
    log "Connected: #{result[:stdout].lines.last&.strip}"
  end

  def ensure_docker(ssh)
    log "Checking Docker installation..."
    result = exec_remote(ssh, "docker --version 2>/dev/null")

    if result[:exit_status] != 0
      log "Docker not found, installing..."
      install_docker(ssh)
    else
      log "Docker already installed: #{result[:stdout].strip}"
      machine.update!(docker_installed: true)
    end

    # Verify Docker daemon is running
    result = exec_remote(ssh, "docker info --format '{{.ServerVersion}}' 2>/dev/null")
    if result[:exit_status] != 0
      log "Starting Docker daemon..."
      exec_remote(ssh, "systemctl start docker 2>/dev/null || service docker start 2>/dev/null")
      sleep 3
      result = exec_remote(ssh, "docker info --format '{{.ServerVersion}}' 2>/dev/null")
      raise ProvisionError, "Docker daemon failed to start" if result[:exit_status] != 0
    end
    log "Docker daemon running: v#{result[:stdout].strip}"
  end

  def install_docker(ssh)
    commands = [
      "apt-get update -qq",
      "apt-get install -y -qq curl ca-certificates gnupg",
      "install -m 0755 -d /etc/apt/keyrings",
      "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
      'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list',
      "apt-get update -qq",
      "apt-get install -y -qq docker-ce docker-ce-cli containerd.io",
      "systemctl enable docker",
      "systemctl start docker"
    ]

    commands.each do |cmd|
      log "  $ #{cmd}"
      result = exec_remote(ssh, cmd)
      if result[:exit_status] != 0 && !cmd.include?("gpg") # gpg warnings are ok
        raise ProvisionError, "Docker install failed at: #{cmd}\n#{result[:stderr]}"
      end
    end

    machine.update!(docker_installed: true)
    log "Docker installed successfully"
  end

  def pull_image(ssh, component)
    image = "#{DOCKER_IMAGES[component]}:latest"
    log "Pulling image #{image}..."
    result = exec_remote(ssh, "docker pull #{image}", timeout: 300)
    if result[:exit_status] != 0
      raise ProvisionError, "Failed to pull #{image}: #{result[:stderr]}"
    end
    log "Image pulled successfully"
  end

  def generate_and_upload_config(ssh, component)
    config = generate_config(component)
    deployment&.update!(config_generated: config)

    remote_dir = "/etc/ztlp"
    config_path = "#{remote_dir}/#{component}.env"

    log "Uploading config to #{config_path}..."
    exec_remote(ssh, "mkdir -p #{remote_dir}")
    exec_remote(ssh, "cat > #{config_path} << 'ZTLP_CONFIG_EOF'\n#{config}\nZTLP_CONFIG_EOF")
    exec_remote(ssh, "chmod 600 #{config_path}")
    log "Config uploaded"
  end

  def generate_config(component)
    network = machine.network
    ns_machines = network.ns_machines
    relay_machines = network.relay_machines

    case component
    when "ns"
      lines = [
        "ZTLP_NS_ZONE=#{network.zone}",
        "ZTLP_NS_PORT=#{ZTLP_PORTS['ns'][:udp]}",
        "ZTLP_NS_STORAGE_MODE=disc_copies",
        "ZTLP_NS_LOG_FORMAT=json",
        "ZTLP_METRICS_PORT=#{ZTLP_PORTS['ns'][:metrics]}"
      ]
      # Add cluster peers (other NS machines)
      peers = ns_machines.reject { |m| m.id == machine.id }
      if peers.any?
        peer_list = peers.map { |m| "ztlp_ns@#{m.ip_address}" }.join(",")
        lines << "ZTLP_NS_CLUSTER_PEERS=#{peer_list}"
      end
      lines.join("\n")

    when "relay"
      lines = [
        "ZTLP_RELAY_PORT=#{ZTLP_PORTS['relay'][:udp]}",
        "ZTLP_RELAY_MESH_PORT=#{ZTLP_PORTS['relay'][:mesh]}",
        "ZTLP_RELAY_LOG_FORMAT=json",
        "ZTLP_METRICS_PORT=#{ZTLP_PORTS['relay'][:metrics]}"
      ]
      # Add NS server for relay discovery
      if ns_machines.any?
        lines << "ZTLP_NS_SERVER=#{ns_machines.first.ip_address}:#{ZTLP_PORTS['ns'][:udp]}"
      end
      # Add mesh peers (other relay machines)
      peers = relay_machines.reject { |m| m.id == machine.id }
      if peers.any?
        peer_list = peers.map { |m| "#{m.ip_address}:#{ZTLP_PORTS['relay'][:mesh]}" }.join(",")
        lines << "ZTLP_RELAY_MESH_PEERS=#{peer_list}"
      end
      lines.join("\n")

    when "gateway"
      lines = [
        "ZTLP_GATEWAY_LISTEN=0.0.0.0:#{ZTLP_PORTS['gateway'][:tcp]}",
        "ZTLP_GATEWAY_LOG_FORMAT=json",
        "ZTLP_METRICS_PORT=#{ZTLP_PORTS['gateway'][:metrics]}"
      ]
      if ns_machines.any?
        lines << "ZTLP_NS_SERVER=#{ns_machines.first.ip_address}:#{ZTLP_PORTS['ns'][:udp]}"
      end
      if relay_machines.any?
        lines << "ZTLP_RELAY_SERVER=#{relay_machines.first.ip_address}:#{ZTLP_PORTS['relay'][:udp]}"
      end
      lines.join("\n")
    else
      raise ProvisionError, "Unknown component: #{component}"
    end
  end

  def start_container(ssh, component)
    container_name = CONTAINER_NAMES[component]
    image = "#{DOCKER_IMAGES[component]}:latest"
    ports = ZTLP_PORTS[component]

    # Stop existing container if running
    log "Stopping existing container #{container_name} (if any)..."
    exec_remote(ssh, "docker rm -f #{container_name} 2>/dev/null")

    # Build docker run command
    port_flags = ports.map do |proto, port|
      case proto
      when :udp then "-p #{port}:#{port}/udp"
      when :tcp then "-p #{port}:#{port}/tcp"
      when :mesh then "-p #{port}:#{port}/udp"
      when :metrics then "-p #{port}:#{port}/tcp"
      end
    end.join(" ")

    cmd = [
      "docker run -d",
      "--name #{container_name}",
      "--restart unless-stopped",
      "--env-file /etc/ztlp/#{component}.env",
      port_flags,
      "--log-driver json-file --log-opt max-size=50m --log-opt max-file=3",
      image
    ].join(" ")

    log "Starting container #{container_name}..."
    result = exec_remote(ssh, cmd)
    if result[:exit_status] != 0
      raise ProvisionError, "Failed to start #{container_name}: #{result[:stderr]}"
    end

    container_id = result[:stdout].strip[0..11]
    deployment&.update!(container_id: container_id)
    log "Container started: #{container_id}"
  end

  def verify_health(ssh, component)
    container_name = CONTAINER_NAMES[component]
    log "Verifying container health..."

    # Wait a moment for startup
    sleep 2

    result = exec_remote(ssh, "docker inspect --format '{{.State.Running}}' #{container_name}")
    unless result[:stdout].strip == "true"
      logs = exec_remote(ssh, "docker logs --tail 20 #{container_name} 2>&1")
      raise ProvisionError, "Container not running. Logs:\n#{logs[:stdout]}"
    end

    # Check the port is listening
    port = ZTLP_PORTS[component].values.first
    result = exec_remote(ssh, "ss -tuln | grep :#{port} || true")
    log "Port check: #{result[:stdout].strip.presence || 'binding...'}"
    log "Container #{container_name} is running"
  end

  def exec_remote(ssh, command, timeout: 60)
    stdout = ""
    stderr = ""
    exit_status = nil

    channel = ssh.open_channel do |ch|
      ch.exec(command) do |_, success|
        raise ProvisionError, "Failed to execute: #{command}" unless success

        ch.on_data { |_, data| stdout << data }
        ch.on_extended_data { |_, _, data| stderr << data }
        ch.on_request("exit-status") { |_, buf| exit_status = buf.read_long }
      end
    end

    channel.wait(timeout)
    deployment&.append_log("$ #{command}")
    deployment&.append_log(stdout) if stdout.present?
    deployment&.append_log(stderr) if stderr.present?
    deployment&.save

    { stdout: stdout, stderr: stderr, exit_status: exit_status || 0 }
  end

  def log(message)
    @log_lines << "[#{Time.current.strftime('%H:%M:%S')}] #{message}"
    deployment&.append_log(message)
    deployment&.save
    Rails.logger.info("[SshProvisioner] #{message}")
  end

  def audit!(action, status: "success", details: nil)
    AuditLog.record(
      action: action,
      target: machine,
      status: status,
      details: (details || {}).merge(
        machine: machine.hostname,
        ip: machine.ip_address,
        network: machine.network.name
      ),
      ip_address: machine.ip_address
    )
  end
end
