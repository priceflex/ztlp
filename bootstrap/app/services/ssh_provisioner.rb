# frozen_string_literal: true

require "net/ssh"
require "net/scp"
require "tempfile"

# Provisions machines via SSH: installs Docker, deploys ZTLP components,
# generates configs, and manages containers.
#
# Handles non-root SSH users by detecting sudo availability and prefixing
# privileged commands automatically. Images are transferred via docker save/load
# over SCP when not available on a registry.
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
    "ns"      => { udp: 23096, metrics: 9103 },
    "relay"   => { udp: 23095, mesh: 23096, metrics: 9101 },
    "gateway" => { tcp: 23098, metrics: 9102 }
  }.freeze

  attr_reader :machine, :deployment, :log_lines

  def initialize(machine, deployment: nil)
    @machine = machine
    @deployment = deployment
    @log_lines = []
    @sudo_prefix = nil
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
      detect_sudo(ssh)
      ensure_docker(ssh)
      load_or_pull_image(ssh, component)
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

  # Prefix a command with sudo if needed (non-root user)
  def sudo(cmd)
    @sudo_prefix ? "#{@sudo_prefix} #{cmd}" : cmd
  end

  def with_ssh(&block)
    options = ssh_options
    log "Connecting to #{machine.ssh_user}@#{machine.ip_address}:#{machine.ssh_port}"

    Net::SSH.start(machine.ip_address, machine.ssh_user, **options) do |ssh|
      yield ssh
    end
  ensure
    if @key_tempfile
      @key_tempfile.unlink rescue nil
      @key_tempfile = nil
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
  end

  def check_connectivity(ssh)
    log "Checking connectivity..."
    result = exec_remote(ssh, "echo 'ztlp-bootstrap-ok' && uname -a")
    unless result[:stdout].include?("ztlp-bootstrap-ok")
      raise ProvisionError, "Connectivity check failed"
    end
    log "Connected: #{result[:stdout].lines.last&.strip}"
  end

  # Detect whether we need sudo and if it's available
  def detect_sudo(ssh)
    result = exec_remote(ssh, "id -u")
    uid = result[:stdout].strip.to_i

    if uid == 0
      @sudo_prefix = nil
      log "Running as root"
    else
      # Check if sudo is available and passwordless
      result = exec_remote(ssh, "sudo -n true 2>/dev/null && echo 'sudo-ok'")
      if result[:stdout].include?("sudo-ok")
        @sudo_prefix = "sudo"
        log "Running as #{machine.ssh_user} with sudo"
      else
        raise ProvisionError, "User '#{machine.ssh_user}' is not root and cannot sudo without password. " \
          "Add '#{machine.ssh_user} ALL=(ALL) NOPASSWD:ALL' to /etc/sudoers or connect as root."
      end
    end
  end

  def ensure_docker(ssh)
    log "Checking Docker installation..."
    result = exec_remote(ssh, "#{sudo('docker')} --version 2>/dev/null")

    if result[:exit_status] != 0
      log "Docker not found, installing..."
      install_docker(ssh)
    else
      log "Docker already installed: #{result[:stdout].strip}"
      machine.update!(docker_installed: true)
    end

    # Verify Docker daemon is running
    result = exec_remote(ssh, "#{sudo('docker')} info --format '{{.ServerVersion}}' 2>/dev/null")
    if result[:exit_status] != 0
      log "Starting Docker daemon..."
      exec_remote(ssh, sudo("systemctl start docker 2>/dev/null || service docker start 2>/dev/null"))
      sleep 3
      result = exec_remote(ssh, "#{sudo('docker')} info --format '{{.ServerVersion}}' 2>/dev/null")
      raise ProvisionError, "Docker daemon failed to start" if result[:exit_status] != 0
    end
    log "Docker daemon running: v#{result[:stdout].strip}"
  end

  def install_docker(ssh)
    # Use a single shell script to avoid sudo+redirect issues.
    # When sudo wraps individual commands, shell redirects (>) run as
    # the unprivileged user and fail to write to /etc. A heredoc script
    # run under sudo -E bash avoids this.
    script = <<~'BASH'
      set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq curl ca-certificates gnupg
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
      apt-get update -qq
      apt-get install -y -qq docker-ce docker-ce-cli containerd.io
      systemctl enable docker
      systemctl start docker
    BASH

    log "Installing Docker via script..."
    result = exec_remote(ssh, "#{sudo('bash')} << 'DOCKER_INSTALL_EOF'\n#{script}DOCKER_INSTALL_EOF")

    if result[:exit_status] != 0
      raise ProvisionError, "Docker install failed:\n#{result[:stderr]}"
    end

    # Add SSH user to docker group so subsequent commands can run without sudo
    if @sudo_prefix
      exec_remote(ssh, sudo("usermod -aG docker #{machine.ssh_user}"))
      log "Added #{machine.ssh_user} to docker group"
    end

    machine.update!(docker_installed: true)
    log "Docker installed successfully"
  end

  # Try to pull from registry; if that fails, transfer via SCP
  def load_or_pull_image(ssh, component)
    image = "#{DOCKER_IMAGES[component]}:latest"

    # First try pulling from registry
    log "Attempting to pull image #{image}..."
    result = exec_remote(ssh, sudo("docker pull #{image} 2>&1"))

    if result[:exit_status] == 0
      log "Image pulled from registry"
      return
    end

    log "Registry pull failed, transferring image via SCP..."
    transfer_image(ssh, component)
  end

  # Transfer a pre-saved image tar to the remote machine via SCP and load it
  def transfer_image(ssh, component)
    image = "#{DOCKER_IMAGES[component]}:latest"

    # Look for pre-saved image tar (gzipped or plain)
    tar_path = find_image_tar(component)
    raise ProvisionError, "No image tar found for #{component}. " \
      "Save it with: docker save #{image} | gzip > /ztlp-images/ztlp-#{component}.tar.gz" unless tar_path

    tar_size = File.size(tar_path)
    compressed = tar_path.end_with?(".gz")
    log "Found image tar: #{tar_path} (#{(tar_size / 1024.0 / 1024.0).round(1)} MB#{compressed ? ', gzipped' : ''})"

    # SCP the tar to remote
    remote_tar = "/tmp/ztlp-#{component}-image.tar#{compressed ? '.gz' : ''}"
    log "Uploading image to remote (this may take a few minutes)..."

    ssh_opts = ssh_options
    Net::SCP.upload!(machine.ip_address, machine.ssh_user,
      tar_path, remote_tar, ssh: ssh_opts)

    # Load on remote (decompress if needed)
    log "Loading image on remote..."
    # Use sudo bash -c to ensure sudo covers the entire pipeline
    load_cmd = if compressed
      sudo("bash -c 'gunzip -c #{remote_tar} | docker load'")
    else
      sudo("bash -c 'docker load < #{remote_tar}'")
    end

    result = exec_remote(ssh, load_cmd)
    if result[:exit_status] != 0
      raise ProvisionError, "Failed to load Docker image: #{result[:stderr]}"
    end

    # Clean up remote tar
    exec_remote(ssh, "rm -f #{remote_tar}")

    log "Image #{image} loaded on remote"
  end

  # Search for a pre-saved image tar file in known locations
  def find_image_tar(component)
    search_paths = [
      "/ztlp-images/ztlp-#{component}.tar.gz",
      "/ztlp-images/ztlp-#{component}.tar",
      "/tmp/ztlp-images/ztlp-#{component}.tar.gz",
      "/tmp/ztlp-images/ztlp-#{component}.tar",
      Rails.root.join("tmp", "ztlp-#{component}.tar.gz").to_s,
      Rails.root.join("tmp", "ztlp-#{component}.tar").to_s
    ]

    search_paths.find { |p| File.exist?(p) }
  end

  def generate_and_upload_config(ssh, component)
    config = generate_config(component)
    deployment&.update!(config_generated: config)

    remote_dir = "/etc/ztlp"
    config_path = "#{remote_dir}/#{component}.env"

    log "Uploading config to #{config_path}..."
    exec_remote(ssh, sudo("mkdir -p #{remote_dir}"))
    exec_remote(ssh, sudo("tee #{config_path} > /dev/null << 'ZTLP_CONFIG_EOF'\n#{config}\nZTLP_CONFIG_EOF"))
    exec_remote(ssh, sudo("chmod 600 #{config_path}"))
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
        "ZTLP_NS_STORAGE_MODE=ram_copies",
        "ZTLP_NS_LOG_FORMAT=json",
        "ZTLP_METRICS_PORT=#{ZTLP_PORTS['ns'][:metrics]}",
        "ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false"
      ]
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
      if ns_machines.any?
        lines << "ZTLP_NS_SERVER=#{ns_machines.first.ip_address}:#{ZTLP_PORTS['ns'][:udp]}"
      end
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
    exec_remote(ssh, sudo("docker rm -f #{container_name} 2>/dev/null"))

    # Build docker run command
    port_flags = ports.map do |proto, port|
      case proto
      when :udp then "-p #{port}:#{port}/udp"
      when :tcp then "-p #{port}:#{port}/tcp"
      when :mesh then "-p #{port}:#{port}/udp"
      when :metrics then "-p #{port}:#{port}/tcp"
      end
    end.join(" ")

    # Add volume for NS data persistence
    volume_flag = component == "ns" ? "-v ztlp-ns-data:/app/data" : ""

    cmd = [
      "docker run -d",
      "--name #{container_name}",
      "--restart unless-stopped",
      "--env-file /etc/ztlp/#{component}.env",
      port_flags,
      volume_flag,
      "--log-driver json-file --log-opt max-size=50m --log-opt max-file=3",
      image
    ].reject(&:blank?).join(" ")

    log "Starting container #{container_name}..."
    result = exec_remote(ssh, sudo(cmd))
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
    sleep 3

    result = exec_remote(ssh, sudo("docker inspect --format '{{.State.Running}}' #{container_name}"))
    unless result[:stdout].strip == "true"
      logs = exec_remote(ssh, sudo("docker logs --tail 30 #{container_name} 2>&1"))
      raise ProvisionError, "Container not running. Logs:\n#{logs[:stdout]}"
    end

    # Check the port is listening
    port = ZTLP_PORTS[component].values.first
    result = exec_remote(ssh, "ss -tuln | grep :#{port} || true")
    log "Port check: #{result[:stdout].strip.presence || 'binding...'}"
    log "Container #{container_name} is running"
  end

  def exec_remote(ssh, command, timeout: 60)
    stdout = +""
    stderr = +""
    exit_status = nil

    channel = ssh.open_channel do |ch|
      ch.exec(command) do |_, success|
        raise ProvisionError, "Failed to execute: #{command}" unless success

        ch.on_data { |_, data| stdout << data }
        ch.on_extended_data { |_, _, data| stderr << data }
        ch.on_request("exit-status") { |_, buf| exit_status = buf.read_long }
      end
    end

    channel.wait

    # Force UTF-8 encoding for log storage (SSH output may be ASCII-8BIT)
    stdout.force_encoding("UTF-8").scrub!("?")
    stderr.force_encoding("UTF-8").scrub!("?")

    deployment&.append_log("$ #{command}")
    deployment&.append_log(stdout) if stdout.present?
    deployment&.append_log(stderr) if stderr.present?
    deployment&.save

    { stdout: stdout, stderr: stderr, exit_status: exit_status || 0 }
  end

  def log(message)
    safe_msg = message.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "?")
    @log_lines << "[#{Time.current.strftime('%H:%M:%S')}] #{safe_msg}"
    deployment&.append_log(safe_msg)
    deployment&.save
    Rails.logger.info("[SshProvisioner] #{safe_msg}")
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
