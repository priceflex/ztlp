# frozen_string_literal: true

require "json"

# Executes `ztlp admin` CLI commands on the NS machine via SSH.
# All methods call `ztlp admin ... --json` and parse JSON responses.
class ZtlpAdmin
  class AdminError < StandardError; end

  attr_reader :network

  def initialize(network)
    @network = network
    ns_machine = network.ns_machines.first
    raise AdminError, "No NS machine found for network #{network.name}" unless ns_machine
    @ssh = SshProvisioner.new(ns_machine)
  end

  # --- Users ---

  def create_user(name, role:, email: nil)
    cmd = "ztlp admin user create #{shell_escape(name)} --role #{shell_escape(role)}"
    cmd += " --email #{shell_escape(email)}" if email.present?
    cmd += " --json"
    execute(cmd)
  end

  def revoke_user(name, reason:)
    cmd = "ztlp admin user revoke #{shell_escape(name)} --reason #{shell_escape(reason)} --json"
    execute(cmd)
  end

  def list_users
    execute("ztlp admin user list --json")
  end

  # --- Devices ---

  def link_device(device_name, owner:)
    cmd = "ztlp admin device link #{shell_escape(device_name)} --owner #{shell_escape(owner)} --json"
    execute(cmd)
  end

  def revoke_device(name, reason:)
    cmd = "ztlp admin device revoke #{shell_escape(name)} --reason #{shell_escape(reason)} --json"
    execute(cmd)
  end

  def list_devices
    execute("ztlp admin device list --json")
  end

  # --- Groups ---

  def create_group(name, description: nil)
    cmd = "ztlp admin group create #{shell_escape(name)}"
    cmd += " --description #{shell_escape(description)}" if description.present?
    cmd += " --json"
    execute(cmd)
  end

  def group_add(group, user)
    execute("ztlp admin group add-member #{shell_escape(group)} #{shell_escape(user)} --json")
  end

  def group_remove(group, user)
    execute("ztlp admin group remove-member #{shell_escape(group)} #{shell_escape(user)} --json")
  end

  def list_groups
    execute("ztlp admin group list --json")
  end

  def group_members(group)
    execute("ztlp admin group members #{shell_escape(group)} --json")
  end

  # --- Admin queries ---

  def list_entities(type: nil, zone: nil)
    cmd = "ztlp admin list"
    cmd += " --type #{shell_escape(type)}" if type.present?
    cmd += " --zone #{shell_escape(zone)}" if zone.present?
    cmd += " --json"
    execute(cmd)
  end

  def audit_log(since: "24h", name: nil)
    cmd = "ztlp admin audit --since #{shell_escape(since)}"
    cmd += " --name #{shell_escape(name)}" if name.present?
    cmd += " --json"
    execute(cmd)
  end

  private

  def execute(command)
    result = run_ssh_command(command)
    parse_response(result)
  rescue StandardError => e
    raise AdminError, "ztlp admin command failed: #{e.message}"
  end

  def run_ssh_command(command)
    ns_machine = network.ns_machines.first
    raise AdminError, "No NS machine available" unless ns_machine

    provisioner = SshProvisioner.new(ns_machine)
    # Use the SSH execution pattern from SshProvisioner
    stdout = ""
    stderr = ""
    exit_status = nil

    options = build_ssh_options(ns_machine)

    Net::SSH.start(ns_machine.ip_address, ns_machine.ssh_user, **options) do |ssh|
      channel = ssh.open_channel do |ch|
        ch.exec(command) do |_, success|
          raise AdminError, "Failed to execute: #{command}" unless success

          ch.on_data { |_, data| stdout << data }
          ch.on_extended_data { |_, _, data| stderr << data }
          ch.on_request("exit-status") { |_, buf| exit_status = buf.read_long }
        end
      end
      channel.wait(30)
    end

    if exit_status && exit_status != 0
      raise AdminError, "Command exited with status #{exit_status}: #{stderr.presence || stdout}"
    end

    stdout
  end

  def build_ssh_options(machine)
    opts = {
      port: machine.ssh_port,
      non_interactive: true,
      timeout: 30
    }

    case machine.ssh_auth_method
    when "key"
      key_data = machine.ssh_private_key_ciphertext
      raise AdminError, "No SSH key configured" if key_data.blank?
      opts[:key_data] = [key_data]
      opts[:keys_only] = true
    when "password"
      opts[:password] = machine.ssh_password_ciphertext
    when "agent"
      opts[:forward_agent] = true
    end

    opts
  end

  def parse_response(raw)
    return {} if raw.blank?
    JSON.parse(raw)
  rescue JSON::ParserError => e
    raise AdminError, "Invalid JSON response: #{e.message}\nRaw: #{raw.truncate(200)}"
  end

  def shell_escape(value)
    Shellwords.escape(value.to_s)
  end
end
