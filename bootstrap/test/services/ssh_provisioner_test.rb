require "test_helper"

class SshProvisionerTest < ActiveSupport::TestCase
  setup do
    @machine = machines(:ns1)
    @provisioner = SshProvisioner.new(@machine)
  end

  # ── Config generation ──────────────────────────────────────

  test "generates NS config" do
    config = @provisioner.send(:generate_config, "ns")
    assert_includes config, "ZTLP_NS_ZONE=office.acme.ztlp"
    assert_includes config, "ZTLP_NS_PORT=23096"
    assert_includes config, "ZTLP_NS_STORAGE_MODE=ram_copies"
    assert_includes config, "ZTLP_NS_LOG_FORMAT=json"
    assert_includes config, "ZTLP_ENROLLMENT_SECRET=deadbeef1234567890abcdef12345678deadbeef1234567890abcdef12345678"
  end

  test "generates relay config with NS reference" do
    machine = machines(:relay1)
    provisioner = SshProvisioner.new(machine)
    config = provisioner.send(:generate_config, "relay")
    assert_includes config, "ZTLP_RELAY_PORT=23095"
    assert_includes config, "ZTLP_RELAY_MESH_PORT=23096"
    assert_includes config, "ZTLP_NS_SERVER="
  end

  test "generates gateway config" do
    machine = machines(:gateway1)
    provisioner = SshProvisioner.new(machine)
    config = provisioner.send(:generate_config, "gateway")
    assert_includes config, "ZTLP_GATEWAY_LISTEN=0.0.0.0:23098"
    assert_includes config, "ZTLP_GATEWAY_LOG_FORMAT=json"
  end

  test "NS config includes cluster peers" do
    config = @provisioner.send(:generate_config, "ns")
    multi = machines(:multi_role)
    assert_includes config, multi.ip_address
  end

  test "relay config includes mesh peers" do
    machine = machines(:relay1)
    provisioner = SshProvisioner.new(machine)
    config = provisioner.send(:generate_config, "relay")
    multi = machines(:multi_role)
    assert_includes config, "ZTLP_RELAY_MESH_PEERS="
  end

  test "raises on unknown component" do
    assert_raises SshProvisioner::ProvisionError do
      @provisioner.send(:generate_config, "bogus")
    end
  end

  # ── Constants ──────────────────────────────────────────────

  test "DOCKER_IMAGES maps all components" do
    %w[ns relay gateway].each do |component|
      assert SshProvisioner::DOCKER_IMAGES.key?(component), "Missing image for #{component}"
      assert SshProvisioner::CONTAINER_NAMES.key?(component), "Missing container name for #{component}"
      assert SshProvisioner::ZTLP_PORTS.key?(component), "Missing ports for #{component}"
    end
  end

  test "ZTLP_PORTS match Dockerfile defaults" do
    assert_equal 23096, SshProvisioner::ZTLP_PORTS["ns"][:udp]
    assert_equal 9103, SshProvisioner::ZTLP_PORTS["ns"][:metrics]
    assert_equal 23095, SshProvisioner::ZTLP_PORTS["relay"][:udp]
    assert_equal 23096, SshProvisioner::ZTLP_PORTS["relay"][:mesh]
    assert_equal 9101, SshProvisioner::ZTLP_PORTS["relay"][:metrics]
    assert_equal 23098, SshProvisioner::ZTLP_PORTS["gateway"][:tcp]
    assert_equal 9102, SshProvisioner::ZTLP_PORTS["gateway"][:metrics]
  end

  # ── Sudo helper ────────────────────────────────────────────

  test "sudo returns plain command when no sudo needed" do
    @provisioner.instance_variable_set(:@sudo_prefix, nil)
    assert_equal "docker ps", @provisioner.send(:sudo, "docker ps")
  end

  test "sudo prefixes command when sudo is detected" do
    @provisioner.instance_variable_set(:@sudo_prefix, "sudo")
    assert_equal "sudo docker ps", @provisioner.send(:sudo, "docker ps")
  end

  # ── SSH options ────────────────────────────────────────────

  test "ssh_options builds key auth options" do
    opts = @provisioner.send(:ssh_options)
    assert_equal 22, opts[:port]
    assert opts[:keys_only]
    assert opts[:keys].is_a?(Array)
    assert_equal 1, opts[:keys].length
  end

  test "ssh_options raises without key data" do
    @machine.ssh_private_key_ciphertext = nil
    assert_raises SshProvisioner::ProvisionError do
      @provisioner.send(:ssh_options)
    end
  end

  test "ssh_options builds password auth options" do
    @machine.ssh_auth_method = "password"
    @machine.ssh_password_ciphertext = "secret123"
    opts = @provisioner.send(:ssh_options)
    assert_equal "secret123", opts[:password]
    assert_nil opts[:keys]
  end

  test "ssh_options raises without password data" do
    @machine.ssh_auth_method = "password"
    @machine.ssh_password_ciphertext = nil
    assert_raises SshProvisioner::ProvisionError do
      @provisioner.send(:ssh_options)
    end
  end

  test "ssh_options builds agent auth options" do
    @machine.ssh_auth_method = "agent"
    opts = @provisioner.send(:ssh_options)
    assert opts[:forward_agent]
    assert_nil opts[:keys]
    assert_nil opts[:password]
  end

  # ── Provision lifecycle ────────────────────────────────────

  test "provision creates deployment record on failure" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    assert_raises SshProvisioner::ProvisionError do
      @provisioner.provision!("ns")
    end

    dep = @machine.deployments.last
    assert_equal "failed", dep.status
    assert_equal "ns", dep.component
  end

  test "provision sets machine to error on failure" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    assert_raises SshProvisioner::ProvisionError do
      @provisioner.provision!("ns")
    end

    @machine.reload
    assert_equal "error", @machine.status
    assert_includes @machine.last_error, "Connection refused"
  end

  test "provision audits on failure" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    assert_difference "AuditLog.count" do
      assert_raises SshProvisioner::ProvisionError do
        @provisioner.provision!("ns")
      end
    end

    log = AuditLog.last
    assert_equal "deploy", log.action
    assert_equal "failure", log.status
  end

  test "provision sets machine to provisioning before SSH" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    assert_raises(SshProvisioner::ProvisionError) { @provisioner.provision!("ns") }

    # Machine goes to error after failure, but was provisioning during
    dep = @machine.deployments.last
    assert_not_nil dep.started_at
  end

  # ── Test connection ────────────────────────────────────────

  test "test_connection! wraps SSH errors" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    error = assert_raises SshProvisioner::ProvisionError do
      @provisioner.test_connection!
    end
    assert_includes error.message, "SSH connection failed"
  end

  test "test_connection! audits failure" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    assert_difference "AuditLog.count" do
      assert_raises(SshProvisioner::ProvisionError) { @provisioner.test_connection! }
    end

    log = AuditLog.last
    assert_equal "ssh_test", log.action
    assert_equal "failure", log.status
  end

  # ── check_docker ───────────────────────────────────────────

  test "check_docker returns false on connection failure" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)
    assert_equal false, @provisioner.check_docker
  end

  # ── Config edge cases ──────────────────────────────────────

  test "NS config without peers has no CLUSTER_PEERS line" do
    # Create a network with only one NS machine
    net = Network.create!(name: "solo", zone: "solo.ztlp", status: "active")
    solo_ns = net.machines.create!(
      hostname: "solo-ns", ip_address: "10.0.0.1", roles: "ns",
      ssh_port: 22, ssh_user: "root", ssh_auth_method: "key",
      ssh_private_key_ciphertext: "fake-key", status: "pending"
    )
    provisioner = SshProvisioner.new(solo_ns)
    config = provisioner.send(:generate_config, "ns")
    refute_includes config, "CLUSTER_PEERS"
  end

  test "relay config without NS has no NS_SERVER line" do
    net = Network.create!(name: "no-ns", zone: "nons.ztlp", status: "active")
    relay = net.machines.create!(
      hostname: "relay-only", ip_address: "10.0.0.1", roles: "relay",
      ssh_port: 22, ssh_user: "root", ssh_auth_method: "key",
      ssh_private_key_ciphertext: "fake-key", status: "pending"
    )
    provisioner = SshProvisioner.new(relay)
    config = provisioner.send(:generate_config, "relay")
    refute_includes config, "ZTLP_NS_SERVER"
  end

  test "gateway config references both NS and relay" do
    machine = machines(:gateway1)
    provisioner = SshProvisioner.new(machine)
    config = provisioner.send(:generate_config, "gateway")
    assert_includes config, "ZTLP_NS_SERVER="
    assert_includes config, "ZTLP_RELAY_SERVER="
  end

  # ── Image constants ────────────────────────────────────────

  test "DOCKER_IMAGES follow naming convention" do
    SshProvisioner::DOCKER_IMAGES.each do |component, image|
      assert_match %r{\Apriceflex/ztlp-#{component}\z}, image
    end
  end

  test "CONTAINER_NAMES follow naming convention" do
    SshProvisioner::CONTAINER_NAMES.each do |component, name|
      assert_match %r{\Aztlp-#{component}\z}, name
    end
  end

  # ── Deployment with existing deployment record ─────────────

  test "provision uses provided deployment record" do
    dep = @machine.deployments.create!(
      component: "ns", status: "pending",
      docker_image: "priceflex/ztlp-ns:latest"
    )
    provisioner = SshProvisioner.new(@machine, deployment: dep)

    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    assert_no_difference "Deployment.count" do
      assert_raises(SshProvisioner::ProvisionError) { provisioner.provision!("ns") }
    end

    dep.reload
    assert_equal "failed", dep.status
  end
end
