require "test_helper"

class SshProvisionerTest < ActiveSupport::TestCase
  setup do
    @machine = machines(:ns1)
    @provisioner = SshProvisioner.new(@machine)
  end

  test "generates NS config" do
    config = @provisioner.send(:generate_config, "ns")
    assert_includes config, "ZTLP_NS_ZONE=office.acme.ztlp"
    assert_includes config, "ZTLP_NS_PORT=23097"
    assert_includes config, "ZTLP_NS_STORAGE_MODE=disc_copies"
    assert_includes config, "ZTLP_NS_LOG_FORMAT=json"
  end

  test "generates relay config with NS reference" do
    machine = machines(:relay1)
    provisioner = SshProvisioner.new(machine)
    config = provisioner.send(:generate_config, "relay")
    assert_includes config, "ZTLP_RELAY_PORT=23095"
    assert_includes config, "ZTLP_RELAY_MESH_PORT=23096"
    # Should reference NS server
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
    # multi_role has NS role too, so ns1 should see it as peer
    config = @provisioner.send(:generate_config, "ns")
    multi = machines(:multi_role)
    assert_includes config, multi.ip_address
  end

  test "relay config includes mesh peers" do
    machine = machines(:relay1)
    provisioner = SshProvisioner.new(machine)
    config = provisioner.send(:generate_config, "relay")
    # multi_role has relay, should appear as mesh peer
    multi = machines(:multi_role)
    assert_includes config, "ZTLP_RELAY_MESH_PEERS="
  end

  test "raises on unknown component" do
    assert_raises SshProvisioner::ProvisionError do
      @provisioner.send(:generate_config, "bogus")
    end
  end

  test "DOCKER_IMAGES maps all components" do
    %w[ns relay gateway].each do |component|
      assert SshProvisioner::DOCKER_IMAGES.key?(component), "Missing image for #{component}"
      assert SshProvisioner::CONTAINER_NAMES.key?(component), "Missing container name for #{component}"
      assert SshProvisioner::ZTLP_PORTS.key?(component), "Missing ports for #{component}"
    end
  end

  test "ZTLP_PORTS has expected structure" do
    assert_equal 23097, SshProvisioner::ZTLP_PORTS["ns"][:udp]
    assert_equal 23095, SshProvisioner::ZTLP_PORTS["relay"][:udp]
    assert_equal 23096, SshProvisioner::ZTLP_PORTS["relay"][:mesh]
    assert_equal 23098, SshProvisioner::ZTLP_PORTS["gateway"][:tcp]
  end

  test "provision creates deployment record" do
    # Mock SSH to avoid real connections
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    assert_raises SshProvisioner::ProvisionError do
      @provisioner.provision!("ns")
    end

    # Deployment should have been created with failed status
    dep = @machine.deployments.last
    assert_equal "failed", dep.status
    assert_equal "ns", dep.component
  end

  test "test_connection! wraps SSH errors" do
    Net::SSH.stubs(:start).raises(Errno::ECONNREFUSED)

    error = assert_raises SshProvisioner::ProvisionError do
      @provisioner.test_connection!
    end
    assert_includes error.message, "SSH connection failed"
  end

  test "ssh_options builds key auth options" do
    opts = @provisioner.send(:ssh_options)
    assert_equal 22, opts[:port]
    assert opts[:keys_only]
    assert opts[:keys].is_a?(Array)
  end

  test "ssh_options raises without key data" do
    @machine.ssh_private_key_ciphertext = nil
    assert_raises SshProvisioner::ProvisionError do
      @provisioner.send(:ssh_options)
    end
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
end
