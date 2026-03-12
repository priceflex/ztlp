# frozen_string_literal: true

require "test_helper"

class WizardControllerTest < ActionDispatch::IntegrationTest
  # ── Step 1: Create Network ──────────────────────────────────────────

  test "GET wizard/new renders step 1" do
    get wizard_new_path
    assert_response :success
    assert_select "h2", /Create Network/
  end

  test "POST wizard/network creates network and redirects to machines" do
    assert_difference "Network.count", 1 do
      post wizard_create_network_path, params: {
        network: { name: "Wizard Net", zone: "wizard-net.ztlp" }
      }
    end
    assert_redirected_to wizard_machines_path

    network = Network.find_by(name: "Wizard Net")
    assert_not_nil network
    assert_equal "wizard-net.ztlp", network.zone
    assert_equal "created", network.status
    assert network.enrollment_secret_ciphertext.present?
  end

  test "POST wizard/network with invalid data re-renders step 1" do
    assert_no_difference "Network.count" do
      post wizard_create_network_path, params: {
        network: { name: "", zone: "" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "POST wizard/network creates audit log" do
    assert_difference "AuditLog.count" do
      post wizard_create_network_path, params: {
        network: { name: "Audit Wiz Net", zone: "audit-wiz.ztlp" }
      }
    end
    log = AuditLog.last
    assert_equal "network_create", log.action
    assert_includes log.parsed_details["via"], "wizard"
  end

  test "POST wizard/network with duplicate name fails" do
    assert_no_difference "Network.count" do
      post wizard_create_network_path, params: {
        network: { name: networks(:office).name, zone: "unique-dupe.ztlp" }
      }
    end
    assert_response :unprocessable_entity
  end

  # ── Step 2: Add Machines ────────────────────────────────────────────

  test "GET wizard/machines redirects if no network in session" do
    get wizard_machines_path
    assert_redirected_to wizard_new_path
  end

  test "GET wizard/machines renders step 2 with network in session" do
    network = setup_wizard_network
    get wizard_machines_path
    assert_response :success
    assert_select "h2", /Add Machines/
  end

  test "POST wizard/machines adds a machine" do
    network = setup_wizard_network

    assert_difference "Machine.count", 1 do
      post wizard_add_machine_path, params: {
        machine: {
          hostname: "wiz-ns1",
          ip_address: "10.99.1.10",
          ssh_port: 22,
          ssh_user: "root",
          ssh_auth_method: "key",
          ssh_private_key_ciphertext: "fake-key",
          roles: "ns"
        }
      }
    end
    assert_redirected_to wizard_machines_path

    machine = Machine.find_by(hostname: "wiz-ns1")
    assert_not_nil machine
    assert_equal network.id, machine.network_id
    assert_equal "10.99.1.10", machine.ip_address
    assert_equal "ns", machine.roles
  end

  test "POST wizard/machines with invalid data re-renders" do
    setup_wizard_network

    assert_no_difference "Machine.count" do
      post wizard_add_machine_path, params: {
        machine: { hostname: "", ip_address: "", roles: "ns", ssh_user: "root", ssh_auth_method: "key" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "POST wizard/machines creates audit log" do
    setup_wizard_network

    assert_difference "AuditLog.count" do
      post wizard_add_machine_path, params: {
        machine: {
          hostname: "audit-m1", ip_address: "10.99.1.11", ssh_port: 22,
          ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "relay"
        }
      }
    end
    log = AuditLog.last
    assert_equal "machine_add", log.action
  end

  test "POST wizard/machines via turbo_stream returns turbo stream response" do
    setup_wizard_network

    post wizard_add_machine_path, params: {
      machine: {
        hostname: "turbo-m1", ip_address: "10.99.1.12", ssh_port: 22,
        ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "ns"
      }
    }, as: :turbo_stream

    assert_response :success
    assert_includes response.media_type, "turbo-stream"
  end

  test "DELETE wizard/machines/:machine_id removes machine" do
    network = setup_wizard_network
    machine = network.machines.create!(
      hostname: "del-m1", ip_address: "10.99.1.20", ssh_port: 22,
      ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "ns"
    )

    assert_difference "Machine.count", -1 do
      delete wizard_remove_machine_path(machine_id: machine.id)
    end
    assert_redirected_to wizard_machines_path
  end

  test "DELETE wizard/machines/:machine_id via turbo_stream" do
    network = setup_wizard_network
    machine = network.machines.create!(
      hostname: "del-t-m1", ip_address: "10.99.1.21", ssh_port: 22,
      ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "relay"
    )

    assert_difference "Machine.count", -1 do
      delete wizard_remove_machine_path(machine_id: machine.id), as: :turbo_stream
    end
    assert_response :success
    assert_includes response.media_type, "turbo-stream"
  end

  test "POST wizard/machines with multiple roles" do
    setup_wizard_network

    post wizard_add_machine_path, params: {
      machine: {
        hostname: "multi-m1", ip_address: "10.99.1.30", ssh_port: 22,
        ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "ns,relay"
      }
    }
    assert_redirected_to wizard_machines_path

    machine = Machine.find_by(hostname: "multi-m1")
    assert_equal %w[ns relay], machine.role_list.sort
  end

  # ── Step 3: Review ──────────────────────────────────────────────────

  test "GET wizard/review redirects if no network in session" do
    get wizard_review_path
    assert_redirected_to wizard_new_path
  end

  test "GET wizard/review renders summary" do
    network = setup_wizard_network_with_machines
    get wizard_review_path
    assert_response :success
    assert_select "h2", /Review Configuration/
  end

  test "GET wizard/review shows machine count" do
    network = setup_wizard_network_with_machines
    get wizard_review_path
    assert_response :success
    # Should list our machines
    assert_match /wiz-ns-1/, response.body
    assert_match /wiz-relay-1/, response.body
  end

  test "GET wizard/review shows role counts" do
    network = setup_wizard_network_with_machines
    get wizard_review_path
    assert_response :success
    assert_select "div.text-xs", /ns/i
    assert_select "div.text-xs", /relay/i
  end

  # ── Step 4: Deploy ──────────────────────────────────────────────────

  test "GET wizard/deploy redirects if no network in session" do
    get wizard_deploy_path
    assert_redirected_to wizard_new_path
  end

  test "GET wizard/deploy renders deploy page" do
    setup_wizard_network_with_machines
    get wizard_deploy_path
    assert_response :success
    assert_select "h2", /Live Deploy/
  end

  test "GET wizard/deploy shows ready to deploy button" do
    setup_wizard_network_with_machines
    get wizard_deploy_path
    assert_response :success
    assert_match /Start Deployment/, response.body
  end

  test "POST wizard/deploy enqueues DeployAllJob" do
    network = setup_wizard_network_with_machines

    assert_enqueued_with(job: DeployAllJob) do
      post wizard_start_deploy_path
    end
  end

  test "POST wizard/deploy sets network status to deploying" do
    network = setup_wizard_network_with_machines
    post wizard_start_deploy_path
    network.reload
    assert_equal "deploying", network.status
  end

  test "POST wizard/deploy creates pending deployments" do
    network = setup_wizard_network_with_machines
    machine_count = network.machines.count
    component_count = network.machines.sum { |m| m.role_list.size }

    assert_difference "Deployment.count", component_count do
      post wizard_start_deploy_path
    end

    # All new deployments should be pending
    new_deployments = Deployment.where(status: "pending").order(created_at: :desc).limit(component_count)
    assert new_deployments.all? { |d| d.status == "pending" }
  end

  test "POST wizard/deploy via turbo_stream returns turbo response" do
    setup_wizard_network_with_machines

    post wizard_start_deploy_path, as: :turbo_stream
    assert_response :success
    assert_includes response.media_type, "turbo-stream"
  end

  # ── Zone Suggestion ─────────────────────────────────────────────────

  test "GET wizard/suggest_zone returns JSON zone" do
    get wizard_suggest_zone_path, params: { name: "My Office" }
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "my-office.ztlp", json["zone"]
  end

  test "GET wizard/suggest_zone handles empty name" do
    get wizard_suggest_zone_path, params: { name: "" }
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "", json["zone"]
  end

  test "GET wizard/suggest_zone strips special characters" do
    get wizard_suggest_zone_path, params: { name: "Test! Network @123" }
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "test-network-123.ztlp", json["zone"]
  end

  # ── Full Wizard Flow ────────────────────────────────────────────────

  test "full wizard flow: create network -> add machines -> review -> deploy" do
    # Step 1: Create network
    post wizard_create_network_path, params: {
      network: { name: "Full Flow Net", zone: "full-flow.ztlp" }
    }
    assert_redirected_to wizard_machines_path
    follow_redirect!
    assert_response :success

    # Step 2: Add machines
    post wizard_add_machine_path, params: {
      machine: {
        hostname: "flow-ns1", ip_address: "10.88.1.10", ssh_port: 22,
        ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "ns"
      }
    }
    assert_redirected_to wizard_machines_path

    post wizard_add_machine_path, params: {
      machine: {
        hostname: "flow-relay1", ip_address: "10.88.1.20", ssh_port: 22,
        ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "relay"
      }
    }
    assert_redirected_to wizard_machines_path

    # Step 3: Review
    get wizard_review_path
    assert_response :success
    assert_match /flow-ns1/, response.body
    assert_match /flow-relay1/, response.body

    # Step 4: Deploy
    get wizard_deploy_path
    assert_response :success

    assert_enqueued_with(job: DeployAllJob) do
      post wizard_start_deploy_path
    end

    network = Network.find_by(name: "Full Flow Net")
    assert_equal "deploying", network.reload.status
  end

  private

  def setup_wizard_network
    network = Network.create!(
      name: "Wizard Test #{SecureRandom.hex(4)}",
      zone: "wiz-test-#{SecureRandom.hex(4)}.ztlp",
      enrollment_secret_ciphertext: SecureRandom.hex(32)
    )
    # Simulate wizard session
    post wizard_create_network_path, params: {
      network: { name: network.name, zone: network.zone }
    }
    # The create_network action creates a NEW network, so let's grab the one from session
    # Actually, the above will fail with duplicate. Let's just use the create flow:
    network.destroy
    post wizard_create_network_path, params: {
      network: { name: "Wiz #{SecureRandom.hex(4)}", zone: "wiz-#{SecureRandom.hex(4)}.ztlp" }
    }
    Network.order(created_at: :desc).first
  end

  def setup_wizard_network_with_machines
    network = setup_wizard_network

    # Add machines directly (faster than going through the controller)
    network.machines.create!(
      hostname: "wiz-ns-1", ip_address: "10.77.1.10", ssh_port: 22,
      ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "ns"
    )
    network.machines.create!(
      hostname: "wiz-relay-1", ip_address: "10.77.1.20", ssh_port: 22,
      ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "relay"
    )
    network.machines.create!(
      hostname: "wiz-gw-1", ip_address: "10.77.1.30", ssh_port: 22,
      ssh_user: "root", ssh_auth_method: "key", ssh_private_key_ciphertext: "k", roles: "gateway"
    )

    network
  end
end
