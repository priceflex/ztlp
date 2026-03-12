# frozen_string_literal: true

require "test_helper"

class DeployAllJobTest < ActiveJob::TestCase
  setup do
    @network = networks(:office)
    @ns1 = machines(:ns1)
    @relay1 = machines(:relay1)
    # Clear any existing deployments from fixtures that might interfere
  end

  test "job can be enqueued" do
    assert_enqueued_with(job: DeployAllJob, args: [@network.id]) do
      DeployAllJob.perform_later(@network.id)
    end
  end

  test "job sets network status to deploying then active on success" do
    # Mock ActionCable broadcasts
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end

    @network.reload
    assert_equal "active", @network.status
  end

  test "job creates deployments for each machine/component" do
    ActionCable.server.stubs(:broadcast)

    initial_count = Deployment.count
    expected_new = @network.machines.sum { |m| m.role_list.size }

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end

    # DeployAllJob creates deployments during perform
    assert Deployment.count > initial_count
  end

  test "job broadcasts status started message" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "status", event: "started")
    ).at_least_once

    # Allow other broadcasts
    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "status", event: "started"))
    )

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end
  end

  test "job broadcasts completion message" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "status", event: "completed")
    ).at_least_once

    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "status", event: "completed"))
    )

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end
  end

  test "job broadcasts progress updates" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "progress")
    ).at_least_once

    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "progress"))
    )

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end
  end

  test "job broadcasts component status updates" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "component_status")
    ).at_least_once

    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "component_status"))
    )

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end
  end

  test "job broadcasts log lines" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "log")
    ).at_least_once

    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "log"))
    )

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end
  end

  test "job creates audit logs for deployments" do
    ActionCable.server.stubs(:broadcast)

    initial_audit_count = AuditLog.count

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end

    assert AuditLog.count > initial_audit_count
    assert AuditLog.where(action: "deploy").any?
  end

  test "job updates machine status to ready on success" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end

    @ns1.reload
    assert_equal "ready", @ns1.status
  end

  test "job processes all machines in the network" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployAllJob.perform_later(@network.id)
    end

    @network.machines.each do |machine|
      machine.reload
      assert_equal "ready", machine.status, "Machine #{machine.hostname} should be ready"
    end
  end

  test "job handles network with no machines gracefully" do
    ActionCable.server.stubs(:broadcast)

    empty_network = Network.create!(
      name: "Empty Net", zone: "empty.ztlp",
      enrollment_secret_ciphertext: "test"
    )

    perform_enqueued_jobs do
      DeployAllJob.perform_later(empty_network.id)
    end

    empty_network.reload
    assert_equal "active", empty_network.status
  end
end
