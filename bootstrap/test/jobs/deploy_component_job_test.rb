# frozen_string_literal: true

require "test_helper"

class DeployComponentJobTest < ActiveJob::TestCase
  setup do
    @machine = machines(:ns1)
    @network = @machine.network
    @deployment = @machine.deployments.create!(
      component: "ns",
      status: "pending",
      docker_image: "priceflex/ztlp-ns:latest"
    )
  end

  test "job can be enqueued" do
    assert_enqueued_with(job: DeployComponentJob, args: [@deployment.id]) do
      DeployComponentJob.perform_later(@deployment.id)
    end
  end

  test "job sets deployment status to running then success" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end

    @deployment.reload
    assert_equal "success", @deployment.status
    assert_not_nil @deployment.started_at
    assert_not_nil @deployment.finished_at
  end

  test "job sets machine status to ready" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end

    @machine.reload
    assert_equal "ready", @machine.status
  end

  test "job appends log lines to deployment" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end

    @deployment.reload
    assert @deployment.log.present?
    assert_includes @deployment.log, "Checking SSH connectivity"
    assert_includes @deployment.log, "Deployment complete"
  end

  test "job broadcasts component_status running" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "component_status", status: "running")
    ).at_least_once

    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "component_status", status: "running"))
    )

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end
  end

  test "job broadcasts component_status success" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "component_status", status: "success")
    ).at_least_once

    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "component_status", status: "success"))
    )

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end
  end

  test "job broadcasts log lines" do
    ActionCable.server.expects(:broadcast).with(
      "deploy_network_#{@network.id}",
      has_entries(type: "log", component: "ns")
    ).at_least_once

    ActionCable.server.stubs(:broadcast).with(
      "deploy_network_#{@network.id}",
      Not(has_entries(type: "log", component: "ns"))
    )

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end
  end

  test "job creates audit log on success" do
    ActionCable.server.stubs(:broadcast)

    assert_difference "AuditLog.count" do
      perform_enqueued_jobs do
        DeployComponentJob.perform_later(@deployment.id)
      end
    end

    log = AuditLog.last
    assert_equal "deploy", log.action
    assert_equal "success", log.status
  end

  test "job updates machine last_health_check_at" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end

    @machine.reload
    assert_not_nil @machine.last_health_check_at
  end

  test "job handles relay component" do
    ActionCable.server.stubs(:broadcast)

    relay = machines(:relay1)
    deployment = relay.deployments.create!(
      component: "relay", status: "pending",
      docker_image: "priceflex/ztlp-relay:latest"
    )

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(deployment.id)
    end

    deployment.reload
    assert_equal "success", deployment.status
    assert_includes deployment.log, "relay"
  end

  test "job handles gateway component" do
    ActionCable.server.stubs(:broadcast)

    gw = machines(:gateway1)
    deployment = gw.deployments.create!(
      component: "gateway", status: "pending",
      docker_image: "priceflex/ztlp-gateway:latest"
    )

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(deployment.id)
    end

    deployment.reload
    assert_equal "success", deployment.status
    assert_includes deployment.log, "gateway"
  end
end
