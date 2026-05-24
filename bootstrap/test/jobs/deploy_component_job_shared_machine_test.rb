require "test_helper"

# Phase C — Defence in depth for shared production Machine rows.
#
# `MachinesController` already blocks `destroy / provision /
# test_connection` for `Machine#shared?` rows (see
# `machines_controller_shared_guard_test`). But Deployments are a
# distinct entry point: anything that calls
# `DeployComponentJob.perform_later(deployment_id)` (or
# `DeployAllJob` which enqueues the same job per machine/component)
# would still drive an SSH-based provisioning attempt against the
# `unmanaged` user. That would:
#
#   1. Fail with an auth error.
#   2. Set `machine.status = "error"` + `last_error = "<auth fail>"`.
#   3. Mark the deployment failed, write a "failure" AuditLog row.
#   4. Broadcast a red banner to the operator over ActionCable.
#
# All four are noise on a row the operator can't fix. Guard at the
# job's `perform` entry point so the rest of the job (broadcasts, logs,
# audit) can't accidentally diverge from the same intent.
class DeployComponentJobSharedMachineTest < ActiveJob::TestCase
  setup do
    @shared = machines(:shared_ns)
    @deployment = @shared.deployments.create!(
      component: "ns",
      status: "pending",
      docker_image: "priceflex/ztlp-ns:latest"
    )

    assert @shared.shared?, "fixture :shared_ns must be Machine#shared?"
  end

  test "perform on a shared machine marks deployment skipped without raising" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end

    @deployment.reload
    assert_equal "skipped", @deployment.status,
                 "deployment for shared machine must short-circuit to :skipped"
    assert_not_nil @deployment.finished_at
  end

  test "perform on a shared machine does NOT flip machine.status to error" do
    ActionCable.server.stubs(:broadcast)

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(@deployment.id)
    end

    @shared.reload
    refute_equal "error", @shared.status,
                 "shared machine must not be marked :error by a deploy attempt"
    assert_nil @shared.last_error
  end

  test "perform on a shared machine writes an audit log with status=skipped" do
    ActionCable.server.stubs(:broadcast)

    assert_difference "AuditLog.where(action: 'deploy', status: 'skipped').count" do
      perform_enqueued_jobs do
        DeployComponentJob.perform_later(@deployment.id)
      end
    end

    log = AuditLog.where(action: "deploy", status: "skipped").last
    assert_equal "skipped", log.status
    refute_nil log.details
  end

  test "perform on an operator-owned machine still completes successfully (regression)" do
    ActionCable.server.stubs(:broadcast)

    owned = machines(:ns1)
    owned_dep = owned.deployments.create!(
      component: "ns",
      status: "pending",
      docker_image: "priceflex/ztlp-ns:latest"
    )

    perform_enqueued_jobs do
      DeployComponentJob.perform_later(owned_dep.id)
    end

    owned_dep.reload
    assert_equal "success", owned_dep.status,
                 "operator-owned deploy path must still succeed end-to-end"
  end
end
