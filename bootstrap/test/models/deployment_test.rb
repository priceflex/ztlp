require "test_helper"

class DeploymentTest < ActiveSupport::TestCase
  test "valid deployment" do
    dep = Deployment.new(machine: machines(:ns1), component: "ns", status: "pending")
    assert dep.valid?
  end

  test "validates component inclusion" do
    dep = Deployment.new(machine: machines(:ns1), component: "invalid", status: "pending")
    assert_not dep.valid?
  end

  test "validates status inclusion" do
    dep = Deployment.new(machine: machines(:ns1), component: "ns", status: "bogus")
    assert_not dep.valid?
  end

  test "duration calculates elapsed time" do
    dep = deployments(:ns1_deploy)
    assert dep.duration > 0
  end

  test "duration returns nil without started_at" do
    dep = Deployment.new(machine: machines(:ns1), component: "ns", status: "pending")
    assert_nil dep.duration
  end

  test "append_log adds lines" do
    dep = Deployment.new(machine: machines(:ns1), component: "ns", status: "running")
    dep.append_log("line 1")
    dep.append_log("line 2")
    assert_includes dep.log, "line 1"
    assert_includes dep.log, "line 2"
  end

  test "finish! updates status and timestamp" do
    dep = deployments(:relay1_deploy)
    dep.finish!("success")
    assert_equal "success", dep.status
    assert_not_nil dep.finished_at
  end

  test "status predicates" do
    assert deployments(:ns1_deploy).success?
    assert deployments(:relay1_deploy).running?
    assert deployments(:failed_deploy).failed?
  end

  test "scopes" do
    assert Deployment.recent.first.created_at >= Deployment.recent.last.created_at
    assert Deployment.successful.all?(&:success?)
    assert Deployment.failed.all?(&:failed?)
  end
end
