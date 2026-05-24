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

  # --- Phase C: "skipped" status -----------------------------------------
  #
  # Added in 2026-05-24 Phase C. `Deployment#status` now accepts "skipped"
  # as a valid terminal state. Used by `DeployComponentJob` when the
  # target machine is `Machine#shared?` (auto-seeded shared production
  # NS/Relay rows): we don't SSH into them, but we still want a row in
  # the deployments table so the dashboard timeline shows "skipped —
  # shared infrastructure" instead of a misleading "pending forever".

  test "status inclusion accepts pending/running/success/failed/skipped" do
    %w[pending running success failed skipped].each do |s|
      d = machines(:ns1).deployments.build(component: "ns", status: s)
      assert d.valid?, "expected status=#{s.inspect} to be valid: #{d.errors.full_messages.join(', ')}"
    end
  end

  test "VALID_STATUSES constant exposes the set for callers (jobs, dashboards)" do
    assert_equal %w[pending running success failed skipped], Deployment::VALID_STATUSES
  end

  test "skipped? predicate is true only when status == 'skipped'" do
    d = machines(:ns1).deployments.create!(
      component: "ns", status: "skipped",
      docker_image: "priceflex/ztlp-ns:latest"
    )
    assert d.skipped?
    refute d.success?
    refute d.failed?
  end

  test "skipped scope returns only deployments with status='skipped'" do
    machine = machines(:ns1)
    machine.deployments.create!(component: "ns", status: "success",
                                docker_image: "priceflex/ztlp-ns:latest")
    skipped = machine.deployments.create!(component: "relay", status: "skipped",
                                          docker_image: "priceflex/ztlp-relay:latest")

    skipped_set = Deployment.skipped
    assert_includes skipped_set, skipped
    assert(skipped_set.all? { |d| d.status == "skipped" })
  end
end
