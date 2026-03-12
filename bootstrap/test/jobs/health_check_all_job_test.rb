require "test_helper"

class HealthCheckAllJobTest < ActiveSupport::TestCase
  test "enqueues health check job for each network with machines" do
    # Office has machines, production doesn't
    assert_enqueued_with(job: HealthCheckJob) do
      HealthCheckAllJob.perform_now
    end
  end

  test "skips networks with no machines" do
    # Production network has no machines in fixtures
    jobs_enqueued = []
    HealthCheckJob.stubs(:perform_later).with { |id| jobs_enqueued << id }

    HealthCheckAllJob.perform_now

    # Only office network should be enqueued (it has machines)
    assert_includes jobs_enqueued, networks(:office).id
    assert_not_includes jobs_enqueued, networks(:production).id
  end

  test "can be enqueued" do
    assert_enqueued_with(job: HealthCheckAllJob) do
      HealthCheckAllJob.perform_later
    end
  end
end
