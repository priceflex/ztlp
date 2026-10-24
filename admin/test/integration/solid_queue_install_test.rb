# frozen_string_literal: true

require "test_helper"

# Before 20261024000001 the solid_queue tables existed nowhere, so bin/jobs idled on every stack
# ("solid_queue not installed yet") and no recurring task ever ran. Pin the install.
class SolidQueueInstallTest < ActiveSupport::TestCase
  test "the solid_queue tables bin/jobs checks for exist after migrations" do
    %w[solid_queue_jobs solid_queue_processes solid_queue_recurring_tasks solid_queue_ready_executions
       solid_queue_scheduled_executions solid_queue_semaphores].each do |t|
      assert ActiveRecord::Base.connection.table_exists?(t), "missing #{t}"
    end
  end

  test "bin/jobs starts solid_queue (not the idle branch) once the tables exist" do
    src = File.read(Rails.root.join("bin/jobs"))
    assert_match(/table_exists\?\(["']solid_queue_jobs["']\)/, src)
    assert ActiveRecord::Base.connection.table_exists?("solid_queue_jobs")
  end

  # The jobs container can start before the web container finishes db:prepare. It must WAIT for
  # the tables and then start, never idle forever (seen in prod on the 0.2.2 swap).
  test "bin/jobs waits for the solid_queue tables instead of idling forever" do
    src = File.read(Rails.root.join("bin/jobs"))
    assert_match(/until\b.*table_exists\?/m, src)
    refute_match(/^\s*sleep\s*$/, src, "a bare `sleep` idles forever")
    assert_match(/exec 'bundle', 'exec', 'rake', 'solid_queue:start'/, src)
  end

  test "production enqueues to solid_queue (durable), not the in-process async adapter" do
    assert_match(/^\s*config\.active_job\.queue_adapter = :solid_queue$/,
                 File.read(Rails.root.join("config/environments/production.rb")))
  end
end
