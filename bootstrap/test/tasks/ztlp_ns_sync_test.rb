require "test_helper"
require "rake"

class ZtlpNsSyncRakeTest < ActiveSupport::TestCase
  setup do
    Rails.application.load_tasks if Rake::Task.tasks.empty?
    Rake::Task["ztlp:ns:sync"].reenable
    Ztlp::SyncState.reset!
  end

  teardown do
    Ztlp::SyncState.reset!
  end

  test "prints greppable status line and writes a success AuditLog" do
    fake_result = Ztlp::SyncNsToBootstrap::Result.new(
      status:   :ok,
      created:  5,
      updated:  2,
      orphaned: 1,
      skipped:  0,
      errors:   [],
      message:  "sync ok"
    )
    Ztlp::SyncNsToBootstrap.stubs(:call).returns(fake_result)

    before = AuditLog.count
    out, _err = capture_io { Rake::Task["ztlp:ns:sync"].invoke }

    assert_match(/\[ztlp:ns:sync\] status=ok created=5 updated=2 orphaned=1 skipped=0 errors=0/, out)
    assert_equal before + 1, AuditLog.count
    audit = AuditLog.where(action: "ztlp.ns.sync").order(:id).last
    assert_not_nil audit
    # AuditLog.status validation accepts only "success" / "failure" — the task
    # translates Result#status (:ok / :error) into that vocabulary.
    assert_equal "success", audit.status
    parsed = audit.parsed_details
    assert_equal 5, parsed["created"]
    assert_equal 2, parsed["updated"]
    assert_equal 1, parsed["orphaned"]
  end

  test "logs each error skip line and writes a failure AuditLog on error result" do
    fake_result = Ztlp::SyncNsToBootstrap::Result.new(
      status:   :error,
      created:  0,
      updated:  0,
      orphaned: 0,
      skipped:  2,
      errors:   [
        { name: "alice.dev.example", reason: "no_matching_network" },
        { name: "bob.dev.example",   reason: "no_matching_network" }
      ],
      message:  "transport failed"
    )
    Ztlp::SyncNsToBootstrap.stubs(:call).returns(fake_result)

    out, _err = capture_io { Rake::Task["ztlp:ns:sync"].invoke }

    assert_match(/\[ztlp:ns:sync\] status=error/, out)
    assert_match(/skip: alice\.dev\.example \(no_matching_network\)/, out)
    audit = AuditLog.where(action: "ztlp.ns.sync").order(:id).last
    assert_equal "failure", audit.status
    parsed = audit.parsed_details
    assert_equal 2, parsed["errors"].length
  end

  test "skips run when SyncState is not due (backoff active)" do
    Ztlp::SyncState.record_failure!(error_class: "TransportError")
    refute Ztlp::SyncState.due?

    Ztlp::SyncNsToBootstrap.expects(:call).never

    out, _err = capture_io { Rake::Task["ztlp:ns:sync"].invoke }
    assert_match(/\[ztlp:ns:sync\] skipped/, out)
    assert_match(/next_retry_at=/, out)
  end

  test "records SyncState success after a successful run" do
    Ztlp::SyncNsToBootstrap.stubs(:call).returns(
      Ztlp::SyncNsToBootstrap::Result.new(
        status: :ok, created: 1, updated: 0, orphaned: 0, skipped: 0,
        errors: [], message: "ok"
      )
    )

    capture_io { Rake::Task["ztlp:ns:sync"].invoke }

    state = Ztlp::SyncState.current
    refute_nil state[:last_success_at]
    assert_equal 0, state[:consecutive_failures]
    assert_nil state[:next_retry_at]
  end

  test "records SyncState failure with error_class after error result" do
    Ztlp::SyncNsToBootstrap.stubs(:call).returns(
      Ztlp::SyncNsToBootstrap::Result.new(
        status: :error, created: 0, updated: 0, orphaned: 0, skipped: 0,
        errors: [{ name: "x", reason: "boom" }], message: "TransportError"
      )
    )

    capture_io { Rake::Task["ztlp:ns:sync"].invoke }

    state = Ztlp::SyncState.current
    assert_equal 1, state[:consecutive_failures]
    assert_equal "TransportError", state[:last_error_class]
    refute_nil state[:next_retry_at]
  end
end
