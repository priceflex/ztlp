require "test_helper"
require "rake"

class ZtlpNsSyncRakeTest < ActiveSupport::TestCase
  setup do
    Rails.application.load_tasks if Rake::Task.tasks.empty?
    Rake::Task["ztlp:ns:sync"].reenable
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
end
