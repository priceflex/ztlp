require "test_helper"

class AuditLogTest < ActiveSupport::TestCase
  test "record creates audit log" do
    machine = machines(:ns1)
    log = AuditLog.record(
      action: "test_action",
      target: machine,
      status: "success",
      details: { foo: "bar" },
      ip_address: "10.0.1.1"
    )

    assert log.persisted?
    assert_equal "test_action", log.action
    assert_equal "Machine", log.target_type
    assert_equal machine.id, log.target_id
    assert_equal "10.0.1.1", log.ip_address
  end

  test "parsed_details returns hash" do
    log = AuditLog.record(action: "test", details: { key: "value" })
    parsed = log.parsed_details
    assert_equal "value", parsed["key"]
  end

  test "parsed_details handles nil" do
    log = AuditLog.record(action: "test")
    assert_nil log.parsed_details
  end

  test "parsed_details handles non-JSON" do
    log = AuditLog.create!(action: "test", details: "plain text")
    assert_equal "plain text", log.parsed_details
  end

  test "scopes" do
    AuditLog.record(action: "a", status: "success")
    AuditLog.record(action: "b", status: "failure")

    assert AuditLog.recent.first.created_at >= AuditLog.recent.last.created_at
    assert AuditLog.failures.all? { |l| l.status == "failure" }
  end

  # --- Phase C: "skipped" status -----------------------------------------
  #
  # Added in 2026-05-24 Phase C. `AuditLog#status` now accepts "skipped"
  # so a job legitimately skipping work on a shared production Machine
  # row (`Machine#shared?` → `Ztlp::EnsureSharedMachines` seed) can still
  # leave a forensic-grade audit trail without forcing the entry into the
  # misleading `"failure"` bucket.

  test "status inclusion accepts the documented set of states" do
    %w[success failure skipped].each do |s|
      log = AuditLog.new(action: "test.action", status: s)
      assert log.valid?, "expected status=#{s.inspect} to be valid: #{log.errors.full_messages.join(', ')}"
    end
  end

  test "status inclusion rejects unknown values" do
    log = AuditLog.new(action: "test.action", status: "indeterminate")
    refute log.valid?
    assert_includes log.errors[:status].join, "is not included in the list"
  end

  test "VALID_STATUSES constant matches validator" do
    assert_equal %w[success failure skipped], AuditLog::VALID_STATUSES
  end

  test ".record(status: 'skipped') writes a row with the given status" do
    log = AuditLog.record(
      action: "deploy",
      status: "skipped",
      details: { reason: "shared_infrastructure" }
    )
    assert_equal "skipped", log.status
    assert_equal "deploy", log.action
    assert_match(/shared_infrastructure/, log.details)
  end

  test "skips scope returns only rows with status='skipped'" do
    AuditLog.record(action: "deploy", status: "success")
    skipped = AuditLog.record(action: "deploy", status: "skipped",
                              details: { reason: "shared_infrastructure" })

    skips = AuditLog.skips
    assert_includes skips, skipped
    assert(skips.all? { |l| l.status == "skipped" })
  end
end
