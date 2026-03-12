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
end
