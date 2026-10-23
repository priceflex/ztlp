# frozen_string_literal: true

require "test_helper"
require "rake"
require "rake/testtask"

# Slice 11c: the admin:reset_claim break-glass rake task (spec §4.1 step 6).
# Container-local command, NEVER a web route. Issues a fresh claim code
# (Claim.issue!(force: true)) and audits system.reset_claim.
class AdminResetClaimTaskTest < ActiveSupport::TestCase
  def load_task
    Rake.application = Rake::Application.new
    Rake.application.load_rakefile
    Rake::Task["admin:reset_claim"].reenable
  end

  def capture_stdout
    buf = StringIO.new
    old = $stdout
    $stdout = buf
    begin
      yield
    ensure
      $stdout = old
    end
    buf.string
  end

  def setup
    @zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
  end

  test "issues a fresh valid claim code even when admins already exist" do
    make_admin
    load_task
    refute Claim.code_valid?("AAAA-AAAA")
    output = capture_stdout { Rake::Task["admin:reset_claim"].invoke }

    m = output.match(/Claim code: ([A-Z2-7]{4}(?:-[A-Z2-7]{1,4})+)/)
    assert m, "no claim code line in: #{output.inspect[0, 400]}"
    code = m[1]
    assert Claim.code_valid?(code)
    assert_match(/break-glass/, output)
  end

  test "prints the host runbook line, not a web route" do
    load_task
    output = capture_stdout { Rake::Task["admin:reset_claim"].invoke }
    assert_match(/docker exec ztlp-admin-web/, output)
    assert_match(/bin\/rails admin:reset_claim/, output)
  end

  test "audits system.reset_claim" do
    make_admin
    load_task
    capture_stdout { Rake::Task["admin:reset_claim"].invoke }
    assert AuditLog.exists?(action: "system.reset_claim")
  end

  test "a forced claim with the issued code creates an additional super_admin" do
    _existing, _seed = make_admin
    load_task
    output = capture_stdout { Rake::Task["admin:reset_claim"].invoke }
    m = output.match(/Claim code: ([A-Z2-7]{4}(?:-[A-Z2-7]{1,4})+)/)
    assert m, "no claim code line"
    code = m[1]

    _seed2, pub2 = Ztlp::Ed25519.generate
    admin = Claim.perform!({ claim_code: code, username: "roberta", display_name: "Roberta",
                             email: "", pubkey_hex: pub2 }, force: true)
    assert_equal "super_admin", admin.role
    assert_equal 2, Admin.count
  end
end
