# frozen_string_literal: true

require "test_helper"

# Slice 5b-i: the three solid_queue jobs. They are thin dispatchers:
# RepublishNsJob → Ztlp::Republisher, ReconcileNsJob → Ztlp::Reconciler,
# ExpireEnrollmentsJob → Enrollment.expire_due!. The service-level behaviour
# is pinned by the republisher/reconciler service tests; this file proves
# the wiring: the job names the right zone, the right service, with the
# right args, and surfaces NS errors as job errors.
#
# NOTE: mocha BLOCK stubs do not run in this harness (mocha 3.1.0 — probed
# 2026-10-22); these tests use mocha EXPECTATIONS (not block stubs).
class JobsTest < ActiveSupport::TestCase
  def setup
    seed, pub = Ztlp::Ed25519.generate
    @zone = Zone.create!(name: "test.ztlp", ns_addr: "127.0.0.1:23096", authority_seed_ct: seed)
    @admin = Admin.create!(username: "steve", display_name: "Steve", pubkey_hex: pub,
                           role: "super_admin")
  end

  def perform(klass, *args)
    klass.perform_now(*args)
  end

  def test_republish_ns_job_delegates_to_republisher_for_primary_zone
    # The job must call Ztlp::Republisher.run(Zone.primary, admin: nil).
    Ztlp::Republisher.expects(:run).with(@zone, admin: nil).returns(:ok)
    # perform_now returns the job's return value directly (the service's
    # :ok). The mocha expectation above IS the proof of the wiring.
    assert_equal :ok, perform(RepublishNsJob)
  end

  def test_republish_ns_job_surfaces_ns_error_as_job_error
    err = Ztlp::NsClient::NsError.new(0x0C, "timeout")
    Ztlp::Republisher.expects(:run).with(@zone, admin: nil).raises(err)
    assert_raises(Ztlp::NsClient::NsError) { perform(RepublishNsJob) }
  end

  def test_reconcile_ns_job_delegates_to_reconciler
    Ztlp::Reconciler.expects(:run).with(@zone, admin: nil).returns(:ok)
    assert_equal :ok, perform(ReconcileNsJob)
  end

  def test_reconcile_ns_job_surfaces_ns_error_as_job_error
    err = Ztlp::NsClient::NsError.new(0x0C, "timeout")
    Ztlp::Reconciler.expects(:run).with(@zone, admin: nil).raises(err)
    assert_raises(Ztlp::NsClient::NsError) { perform(ReconcileNsJob) }
  end

  def test_expire_enrollments_job_expires_only_pending_rows
    zone = @zone
    due = zone.enrollments.create!(token_id: Enrollment.generate_token_id, kind: "user_device",
                                   status: "pending", expires_at: 1.hour.ago)
    not_due = zone.enrollments.create!(token_id: Enrollment.generate_token_id, kind: "user_device",
                                       status: "pending", expires_at: 1.hour.from_now)
    redeemed = zone.enrollments.create!(token_id: Enrollment.generate_token_id, kind: "user_device",
                                        status: "redeemed", expires_at: 1.hour.ago)

    perform(ExpireEnrollmentsJob)

    assert_equal "expired", due.reload.status
    assert_equal "pending", not_due.reload.status
    assert_equal "redeemed", redeemed.reload.status
  end
end
