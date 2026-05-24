require "test_helper"

# Tests for the EnrollmentToken model lifecycle.
#
# Coverage matrix (BS-PR-1, 2026-05-23):
#
#   * Original 9 tests (pre-existing): scopes, basic use!, expired/exhausted
#     usable? states, token_id generation, revoke! transitions to revoked.
#
#   * New BS-PR-1 tests below cover the adversarial cases Steve asked for
#     in the Z2LS / bootstrap brief:
#
#     - Default 24h TTL on create (per the brief — "Enrollment tokens
#       should last 24 hours by default")
#     - Single-use enforcement: second use! returns false
#     - Atomicity: two threads racing use! never overflow current_uses
#     - revoke! is no-op on already-terminal tokens
#     - sweep_expired! transitions active+past-deadline rows to expired
#       and emits one summary audit log entry
#     - Audit log writes on use!, exhaustion, revoke!, expiry, and sweep
class EnrollmentTokenTest < ActiveSupport::TestCase
  # ── Original suite (kept verbatim) ──────────────────────────────

  test "active token is usable" do
    token = enrollment_tokens(:active_token)
    assert token.usable?
  end

  test "expired token is not usable" do
    token = enrollment_tokens(:expired_token)
    assert token.expired?
    assert_not token.usable?
  end

  test "exhausted token is not usable" do
    token = enrollment_tokens(:exhausted_token)
    assert token.exhausted?
    assert_not token.usable?
  end

  test "use! increments counter" do
    token = enrollment_tokens(:active_token)
    old_uses = token.current_uses
    assert token.use!
    assert_equal old_uses + 1, token.reload.current_uses
  end

  test "use! marks exhausted when max reached" do
    token = enrollment_tokens(:active_token)
    token.update!(current_uses: token.max_uses - 1)
    token.use!
    assert_equal "exhausted", token.reload.status
  end

  test "use! returns false when not usable" do
    token = enrollment_tokens(:expired_token)
    assert_not token.use!
  end

  test "revoke! sets status to revoked" do
    token = enrollment_tokens(:active_token)
    token.revoke!
    assert_equal "revoked", token.reload.status
    assert_not token.usable?
  end

  test "refresh_status! marks expired tokens" do
    token = enrollment_tokens(:expired_token)
    token.refresh_status!
    assert_equal "expired", token.reload.status
  end

  test "generates token_id if not provided" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1,
      expires_at: 24.hours.from_now,
      status: "active"
    )
    token.save!
    assert token.token_id.present?
    assert_equal 16, token.token_id.length  # hex(8) = 16 chars
  end

  test "scopes" do
    assert EnrollmentToken.active.all? { |t| t.status == "active" && t.expires_at > Time.current }
    assert EnrollmentToken.usable.all?(&:usable?)
  end

  # ── BS-PR-1: default 24h TTL ────────────────────────────────────

  test "defaults expires_at to ~24 hours when not provided" do
    pre = Time.current

    token = EnrollmentToken.create!(
      network: networks(:office),
      max_uses: 1,
      status: "active"
    )

    post = Time.current

    # Default lifetime is 24h ± a few seconds of test-runtime jitter.
    assert_in_delta 24.hours.to_i,
                    (token.expires_at - pre).to_i,
                    (post - pre).to_i + 2
    assert token.expires_at > 23.hours.from_now
  end

  test "honors explicit expires_at over the default" do
    deadline = 1.hour.from_now

    token = EnrollmentToken.create!(
      network: networks(:office),
      max_uses: 1,
      status: "active",
      expires_at: deadline
    )

    # Compare to-the-second; ActiveRecord storage may shave fractions.
    assert_in_delta deadline.to_i, token.expires_at.to_i, 1
  end

  test "DEFAULT_LIFETIME constant is 24 hours" do
    # Pinning the public contract: any future change to the default
    # must update this test consciously.
    assert_equal 24.hours, EnrollmentToken::DEFAULT_LIFETIME
  end

  # ── BS-PR-1: single-use enforcement ─────────────────────────────

  test "second use! of a single-use token returns false and does not increment" do
    token = EnrollmentToken.create!(
      network: networks(:office),
      max_uses: 1,
      status: "active"
    )

    assert token.use!, "first use should succeed"
    assert_equal 1, token.reload.current_uses
    assert_equal "exhausted", token.status

    # The second attempt must NOT increment current_uses — that's the
    # contract Steve called out: "Be invalid immediately after
    # successful enrollment" / "Consumed tokens cannot be reused".
    refute token.use!, "second use must return false"
    assert_equal 1, token.reload.current_uses
  end

  test "use! returns false on a revoked token even if uses remain" do
    token = enrollment_tokens(:active_token)
    token.update!(max_uses: 5, current_uses: 0, status: "revoked")
    refute token.use!
    assert_equal 0, token.reload.current_uses
  end

  test "use! returns false on a token whose expires_at is in the past" do
    token = enrollment_tokens(:active_token)
    token.update!(expires_at: 1.second.ago)
    refute token.use!
  end

  # ── BS-PR-1: atomicity ──────────────────────────────────────────

  test "use! is atomic under concurrent callers" do
    # Two callers racing on the same single-use token. Only one
    # should win; the other should get `false`. current_uses must end
    # at exactly max_uses, NOT 2x max_uses.
    token = EnrollmentToken.create!(
      network: networks(:office),
      max_uses: 1,
      status: "active"
    )

    results = Concurrent::Array.new
    barrier = Concurrent::CyclicBarrier.new(2)

    threads = 2.times.map do
      Thread.new do
        # ActiveRecord uses connection-per-thread; ensure each thread
        # has its own connection released cleanly even if it raises.
        ActiveRecord::Base.connection_pool.with_connection do
          barrier.wait
          fresh = EnrollmentToken.find(token.id)
          results << fresh.use!
        end
      end
    end

    threads.each(&:join)
    token.reload

    successes = results.count { |r| r == true }
    failures = results.count { |r| r == false }

    assert_equal 1, successes, "exactly one thread should win the race"
    assert_equal 1, failures, "exactly one thread should be rejected"
    assert_equal token.max_uses, token.current_uses,
                 "current_uses must not exceed max_uses under concurrency"
    assert_equal "exhausted", token.status
  end

  # ── BS-PR-1: revoke!() ──────────────────────────────────────────

  test "revoke! is a no-op on an already-exhausted token" do
    token = enrollment_tokens(:exhausted_token)
    refute token.revoke!
    assert_equal "exhausted", token.reload.status
  end

  test "revoke! is a no-op on an already-revoked token" do
    token = enrollment_tokens(:active_token)
    token.update!(status: "revoked")
    refute token.revoke!
    assert_equal "revoked", token.reload.status
  end

  test "revoke! is a no-op on an expired token" do
    token = enrollment_tokens(:active_token)
    token.update!(status: "expired")
    refute token.revoke!
    assert_equal "expired", token.reload.status
  end

  # ── BS-PR-1: sweep_expired! ─────────────────────────────────────

  test "sweep_expired! transitions only active+past-expiry rows" do
    stale_active = EnrollmentToken.create!(
      network: networks(:office),
      max_uses: 1,
      current_uses: 0,
      status: "active",
      expires_at: 1.minute.from_now
    )
    # Backdate AFTER creation so the before_validation default doesn't
    # override us, AND so validations (expires_at > something?) don't
    # interfere.
    stale_active.update_column(:expires_at, 1.hour.ago)

    fresh_active = EnrollmentToken.create!(
      network: networks(:office),
      max_uses: 1,
      current_uses: 0,
      status: "active",
      expires_at: 12.hours.from_now
    )

    already_exhausted = enrollment_tokens(:exhausted_token)
    already_expired_known = enrollment_tokens(:expired_token)
    already_expired_known.update!(status: "expired")

    transitioned = EnrollmentToken.sweep_expired!

    # The stale active token must transition; the freshly-active and
    # already-terminal rows must NOT change.
    assert_equal 1, transitioned,
                 "sweep should report exactly one transition"

    assert_equal "expired", stale_active.reload.status
    assert_equal "active", fresh_active.reload.status
    assert_equal "exhausted", already_exhausted.reload.status
    assert_equal "expired", already_expired_known.reload.status
  end

  test "sweep_expired! writes a single summary audit log" do
    # Set up two stale-active tokens to make the summary count > 1.
    [1, 2].each do |i|
      t = EnrollmentToken.create!(
        network: networks(:office),
        max_uses: 1,
        status: "active",
        expires_at: 1.hour.from_now,
        notes: "stale #{i}"
      )
      t.update_column(:expires_at, 1.hour.ago)
    end

    sweep_entries_before = AuditLog.where(action: "enrollment_token.sweep_expired").count

    EnrollmentToken.sweep_expired!

    sweep_entries_after = AuditLog.where(action: "enrollment_token.sweep_expired").count
    assert_equal sweep_entries_before + 1, sweep_entries_after,
                 "exactly one summary audit entry per sweep"
  end

  test "sweep_expired! is a no-op when no rows are eligible" do
    # Ensure the fixtures' expired_token has status=expired (it's
    # active in the fixture for one of the original tests).
    enrollment_tokens(:expired_token).update!(status: "expired")

    before_count = AuditLog.where(action: "enrollment_token.sweep_expired").count
    transitioned = EnrollmentToken.sweep_expired!
    after_count = AuditLog.where(action: "enrollment_token.sweep_expired").count

    assert_equal 0, transitioned
    # No transitions → no summary entry (avoid log churn).
    assert_equal before_count, after_count
  end

  # ── BS-PR-1: audit logging on transitions ───────────────────────

  test "use! writes a token_used audit log entry" do
    token = enrollment_tokens(:active_token)
    token.update!(max_uses: 5, current_uses: 0)

    assert_difference -> { AuditLog.where(action: "enrollment_token.used").count }, 1 do
      token.use!
    end

    entry = AuditLog.where(action: "enrollment_token.used").order(:id).last
    details = entry.parsed_details
    assert_equal token.token_id, details["token_id"]
    assert_equal 0, details["uses_before"]
    assert_equal 1, details["uses_after"]
  end

  test "use! writes a token_exhausted audit log when max_uses is reached" do
    token = enrollment_tokens(:active_token)
    token.update!(max_uses: 1, current_uses: 0)

    assert_difference -> { AuditLog.where(action: "enrollment_token.exhausted").count }, 1 do
      token.use!
    end
  end

  test "revoke! writes a token_revoked audit log entry on success" do
    token = enrollment_tokens(:active_token)

    assert_difference -> { AuditLog.where(action: "enrollment_token.revoked").count }, 1 do
      assert token.revoke!
    end
  end

  test "revoke! does NOT write an audit log when no-op" do
    token = enrollment_tokens(:exhausted_token)

    assert_no_difference -> { AuditLog.where(action: "enrollment_token.revoked").count } do
      refute token.revoke!
    end
  end

  # ── Phase A: target_kind / target_label ─────────────────────────
  #
  # Added 2026-05-25 (Phase A). Bind enrollment tokens to a principal
  # (device OR user) on mint, so dashboard tokens carry "who/what is
  # this for" instead of being loose. Schema migration added two
  # NULLABLE columns + a composite index; the controller layer is
  # what enforces presence on the dashboard path.

  test "TARGET_KINDS constant lists the two supported kinds" do
    assert_equal %w[device user], EnrollmentToken::TARGET_KINDS
  end

  test "target_kind accepts 'device'" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1, status: "active",
      target_kind: "device",
      target_label: "alice-laptop"
    )
    assert token.valid?, token.errors.full_messages.join(", ")
  end

  test "target_kind accepts 'user'" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1, status: "active",
      target_kind: "user",
      target_label: "alice"
    )
    assert token.valid?, token.errors.full_messages.join(", ")
  end

  test "target_kind nil is accepted (legacy / API tokens without explicit principal)" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1, status: "active"
    )
    assert token.valid?, token.errors.full_messages.join(", ")
    assert_nil token.target_kind
    assert_nil token.target_label
  end

  test "unknown target_kind is rejected" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1, status: "active",
      target_kind: "machine",  # not in TARGET_KINDS
      target_label: "x"
    )
    refute token.valid?
    assert_includes token.errors[:target_kind].join, "is not included in the list"
  end

  test "target_kind without target_label is rejected" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1, status: "active",
      target_kind: "device"
    )
    refute token.valid?
    assert_includes token.errors[:target_label].join, "can't be blank"
  end

  test "target_label without target_kind is rejected (avoid orphan label)" do
    token = EnrollmentToken.new(
      network: networks(:office),
      max_uses: 1, status: "active",
      target_label: "alice-laptop"
    )
    refute token.valid?
    assert_includes token.errors[:target_kind].join, "can't be blank"
  end

  test "device_target? and user_target? predicates" do
    device_token = EnrollmentToken.new(target_kind: "device", target_label: "x")
    user_token   = EnrollmentToken.new(target_kind: "user",   target_label: "x")
    legacy       = EnrollmentToken.new

    assert device_token.device_target?
    refute device_token.user_target?

    assert user_token.user_target?
    refute user_token.device_target?

    refute legacy.device_target?
    refute legacy.user_target?
  end
end
