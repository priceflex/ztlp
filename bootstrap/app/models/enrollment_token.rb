# frozen_string_literal: true

# An EnrollmentToken is a short-lived, single-(or limited-)use credential
# that allows a device to enroll into a ZTLP network. The token carries:
#
#   * a network reference (which zone the enrolling device will join),
#   * a `token_id` — the opaque hex identifier embedded in the
#     `ztlp://enroll/?token=...` URI handed to the device,
#   * a `max_uses` / `current_uses` pair (defaults to 1 for the
#     Z2LS-driven single-device flow but supports kiosk-style multi-use),
#   * an `expires_at` deadline (default 24h from creation, per Steve's
#     2026-05-23 brief — "Enrollment tokens should last 24 hours by
#     default"),
#   * a coarse `status` of `active | exhausted | expired | revoked`.
#
# Lifecycle invariants:
#
#   * Status only ever progresses from `active` → terminal
#     (`exhausted`/`expired`/`revoked`). Terminal states are sticky and
#     do not reset.
#   * `use!` is atomic against concurrent callers via `with_lock` — two
#     devices racing on the same token cannot both succeed.
#   * `revoke!` on an already-terminal token is a no-op (returns false)
#     so an admin double-clicking "Revoke" doesn't overwrite the
#     authoritative reason (`exhausted` becoming `revoked` would lose
#     the fact that the device successfully enrolled).
#   * Every successful state transition writes an `AuditLog` row. The
#     daily `EnrollmentToken.sweep_expired!` sweep does the same.
#
# See `docs/enrollment_token_lifecycle.md` for the operator-facing
# walkthrough and the Hermes session handoff (`~/hermes_session_handoff.md`
# BS-PR-1) for the design rationale.
class EnrollmentToken < ApplicationRecord
  belongs_to :network
  belongs_to :ztlp_user, optional: true

  # Default token lifetime per the Z2LS / ZTLP Bootstrap API brief.
  # Single source of truth — every caller that creates an EnrollmentToken
  # without an explicit `expires_at:` ends up here via the
  # `set_default_expires_at` before_validation hook.
  DEFAULT_LIFETIME = 24.hours

  VALID_STATUSES = %w[active exhausted expired revoked].freeze
  TERMINAL_STATUSES = %w[exhausted expired revoked].freeze

  # Phase A — the two principal kinds a freshly-minted token can be
  # bound to. Both columns are NULLABLE for backward compatibility:
  # tokens minted before Phase A keep working with both columns nil.
  # The DASHBOARD controller is where presence is enforced; the model
  # only pins the inclusion + the device/user paired-presence
  # invariant (you can't have a target_label without a target_kind,
  # and vice versa).
  TARGET_KINDS = %w[device user].freeze

  validates :token_id, presence: true, uniqueness: true
  validates :max_uses, numericality: { greater_than: 0 }
  validates :current_uses, numericality: { greater_than_or_equal_to: 0 }
  validates :expires_at, presence: true
  validates :status, inclusion: { in: VALID_STATUSES }

  validates :target_kind, inclusion: { in: TARGET_KINDS }, allow_nil: true
  # Paired-presence: target_kind and target_label must either BOTH be
  # set (a bound token) or BOTH be nil (a legacy / unbound token).
  validates :target_label, presence: true, if: -> { target_kind.present? }
  validates :target_kind,  presence: true, if: -> { target_label.present? }

  scope :active, -> { where(status: "active").where("expires_at > ?", Time.current) }
  scope :usable, -> { active.where("current_uses < max_uses") }
  scope :past_expiry_but_active, lambda {
    where(status: "active").where("expires_at <= ?", Time.current)
  }

  before_validation :generate_token_id, on: :create
  before_validation :set_default_expires_at, on: :create

  # Public: default expiry for a freshly-created token. Reading the
  # constant in two places lets tests assert what the default is without
  # duplicating the literal.
  def self.default_expires_at
    DEFAULT_LIFETIME.from_now
  end

  def expired?
    expires_at < Time.current
  end

  def exhausted?
    current_uses >= max_uses
  end

  def usable?
    status == "active" && !expired? && !exhausted?
  end

  # Phase A — Predicate helpers for views that need to render
  # "for device X" vs "for user Y" differently.
  def device_target?
    target_kind == "device"
  end

  def user_target?
    target_kind == "user"
  end

  # Atomically consume one use of the token. Uses an `UPDATE ... WHERE`
  # guarded by the current_uses we observed inside the row lock, so two
  # racing threads cannot both increment beyond `max_uses`. Returns
  # `true` on a successful consume, `false` otherwise (token already
  # terminal, expired, or exhausted).
  #
  # Writes a `token_used` audit log entry on success and, if this use
  # exhausts the token, a `token_exhausted` audit log entry.
  def use!
    with_lock do
      # Re-check usability inside the lock — another transaction may
      # have transitioned the token between the controller's read and
      # our lock acquisition.
      reload
      return false unless usable?

      previous_uses = current_uses
      update!(current_uses: previous_uses + 1)

      AuditLog.record(
        action: "enrollment_token.used",
        target: self,
        details: {
          token_id: token_id,
          uses_before: previous_uses,
          uses_after: current_uses,
          max_uses: max_uses
        }
      )

      if current_uses >= max_uses
        update!(status: "exhausted")
        AuditLog.record(
          action: "enrollment_token.exhausted",
          target: self,
          details: { token_id: token_id, max_uses: max_uses }
        )
      end

      true
    end
  end

  # Administratively revoke a token. No-op (returns false) on tokens
  # that are already in a terminal state — terminal states are sticky
  # and we don't want a "revoked" stomp on the truthful `exhausted`
  # outcome of a successful enrollment.
  #
  # On success writes a `token_revoked` audit log entry.
  def revoke!
    return false if TERMINAL_STATUSES.include?(status)

    update!(status: "revoked")

    AuditLog.record(
      action: "enrollment_token.revoked",
      target: self,
      details: { token_id: token_id }
    )

    true
  end

  # Check the wall-clock-vs-DB-status invariant and reconcile if the
  # row has drifted (e.g., the token was created with status=active,
  # the row was never `use!`d, and the deadline passed). Idempotent on
  # already-terminal tokens.
  #
  # On a transition from active → expired (or active → exhausted, for
  # the rare case where `current_uses` was bumped out-of-band) writes
  # the corresponding `enrollment_token.{expired,exhausted}` audit
  # entry.
  def refresh_status!
    return false unless status == "active"

    if expired?
      update!(status: "expired")
      AuditLog.record(
        action: "enrollment_token.expired",
        target: self,
        details: { token_id: token_id, expired_at: expires_at }
      )
      true
    elsif exhausted?
      update!(status: "exhausted")
      AuditLog.record(
        action: "enrollment_token.exhausted",
        target: self,
        details: { token_id: token_id, max_uses: max_uses }
      )
      true
    else
      false
    end
  end

  # Bulk-mark every `active`-status token whose `expires_at` is in the
  # past as `expired`. Designed to be called by a daily cron / rake
  # task (`rails ztlp:tokens:sweep_expired`) so the DB doesn't carry
  # ever-growing piles of stale active rows.
  #
  # Returns the count of tokens transitioned. Writes a single
  # `enrollment_token.sweep_expired` audit entry summarising the run so
  # operators can grep the audit log without one event per token.
  def self.sweep_expired!
    transitioned_ids = []

    past_expiry_but_active.find_each do |token|
      if token.refresh_status!
        transitioned_ids << token.id
      end
    end

    if transitioned_ids.any?
      AuditLog.record(
        action: "enrollment_token.sweep_expired",
        target: nil,
        details: {
          count: transitioned_ids.size,
          token_ids: transitioned_ids.first(100)
        }
      )
    end

    transitioned_ids.size
  end

  private

  def generate_token_id
    self.token_id ||= SecureRandom.hex(8)
  end

  def set_default_expires_at
    self.expires_at ||= self.class.default_expires_at
  end
end
