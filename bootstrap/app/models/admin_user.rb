# frozen_string_literal: true

class AdminUser < ApplicationRecord
  has_secure_password

  ROLES = %w[super_admin admin read_only].freeze
  LOCKOUT_THRESHOLD = 5
  LOCKOUT_DURATION = 15.minutes

  validates :email, presence: true,
                    uniqueness: { case_sensitive: false },
                    format: { with: /\A[^@\s]+@[^@\s]+\z/, message: "must be a valid email address" }
  validates :name, presence: true
  validates :role, presence: true, inclusion: { in: ROLES }

  scope :ordered, -> { order(:name) }

  def super_admin?
    role == "super_admin"
  end

  def admin?
    role == "admin"
  end

  def read_only?
    role == "read_only"
  end

  def locked?
    locked_until.present? && locked_until > Time.current
  end

  def lock!
    update!(locked_until: LOCKOUT_DURATION.from_now)
  end

  def unlock!
    update!(locked_until: nil, failed_login_attempts: 0)
  end

  def record_login!(ip)
    update!(
      failed_login_attempts: 0,
      last_login_at: Time.current,
      last_login_ip: ip,
      locked_until: nil
    )
  end

  def record_failed_login!
    new_count = failed_login_attempts + 1
    update!(failed_login_attempts: new_count)
    lock! if new_count >= LOCKOUT_THRESHOLD
  end

  def lockout_minutes_remaining
    return 0 unless locked?
    ((locked_until - Time.current) / 60.0).ceil
  end
end
