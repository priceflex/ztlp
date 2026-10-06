# frozen_string_literal: true

class LoginChallenge < ApplicationRecord
  TTL = 120.seconds
  belongs_to :admin

  scope :live, -> { where(used_at: nil).where("expires_at > ?", Time.current) }

  def self.issue!(admin)
    create!(admin: admin, nonce: SecureRandom.hex(32), expires_at: TTL.from_now)
  end

  def consume!
    with_lock do
      raise ActiveRecord::RecordInvalid, self if used_at || expires_at <= Time.current

      update!(used_at: Time.current)
    end
  end
end
