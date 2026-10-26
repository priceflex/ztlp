# frozen_string_literal: true

# One-time URL token exchanged for a browser session (spec §4.2 step 3).
class SessionToken < ApplicationRecord
  TTL = 60.seconds
  belongs_to :admin

  def self.issue!(admin)
    raw = SecureRandom.urlsafe_base64(32)
    create!(admin: admin, token_digest: digest(raw), expires_at: TTL.from_now)
    raw
  end

  def self.redeem!(raw)
    rec = find_by(token_digest: digest(raw.to_s))
    return nil unless rec

    rec.with_lock do
      return nil if rec.used_at || rec.expires_at <= Time.current

      rec.update!(used_at: Time.current)
    end
    rec.admin
  end

  def self.digest(raw) = Digest::SHA256.hexdigest(raw)
end
