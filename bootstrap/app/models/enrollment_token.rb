class EnrollmentToken < ApplicationRecord
  belongs_to :network

  validates :token_id, presence: true, uniqueness: true
  validates :max_uses, numericality: { greater_than: 0 }
  validates :current_uses, numericality: { greater_than_or_equal_to: 0 }
  validates :expires_at, presence: true
  validates :status, inclusion: { in: %w[active exhausted expired revoked] }

  scope :active, -> { where(status: "active").where("expires_at > ?", Time.current) }
  scope :usable, -> { active.where("current_uses < max_uses") }

  before_validation :generate_token_id, on: :create

  def expired?
    expires_at < Time.current
  end

  def exhausted?
    current_uses >= max_uses
  end

  def usable?
    status == "active" && !expired? && !exhausted?
  end

  def use!
    return false unless usable?

    increment!(:current_uses)
    update!(status: "exhausted") if current_uses >= max_uses
    true
  end

  def revoke!
    update!(status: "revoked")
  end

  # Check and update status based on current state
  def refresh_status!
    if status == "active"
      if expired?
        update!(status: "expired")
      elsif exhausted?
        update!(status: "exhausted")
      end
    end
  end

  private

  def generate_token_id
    self.token_id ||= SecureRandom.hex(8)
  end
end
