class Network < ApplicationRecord
  has_many :machines, dependent: :destroy
  has_many :enrollment_tokens, dependent: :destroy
  has_many :deployments, through: :machines
  has_many :health_checks, through: :machines
  has_many :alerts, dependent: :destroy

  encrypts :enrollment_secret_ciphertext
  encrypts :zone_key_ciphertext

  validates :name, presence: true, uniqueness: true
  validates :zone, presence: true, uniqueness: true,
    format: { with: /\A[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\z/, message: "must be a valid ZTLP zone name" }
  validates :status, inclusion: { in: %w[created deploying active error] }

  scope :active, -> { where(status: "active") }

  def roles_in_use
    machines.flat_map(&:role_list).uniq.sort
  end

  def machine_count_by_role
    machines.each_with_object(Hash.new(0)) do |machine, counts|
      machine.role_list.each { |r| counts[r] += 1 }
    end
  end

  def deployable?
    machines.any? && machines.all? { |m| m.role_list.any? }
  end

  def ns_machines
    machines.select { |m| m.role_list.include?("ns") }
  end

  def relay_machines
    machines.select { |m| m.role_list.include?("relay") }
  end

  def gateway_machines
    machines.select { |m| m.role_list.include?("gateway") }
  end

  def health_status
    statuses = machines.map(&:health_status)
    return "unknown" if statuses.empty? || statuses.all? { |s| s == "unknown" }
    return "down" if statuses.any? { |s| s == "down" }
    return "degraded" if statuses.any? { |s| s == "degraded" }
    "healthy"
  end

  def health_summary
    total = machines.count
    statuses = machines.map(&:health_status)
    {
      total: total,
      healthy: statuses.count { |s| s == "healthy" },
      degraded: statuses.count { |s| s == "degraded" },
      down: statuses.count { |s| s == "down" },
      unknown: statuses.count { |s| s == "unknown" }
    }
  end
end
