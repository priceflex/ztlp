# frozen_string_literal: true

class HealthCheck < ApplicationRecord
  belongs_to :machine

  VALID_COMPONENTS = %w[ns relay gateway].freeze
  VALID_STATUSES = %w[healthy degraded down unknown].freeze

  validates :component, presence: true, inclusion: { in: VALID_COMPONENTS }
  validates :status, presence: true, inclusion: { in: VALID_STATUSES }
  validates :checked_at, presence: true

  scope :recent, -> { order(checked_at: :desc) }
  scope :for_component, ->(comp) { where(component: comp) }
  scope :healthy, -> { where(status: "healthy") }
  scope :degraded, -> { where(status: "degraded") }
  scope :down, -> { where(status: "down") }
  scope :since, ->(time) { where("checked_at >= ?", time) }

  def parsed_metrics
    return {} if metrics.blank?
    JSON.parse(metrics)
  rescue JSON::ParserError
    {}
  end

  def healthy?
    status == "healthy"
  end

  def degraded?
    status == "degraded"
  end

  def down?
    status == "down"
  end

  # Get the latest health check for each machine+component
  def self.latest_per_machine_component
    subquery = select("MAX(id) as max_id")
      .group(:machine_id, :component)

    where(id: subquery.map(&:max_id))
  end

  # Summary stats for a set of health checks
  def self.status_counts
    group(:status).count
  end
end
