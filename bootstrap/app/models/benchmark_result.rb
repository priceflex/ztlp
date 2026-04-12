# frozen_string_literal: true

class BenchmarkResult < ApplicationRecord
  self.table_name = "benchmarks"
  belongs_to :ztlp_device, optional: true, class_name: "ZtlpDevice"
  belongs_to :network

  validates :app_version, presence: true
  validates :benchmarks_passed, presence: true
  validates :benchmarks_total, presence: true

  scope :recent, -> { order(created_at: :desc).limit(50) }
  scope :by_network, ->(net_id) { where(network_id: net_id).order(created_at: :desc) }

  def all_passed?
    benchmarks_passed == benchmarks_total
  end

  def memory_ok?
    ne_memory_pass != false && ne_memory_mb.to_i <= 15
  end
end
