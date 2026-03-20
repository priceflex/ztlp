# frozen_string_literal: true

class DeviceHeartbeat < ApplicationRecord
  belongs_to :ztlp_device
  belongs_to :network

  validates :ztlp_device_id, presence: true
  validates :network_id, presence: true

  scope :recent, -> { order(created_at: :desc) }
  scope :for_device, ->(device_id) { where(ztlp_device_id: device_id) }
  scope :for_network, ->(network_id) { where(network_id: network_id) }
  scope :since, ->(time) { where("created_at > ?", time) }

  # Returns hourly counts of unique online devices in a network over the last 24h
  def self.hourly_online_counts(network_id, hours: 24)
    since_time = hours.hours.ago
    where(network_id: network_id)
      .where("created_at > ?", since_time)
      .group_by_hour
      .map { |hour, heartbeats| [hour, heartbeats.map(&:ztlp_device_id).uniq.count] }
  end

  # Aggregate bandwidth for a network
  def self.aggregate_bandwidth(network_id, since: 1.hour.ago)
    where(network_id: network_id)
      .where("created_at > ?", since)
      .pick(Arel.sql("COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)"))
  end

  private

  def self.group_by_hour
    all.group_by { |hb| hb.created_at.beginning_of_hour }
       .sort_by(&:first)
  end
end
