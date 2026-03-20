# frozen_string_literal: true

class StatusController < ApplicationController
  before_action :set_network

  def index
    @devices = @network.ztlp_devices.includes(:ztlp_user).order(:name)
    @online_count = @network.ztlp_devices.online.count
    @total_count = @network.ztlp_devices.count

    # Bandwidth aggregation (last hour)
    bandwidth = DeviceHeartbeat.aggregate_bandwidth(@network.id)
    @bytes_sent = bandwidth&.first || 0
    @bytes_received = bandwidth&.last || 0

    # Connection timeline (last 100 events, filterable)
    events_scope = @network.connection_events.recent.includes(:ztlp_device, :ztlp_user)
    if params[:event_type].present? && ConnectionEvent::VALID_EVENT_TYPES.include?(params[:event_type])
      events_scope = events_scope.of_type(params[:event_type])
    end
    @page = (params[:page] || 1).to_i
    @per_page = 100
    @events = events_scope.limit(@per_page).offset((@page - 1) * @per_page)
    @events_total = events_scope.count

    # User sessions — users with at least one online device
    @online_users = @network.ztlp_users.active.includes(:ztlp_devices)
                           .select { |u| u.ztlp_devices.any?(&:online?) }

    # Sparkline data: hourly online device counts for last 24h
    @sparkline_data = build_sparkline_data
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def build_sparkline_data
    heartbeats = DeviceHeartbeat.where(network_id: @network.id)
                                .where("created_at > ?", 24.hours.ago)
                                .select(:ztlp_device_id, :created_at)

    # Group by hour and count unique devices
    hourly = heartbeats.group_by { |hb| hb.created_at.beginning_of_hour }
    hours = (0..23).map { |i| (24 - i).hours.ago.beginning_of_hour }
    hours.map { |h| hourly[h]&.map(&:ztlp_device_id)&.uniq&.count || 0 }
  end
end
