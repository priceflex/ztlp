# frozen_string_literal: true

class AlertsController < ApplicationController
  # GET /alerts
  def index
    @alerts = Alert.recent.includes(:network, :machine)

    if params[:severity].present?
      @alerts = @alerts.where(severity: params[:severity])
    end

    if params[:status] == "active"
      @alerts = @alerts.active
    elsif params[:status] == "acknowledged"
      @alerts = @alerts.acknowledged_alerts
    elsif params[:status] == "resolved"
      @alerts = @alerts.resolved
    end

    @active_count = Alert.active_count
    @alerts = @alerts.limit(100)
  end

  # POST /alerts/:id/acknowledge
  def acknowledge
    alert = Alert.find(params[:id])
    alert.acknowledge!
    redirect_to alerts_path, notice: "Alert acknowledged"
  end

  # POST /alerts/acknowledge_all
  def acknowledge_all
    Alert.active.update_all(acknowledged: true, acknowledged_at: Time.current)
    redirect_to alerts_path, notice: "All active alerts acknowledged"
  end
end
