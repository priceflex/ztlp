# frozen_string_literal: true

module Api
  class AlertsController < BaseController
    # GET /api/alerts
    def index
      alerts = Alert.recent.includes(:network, :machine)

      if params[:severity].present?
        alerts = alerts.where(severity: params[:severity])
      end

      if params[:status] == "active"
        alerts = alerts.active
      elsif params[:status] == "resolved"
        alerts = alerts.resolved
      end

      alerts = alerts.limit(params[:limit]&.to_i || 100)

      render json: {
        alerts: alerts.map { |alert|
          {
            id: alert.id,
            network: alert.network.name,
            machine: alert.machine.hostname,
            component: alert.component,
            severity: alert.severity,
            message: alert.message,
            acknowledged: alert.acknowledged,
            acknowledged_at: alert.acknowledged_at,
            resolved_at: alert.resolved_at,
            created_at: alert.created_at
          }
        },
        meta: {
          total_active: Alert.active_count
        }
      }
    end
  end
end
