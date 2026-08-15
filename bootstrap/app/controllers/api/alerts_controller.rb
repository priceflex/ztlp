# frozen_string_literal: true

module Api
  class AlertsController < BaseController
    before_action :authenticate_api_token!

    # GET /api/alerts
    def index
      alerts = @api_network.alerts.recent.includes(:network, :machine)

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
          total_active: @api_network.alerts.active.count
        }
      }
    end

    private

    def authenticate_api_token!
      token = request.headers["Authorization"].to_s.gsub(/^Bearer\s+/i, "").strip
      return render json: { error: "Unauthorized" }, status: :unauthorized if token.blank?

      @api_network = Network.all.find do |n|
        raw = n.read_attribute(:enrollment_secret_ciphertext)
        raw && raw.strip == token
      end

      return render json: { error: "Unauthorized" }, status: :unauthorized unless @api_network
    end
  end
end
