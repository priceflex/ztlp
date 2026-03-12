# frozen_string_literal: true

module Api
  class HealthController < BaseController
    # GET /api/networks/:network_id/health
    def network_health
      network = Network.find(params[:network_id])
      machines_data = network.machines.includes(:health_checks).map do |machine|
        {
          id: machine.id,
          hostname: machine.hostname,
          ip_address: machine.ip_address,
          status: machine.health_status,
          components: machine.health_summary,
          last_check_at: machine.last_health_check_at
        }
      end

      render json: {
        network: {
          id: network.id,
          name: network.name,
          zone: network.zone,
          status: network.health_status,
          summary: network.health_summary
        },
        machines: machines_data
      }
    end

    # GET /api/machines/:id/health
    def machine_health
      machine = Machine.find(params[:id])
      recent_checks = machine.health_checks.recent.limit(20)

      render json: {
        machine: {
          id: machine.id,
          hostname: machine.hostname,
          ip_address: machine.ip_address,
          status: machine.health_status,
          last_check_at: machine.last_health_check_at
        },
        components: machine.health_summary,
        recent_checks: recent_checks.map { |check|
          {
            id: check.id,
            component: check.component,
            status: check.status,
            metrics: check.parsed_metrics,
            container_state: check.container_state,
            error_message: check.error_message,
            response_time_ms: check.response_time_ms,
            checked_at: check.checked_at
          }
        }
      }
    end
  end
end
