# frozen_string_literal: true

# Checks health of all machines in a given network.
# Broadcasts results via Turbo Streams for real-time dashboard updates.
class HealthCheckJob < ApplicationJob
  queue_as :default

  def perform(network_id)
    network = Network.find_by(id: network_id)
    return unless network

    network.machines.each do |machine|
      next unless machine.role_list.any?

      begin
        checker = HealthChecker.new(machine)
        results = checker.check_all

        # Broadcast health update for this machine
        broadcast_machine_health(machine, results)
      rescue StandardError => e
        Rails.logger.error("[HealthCheckJob] Failed checking #{machine.hostname}: #{e.message}")
      end
    end

    # Broadcast network-level summary
    broadcast_network_health(network)
  end

  private

  def broadcast_machine_health(machine, results)
    Turbo::StreamsChannel.broadcast_replace_to(
      "health_network_#{machine.network_id}",
      target: "machine_health_#{machine.id}",
      html: render_machine_health_card(machine)
    )
  rescue StandardError => e
    Rails.logger.warn("[HealthCheckJob] Broadcast failed for machine #{machine.id}: #{e.message}")
  end

  def broadcast_network_health(network)
    Turbo::StreamsChannel.broadcast_replace_to(
      "health_dashboard",
      target: "network_health_#{network.id}",
      html: render_network_health_summary(network)
    )
  rescue StandardError => e
    Rails.logger.warn("[HealthCheckJob] Broadcast failed for network #{network.id}: #{e.message}")
  end

  def render_machine_health_card(machine)
    ApplicationController.render(
      partial: "health/machine_health_card",
      locals: { machine: machine }
    )
  end

  def render_network_health_summary(network)
    ApplicationController.render(
      partial: "health/network_health_summary",
      locals: { network: network }
    )
  end
end
