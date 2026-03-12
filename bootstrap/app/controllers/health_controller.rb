# frozen_string_literal: true

class HealthController < ApplicationController
  before_action :set_network
  before_action :set_machine, only: [:machine_health, :check_machine_health]

  # GET /networks/:network_id/health
  def network_health
    @machines = @network.machines.includes(:health_checks)
    @summary = @network.health_summary
    @recent_alerts = @network.alerts.active.recent.limit(10)
  end

  # GET /networks/:network_id/machines/:machine_id/health
  def machine_health
    @health_checks = @machine.health_checks.recent.limit(50)
    @health_summary = @machine.health_summary
    @recent_alerts = @machine.alerts.recent.limit(10)
    @history = health_history(@machine)
  end

  # POST /networks/:network_id/check_health
  def check_health
    HealthCheckJob.perform_later(@network.id)
    redirect_to network_health_path(@network), notice: "Health check started for all machines in #{@network.name}"
  end

  # POST /networks/:network_id/machines/:machine_id/check_health
  def check_machine_health
    checker = HealthChecker.new(@machine)

    begin
      checker.check_all
      redirect_to health_network_machine_path(@network, @machine), notice: "Health check completed for #{@machine.hostname}"
    rescue StandardError => e
      redirect_to health_network_machine_path(@network, @machine), alert: "Health check failed: #{e.message}"
    end
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_machine
    @machine = @network.machines.find(params[:machine_id] || params[:id])
  end

  # Build health history data for charts (last 24 hours)
  def health_history(machine)
    machine.health_checks
      .where("checked_at >= ?", 24.hours.ago)
      .order(checked_at: :asc)
      .group_by(&:component)
  end
end
