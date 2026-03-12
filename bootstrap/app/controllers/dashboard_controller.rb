class DashboardController < ApplicationController
  def index
    @networks = Network.all.includes(:machines, :enrollment_tokens)
    @recent_deployments = Deployment.recent.includes(machine: :network).limit(5)
    @recent_audit_logs = AuditLog.recent.limit(10)
    @machine_stats = {
      total: Machine.count,
      ready: Machine.ready.count,
      error: Machine.where(status: "error").count,
      pending: Machine.where(status: "pending").count
    }
  end
end
