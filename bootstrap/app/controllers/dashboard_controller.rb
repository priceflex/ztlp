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

    # Health stats
    all_statuses = Machine.all.map(&:health_status)
    @health_stats = {
      total: all_statuses.count,
      healthy: all_statuses.count { |s| s == "healthy" },
      degraded: all_statuses.count { |s| s == "degraded" },
      down: all_statuses.count { |s| s == "down" },
      unknown: all_statuses.count { |s| s == "unknown" }
    }

    @active_alerts = Alert.active.recent.limit(5)

    # Identity stats
    @identity_stats = {
      users: ZtlpUser.count,
      users_active: ZtlpUser.active.count,
      devices: ZtlpDevice.count,
      devices_enrolled: ZtlpDevice.enrolled.count,
      groups: ZtlpGroup.count,
      revoked_users: ZtlpUser.revoked.count,
      revoked_devices: ZtlpDevice.revoked.count
    }
    @pending_tokens = EnrollmentToken.usable.count
    @recent_enrollments = ZtlpDevice.enrolled.order(enrolled_at: :desc).limit(5)
  end
end
