class AuditLogsController < ApplicationController
  def index
    @audit_logs = AuditLog.recent.limit(100)
  end
end
