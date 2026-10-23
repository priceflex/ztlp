# frozen_string_literal: true

# Slice 11a: break-glass acknowledgement (spec Slice 11).
#
# The Overview Setup checklist asks a super admin to confirm they can SSH to
# the host and run the break-glass runbook (`admin:reset_claim`) if every
# administrator key is lost. The acknowledgement stores a timestamp + admin
# id in system_settings and writes an audit row. It proves NOTHING about the
# host — it is a "I read and accept the runbook now" checkbox, so the panel
# does not nag about it forever.
class SetupController < ApplicationController
  before_action :require_super_admin, only: [ :acknowledge_breakglass ]

  def acknowledge_breakglass
    ts = Time.current.iso8601
    SystemSetting["breakglass_acknowledged_at"] = ts
    SystemSetting["breakglass_acknowledged_by"] = current_admin.id.to_s
    AuditLog.record!("system.breakglass_acknowledged", admin: current_admin, status: "ok",
                      details: { acknowledged_at: ts, admin_username: current_admin.username })
    redirect_to root_path, notice: "Break-glass runbook acknowledged."
  end
end
