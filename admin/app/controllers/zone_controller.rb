# frozen_string_literal: true

# Slice 5c: the /zone page (spec Slice 5, §2.1). Zone status — authority
# import, secrets, last publish/reconcile, the drift table from
# system_settings ns_drift_json — plus Publish now / Reconcile now
# (enqueue the solid_queue jobs; write access only).
class ZoneController < ApplicationController
  before_action :require_write_access, only: [ :publish, :reconcile ]

  def show
    @drift = drift_record
    @last_publish = last_audit
    @last_reconcile = last_reconcile_audit
  end

  def publish
    RepublishNsJob.perform_later
    audit!("zone.publish_now", target: @zone)
    redirect_to zone_path, notice: "Publish queued."
  end

  def reconcile
    ReconcileNsJob.perform_later
    audit!("zone.reconcile_now", target: @zone)
    redirect_to zone_path, notice: "Reconcile queued."
  end

  private

  def drift_record
    raw = SystemSetting[(
      "ns_drift_json"
    )]
    return {} if raw.blank?

    JSON.parse(raw)
  rescue JSON::ParserError
    {}
  end

  def last_audit
    AuditLog.where(action: "ns.publish", target_id: @zone.id).order(created_at: :desc).first
  end

  def last_reconcile_audit
    AuditLog.where(action: "ns.reconcile", target_id: @zone.id).order(created_at: :desc).first
  end
end
