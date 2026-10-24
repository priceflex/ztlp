# frozen_string_literal: true

# Slice 11a: Overview (root) — tally strip, Setup checklist, recent activity,
# infra panel (spec Slice 11). The pre-11 dashboard rendered admins/zone/
# authority/Build; the spec Overview tallies USERS/DEVICES/GROUPS/APPLICATIONS
# and surfaces the setup checklist + infra status.
class DashboardController < ApplicationController
  BREAKGLASS_CMD = "docker exec ztlp-admin-web /rails/bin/docker-entrypoint ./bin/rails admin:reset_claim"

  def show
    @admins = Admin.order(:username)
    @recent_audit = AuditLog.order(created_at: :desc).limit(20).includes(:admin)
    @tally = {
      "users" => zone_users.count,
      "devices" => zone_devices.count,
      "groups" => @zone&.groups.count.to_i,
      "applications" => Application.where(gateway_id: zone_gateway_ids).count
    }
    @checklist = setup_checklist
    @checklist_open = @checklist.any? { |i| !i["done"] }
    @drift = parse_drift(SystemSetting[Ztlp::Reconciler.drift_key(@zone)])
    @gateways = @zone ? @zone.gateways.order(:name) : []
  end

  private

  def zone_users
    @zone ? @zone.users : User.none
  end

  def zone_devices
    @zone ? @zone.devices : Device.none
  end

  def zone_gateway_ids
    return [] unless @zone

    @zone.gateways.pluck(:id)
  end

  # spec Slice 11: second administrator, break-glass acknowledged, authority
  # imported, NS admin API secret set; ZTLP_MIN_ASSURANCE is INFO only (the
  # gate's floor is read from the ENV at request time and is not a zone row).
  def setup_checklist
    min_assurance = ENV["ZTLP_MIN_ASSURANCE"]
    admins = Admin.active.count # spec: a disabled admin is not a second key
    list = [
      { "done" => admins >= 2, "label" => "Add a second administrator",
        "sub" => "one lost key locks the panel out (break-glass covers it, but it is slow)" },
      { "done" => breakglass_acknowledged?, "label" => "Acknowledge the break-glass runbook",
        "sub" => "If every administrator key is lost, run this on the host over SSH (certificate auth). " \
                 "Confirm you can SSH to the host now.",
        "cmd" => BREAKGLASS_CMD },
      { "done" => @zone&.authority_configured? == true, "label" => "Import the zone authority",
        "sub" => "zone:import_authority[/data/identity.json] on the host" },
      { "done" => @zone&.ns_admin_secret.present? == true,
        "label" => "Set the NS admin API secret", "sub" => "zone:set_secret[ns_admin_api] reads it from stdin" }
    ].reject { |item| item["done"] }
    list << { "done" => true, "label" => "ZTLP_MIN_ASSURANCE=#{min_assurance.presence || 'unknown'} (info only)",
              "sub" => "the assurance floor is read from the app's ENV at request time; not stored per zone" }
    list
  end

  def breakglass_acknowledged? = SystemSetting["breakglass_acknowledged_at"].present?

  def parse_drift(raw)
    raw.present? ? JSON.parse(raw) : nil
  rescue JSON::ParserError
    nil
  end
end
