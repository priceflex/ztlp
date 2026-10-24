# frozen_string_literal: true

module Ztlp
  # The 30-minute drift check (spec Slice 5). Lists user/device/group
  # records from the NS admin API and compares them to the panel rows,
  # storing the result as JSON in system_settings `ns_drift_json` —
  # per-type panel/NS counts + missing/extra names (for the /zone drift
  # table). Names never go into the audit row; only the counts do.
  #
  # `ns_client:` is the seam (default: the real Ztlp::NsClient class, whose
  # `list` method takes (port, secret, type:, zone:)).
  class Reconciler
    TYPES = %w[user device group].freeze

    def self.default_ns_client = NsClient

    # `now:` is the wall clock for `checked_at` (default: Time.now.to_i).
    # Injectable so tests can pin it.
    # Always records an outcome in ns_drift_json["status"]: "ok", "failed" (+ "error") or
    # "not_configured" (no NS admin API secret yet). Never raises on an NS failure: the
    # overview's NS dot and the /zone page read this status.
    def self.run(zone, admin: nil, ns_client: default_ns_client, now: Time.now.to_i)
      port = ns_admin_port(zone)
      secret = zone.ns_admin_api_secret_ct
      if secret.blank?
        SystemSetting[("ns_drift_json")] = { "zone" => zone.name, "checked_at" => now, "status" => "not_configured" }.to_json
        return :not_configured
      end

      drift = { "zone" => zone.name, "checked_at" => now, "status" => "ok" }
      begin
        TYPES.each do |type|
          ns_records = ns_client.list(port, secret, type: type, zone: zone.name)
          ns_names = ns_records.map { |r| r[:name] || r["name"] }.compact
          panel_names = panel_names_for(zone, type)

          drift[type] = {
            "panel" => panel_names.size,
            "ns" => ns_names.size,
            "missing_in_ns" => (panel_names - ns_names).sort,
            "extra_in_ns" => (ns_names - panel_names).sort
          }
        end
      rescue NsClient::NsError => e
        error = format("0x%02X %s", e.code, e.reason)
        SystemSetting[("ns_drift_json")] = { "zone" => zone.name, "checked_at" => now, "status" => "failed",
                                             "error" => error }.to_json
        AuditLog.record!("ns.reconcile", admin: admin, target: zone, status: "failed", details: { error: error })
        return :failed
      end

      SystemSetting[("ns_drift_json")] = drift.to_json
      AuditLog.record!("ns.reconcile", admin: admin, target: zone, status: "ok",
                        details: audit_counts(drift))
      :ok
    end

    # The port the NS admin HTTP API listens on. Reads
    # ZTLP_NS_ADMIN_BASE_URL (docker-compose sets it to the metrics port)
    # and falls back to the NS UDP port's sibling (9103).
    def self.ns_admin_port(zone)
      # (`match?` does not set Regexp.last_match: the old form returned 0 whenever the URL was set.)
      port = ENV["ZTLP_NS_ADMIN_BASE_URL"].to_s[%r{\Ahttps?://[^:/\s]+:(\d+)}, 1]
      port ? port.to_i : 9103
    end

    # Only rows the panel PUBLISHES (same sets as Republisher): active users, enrolled devices,
    # all groups. Invited users / pending or revoked devices are never in the NS by design.
    def self.panel_names_for(zone, type)
      case type
      when "user" then zone.users.where(status: "active").order(:ns_name).pluck(:ns_name)
      when "device" then zone.devices.where(status: "enrolled").order(:ns_name).pluck(:ns_name)
      when "group" then zone.groups.order(:ns_name).pluck(:ns_name)
      else raise ArgumentError, "unknown type: #{type}"
      end
    end

    def self.audit_counts(drift)
      TYPES.each_with_object({}) do |type, h|
        h["#{type}_panel"] = drift.dig(type, "panel")
        h["#{type}_ns"] = drift.dig(type, "ns")
      end
    end
  end
end
