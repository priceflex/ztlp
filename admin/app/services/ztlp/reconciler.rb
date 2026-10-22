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
    def self.run(zone, admin: nil, ns_client: default_ns_client, now: Time.now.to_i)
      port = ns_admin_port(zone)
      secret = zone.ns_admin_api_secret_ct
      raise NsClient::NsError.new(0x00, "no_ns_admin_api_secret") if secret.blank?

      drift = { "zone" => zone.name, "checked_at" => now }
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

      SystemSetting[("ns_drift_json")] = drift.to_json
      AuditLog.record!("ns.reconcile", admin: admin, target: zone, status: "ok",
                        details: audit_counts(drift))
      :ok
    end

    # The port the NS admin HTTP API listens on. Reads
    # ZTLP_NS_ADMIN_BASE_URL (docker-compose sets it to the metrics port)
    # and falls back to the NS UDP port's sibling (9103).
    def self.ns_admin_port(zone)
      base = ENV["ZTLP_NS_ADMIN_BASE_URL"].to_s
      if base.match?(%r{\Ahttps?://[^:/]+:(\d+)})
        Regexp.last_match(1).to_i
      else
        9103
      end
    end

    def self.panel_names_for(zone, type)
      case type
      when "user" then zone.users.order(:ns_name).pluck(:ns_name)
      when "device" then zone.devices.order(:ns_name).pluck(:ns_name)
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
