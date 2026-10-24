# frozen_string_literal: true

module Ztlp
  # Copy the NS directory of the panel's zone (users, devices, groups) into the panel DB, in the
  # PANEL's naming convention (spec F4 + §12 step 5): NS user "steve@trs.ztlp" -> panel user
  # "steve" (ns_name "steve.users.trs.ztlp", derived by the model); NS group "blitz@trs.ztlp" ->
  # panel group "blitz"; devices keep their "<label>.<zone>" names. The original NS name is kept in
  # the row's notes/description for reference.
  #
  # READ-ONLY toward the NS: lists via the NS admin API (/admin/records, the Reconciler seam) and
  # never publishes, so the existing NS records stay exactly as they are. Idempotent: rows that
  # already exist (same username / group name / device ns_name) are reused, never modified.
  # Records outside the panel zone are ignored.
  #
  # Returns :not_configured (no NS admin API secret), or
  #   { created: {"users"=>n, "devices"=>n, "groups"=>n, "memberships"=>n},
  #     skipped: [ns names already present], errors: [strings] }
  class NsImporter
    TYPES = %w[user device group].freeze

    def self.run(zone, admin: nil, ns_client: NsClient)
      secret = zone.ns_admin_secret
      return :not_configured if secret.blank?

      new(zone, admin).run(ns_client, secret)
    end

    def initialize(zone, admin)
      @zone = zone
      @admin = admin
      @created = { "users" => 0, "devices" => 0, "groups" => 0, "memberships" => 0 }
      @skipped = []
      @errors = []
    end

    def run(ns_client, secret)
      port = Reconciler.ns_admin_port(@zone)
      records = TYPES.to_h { |t| [ t, ns_client.list(port, secret, type: t, zone: @zone.name) ] }
      ActiveRecord::Base.transaction do
        records["user"].each { |r| import_user(r) }
        records["device"].each { |r| import_device(r) }
        records["group"].each { |r| import_group(r) }
      end
      AuditLog.record!("ns.import", admin: @admin, target: @zone, status: "ok",
                                    details: { created: @created, skipped: @skipped.size, errors: @errors })
      result
    rescue NsClient::NsError => e
      @errors << format("NS list failed: 0x%02X %s", e.code, e.reason)
      AuditLog.record!("ns.import", admin: @admin, target: @zone, status: "failed", details: { errors: @errors })
      result
    end

    private

    def result = { created: @created, skipped: @skipped, errors: @errors }

    def field(rec, key) = rec[key.to_sym] || rec[key.to_s]

    def data_of(rec)
      d = field(rec, :data)
      d.is_a?(Hash) ? d.transform_keys(&:to_s) : {}
    end

    # "steve@trs.ztlp", "aipc@aicomputer.trs.ztlp", "box.trs.ztlp" are in zone trs.ztlp.
    def in_zone?(ns_name)
      ns_name.end_with?(".#{@zone.name}", "@#{@zone.name}")
    end

    def dns_label(str) = str.to_s.downcase.gsub(/[^a-z0-9-]+/, "-").gsub(/\A-+|-+\z/, "")[0, 63]

    # The panel username / group name an NS user or group name maps to:
    # "steve@trs.ztlp" / "steve.users.trs.ztlp" -> "steve"; "aipc@aicomputer.trs.ztlp" -> "aipc".
    def principal_label(ns_name)
      name = ns_name.to_s
      name.include?("@") ? dns_label(name.split("@", 2).first) : dns_label(name.split(".", 2).first)
    end

    def import_user(rec)
      ns_name = field(rec, :name).to_s
      return unless in_zone?(ns_name)

      label = principal_label(ns_name)
      return @skipped << ns_name if @zone.users.exists?(username: label)

      d = data_of(rec)
      email = d["email"].to_s
      @zone.users.create!(username: label, display_name: label, kind: "person",
                          role: d["role"].to_s == "admin" ? "admin" : "user", status: "active",
                          email: email.include?("@") && email != ns_name ? email : nil,
                          signing_pubkey_hex: d["public_key"].presence,
                          notes: "Imported from name server record #{ns_name}")
      @created["users"] += 1
    rescue ActiveRecord::RecordInvalid => e
      @errors << "#{ns_name}: #{e.record.errors.full_messages.to_sentence}"
    end

    def import_device(rec)
      ns_name = field(rec, :name).to_s
      return unless ns_name.end_with?(".#{@zone.name}")

      label = dns_label(ns_name.delete_suffix(".#{@zone.name}"))
      return @skipped << ns_name if @zone.devices.exists?(name: label)

      d = data_of(rec)
      owner = d["owner"].to_s.presence && @zone.users.find_by(username: principal_label(d["owner"]))
      key_source = Assurance::KEY_SOURCES.include?(d["key_source"].to_s) ? d["key_source"].to_s : "unknown"
      @zone.devices.create!(name: label, status: "enrolled", user: owner || nil,
                            node_id_hex: d["node_id"].presence, noise_pubkey_hex: d["public_key"].presence,
                            assurance: Assurance.level(d["assurance"]), key_source: key_source)
      @created["devices"] += 1
    rescue ActiveRecord::RecordInvalid => e
      @errors << "#{ns_name}: #{e.record.errors.full_messages.to_sentence}"
    end

    def import_group(rec)
      ns_name = field(rec, :name).to_s
      return unless in_zone?(ns_name)

      label = principal_label(ns_name)
      return @skipped << ns_name if @zone.groups.exists?(name: label)

      d = data_of(rec)
      desc = [ d["description"].to_s.presence, "imported from #{ns_name}" ].compact.join(" - ")
      group = @zone.groups.create!(name: label, description: desc[0, 255])
      @created["groups"] += 1
      Array(d["members"]).each do |m|
        user = @zone.users.find_by(username: principal_label(m))
        next @errors << "#{ns_name}: member #{m} is not in the panel" unless user

        group.group_memberships.create!(user: user, added_by_admin: @admin)
        @created["memberships"] += 1
      end
    rescue ActiveRecord::RecordInvalid => e
      @errors << "#{ns_name}: #{e.record.errors.full_messages.to_sentence}"
    end
  end
end
