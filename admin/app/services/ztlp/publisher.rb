# frozen_string_literal: true

module Ztlp
  # The single seam between panel rows and the name server.
  #
  # Every NS write flows through here: build the record data with
  # Ztlp::Records (the PII boundary), sign it with the zone's authority
  # seed, and audit `ns.publish` with {name, type, result} — NEVER the
  # record data itself (spec §6.2 / §11: secrets and record contents do not
  # go into audit rows).
  #
  # The NS client is an injectable seam (`ns_client:`) defaulting to the real
  # Ztlp::NsClient class, whose `register` method (class or instance) is
  # called with the keyword contract register(ns_addr, timeout, name:,
  # type:, data:, seed:).
  class Publisher
    NS_TIMEOUT = 5

    # ── public API ─────────────────────────────────────────────────

    # Publish the USER record (0x11) for `user` to its zone.
    def self.publish_user!(user, ns_client: NsClient, admin: nil, **kw)
      publish!(user, "user", Records.user_data(user), ns_client: ns_client, admin: admin, **kw)
    end

    # Publish the GROUP record (0x12) for `group` to its zone.
    def self.publish_group!(group, ns_client: NsClient, admin: nil, **kw)
      publish!(group, "group", Records.group_data(group), ns_client: ns_client, admin: admin, **kw)
    end

    # Publish the DEVICE record (0x10) for `device` to its zone.
    def self.publish_device!(device, ns_client: NsClient, admin: nil, **kw)
      publish!(device, "device", Records.device_data(device), ns_client: ns_client, admin: admin, **kw)
    end

    # Write a REVOKE record (0x05) for `name` in `zone`. `target` (optional)
    # is the panel row the revocation applies to — used only for the audit
    # row's target. Never republishes the entity.
    def self.revoke!(zone, name:, reason: nil, target: nil, ns_client: NsClient, admin: nil, **kw)
      data = Records.revoke_data(name, reason)
      seed = zone.authority_seed_ct # 64-hex Ed25519 seed (identity.json signing_key_seed)
      audit_target = target || zone

      result = begin
        # REVOKE records live at "revoke.<name>" (ztlp-cli.rs:11293 `admin revoke`).
        call_register(ns_client, zone.ns_addr, name: "revoke.#{name}", type: "revoke",
                      data: data, seed: seed, **kw)
        :ok
      rescue NsClient::NsError => e
        audit(zone, "ns.publish", audit_target, "failed",
              { "name" => name, "type" => "revoke", "result" => format("0x%02X %s", e.code, e.reason) },
              admin)
        raise
      end

      audit(zone, "ns.publish", audit_target, "ok",
            { "name" => name, "type" => "revoke", "result" => "ok" }, admin)
      result
    end

    # Publish the zone's authority KEY record (0x01) — the record the zone's
    # own authority signs, self-registered (registration_auth.ex:290-298).
    # The KEY is republished on every republish cycle so a fresh NS copy can
    # verify records the zone's authority has already written.
    def self.publish_authority!(zone, ns_client: NsClient, admin: nil, **kw)
      raise NsClient::NsError.new(0x00, "no_authority") unless zone.authority_configured?

      seed = zone.authority_seed_ct
      name = zone.name # the zone name IS the KEY record's name

      result = begin
        call_register(ns_client, zone.ns_addr, name: name, type: "key",
                      data: Records.authority_data(zone), seed: seed, **kw)
        :ok
      rescue NsClient::NsError => e
        audit(zone, "ns.publish", zone, "failed",
              { "name" => name, "type" => "key", "result" => format("0x%02X %s", e.code, e.reason) },
              admin)
        raise
      end

      audit(zone, "ns.publish", zone, "ok",
            { "name" => name, "type" => "key", "result" => "ok" }, admin)
      result
    end

    # ── internals ──────────────────────────────────────────────────

    # Shared happy/failure path for the three publish_*! methods.
    def self.publish!(entity, type, data, ns_client:, admin: nil, **kw)
      zone = entity.zone
      raise NsClient::NsError.new(0x00, "no_authority") unless zone.authority_configured?

      name = entity.ns_name
      seed = zone.authority_seed_ct

      result = begin
        call_register(ns_client, zone.ns_addr, name: name, type: type, data: data,
                      seed: seed, **kw)
        entity.update_column(:ns_published_at, Time.current)
        :ok
      rescue NsClient::NsError => e
        audit(zone, "ns.publish", entity, "failed",
              { "name" => name, "type" => type, "result" => format("0x%02X %s", e.code, e.reason) },
              admin)
        raise
      end

      audit(zone, "ns.publish", entity, "ok",
            { "name" => name, "type" => type, "result" => "ok" }, admin)
      result
    end

    def self.call_register(ns_client, ns_addr, name:, type:, data:, seed:, **kw)
      args = { name: name, type: type, data: data, seed: seed }.merge(kw)
      ns_client.respond_to?(:register) ? ns_client.register(ns_addr, NS_TIMEOUT, **args)
                                       : ns_client.call(ns_addr, NS_TIMEOUT, **args)
    end

    def self.audit(zone, action, target, status, details, admin)
      # Target the entity's own class/id when given; fall back to the zone.
      AuditLog.record!(action, admin: admin,
                       target: target.is_a?(ActiveRecord::Base) ? target : zone,
                       status: status, details: details)
    end
  end
end
