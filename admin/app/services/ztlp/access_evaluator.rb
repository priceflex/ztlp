# frozen_string_literal: true

module Ztlp
  # Evaluate whether a device may use an application on its gateway,
  # mirroring the GATEWAY (not the spec prose) — STATUS 2026-10-23 01:55Z:
  #
  # proto/src/policy.rs: the client identity on a Rust gateway is the DEVICE
  # ns name. Plain literals match exactly ("*" = all, "*.suffix" = suffix);
  # only "group:" and "role:" resolve device -> owner. A "user" literal is a
  # plain literal, so it NEVER matches a device identity -> the decision is
  # deny with a reason that says a group is the right subject.
  #
  # min_assurance is NOT enforced by the Rust gateway (it has no assurance
  # check); it is enforced by the panel's mandatory gateway gate only. The
  # evaluator therefore always reports `assurance_enforced: false` while
  # still computing the deny/allow the panel gate would apply.
  # Per gateway kind (reviewed 2026-10-23 against priceflex/ztlp HEAD):
  #   rust_listen (proto/src/policy.rs): "*", exact device name; group:/role: resolve the device's
  #     OWNER via NS (DEVICE.owner -> GROUP.members / USER.role); a user literal never equals a
  #     device identity.
  #   elixir (gateway/lib/ztlp_gateway/policy_engine.ex): identity = the device name its key
  #     resolves to; group:/role: check THAT identity directly (is_group_member?/user_role) with no
  #     owner step, and GROUP members are user names -> group/role/user rules never match a device.
  # There is no owner pre-check in either gateway (an ownerless device can match "*" / its name).
  # min_assurance: G6 -- the Rust gateway has no per-service floor; the Elixir floor is per-route
  # config the panel does not render. So the floor is reported as a WARNING with
  # assurance_enforced: false and never changes the gateway's decision.
  class AccessEvaluator
    def self.evaluate(device, application, ns_client: NsClient)
      trace = []
      warnings = []
      kind = application.gateway&.kind || "rust_listen"

      return result("deny", "device is #{device.status} (not enrolled)", trace, warnings) unless device.enrolled?

      owner = device.user
      if owner && %w[revoked disabled].include?(owner.status)
        return result("deny", "owner #{owner.username} is #{owner.status}", trace, warnings)
      end
      return result("deny", "application #{application.name} is disabled", trace, warnings) unless application.enabled

      if device.assurance.to_i < application.min_assurance.to_i
        warnings << "Device assurance #{device.assurance} is below the application minimum " \
                    "#{application.min_assurance}, but the minimum is not enforced by #{kind} gateways."
      end

      zone = device.zone
      ns_port = Reconciler.ns_admin_port(zone)
      ns_secret = zone.ns_admin_secret
      application.policy_rules.order(:position, :id).each do |rule|
        res, why = rule_result(rule, device: device, owner: owner, zone: zone, kind: kind,
                                     ns_client: ns_client, ns_port: ns_port, ns_secret: ns_secret)
        trace << { rule: rule_label(rule), result: res, why: why }
        return result("allow", "rule #{rule_label(rule)} matched", trace, warnings) if res == "allow"
      end

      last = trace.last
      result("deny", last && last[:why] ? last[:why] : "default deny (no rule matched)", trace, warnings)
    end

    def self.result(decision, reason, trace, warnings)
      { decision: decision, reason: reason, trace: trace, warnings: warnings, assurance_enforced: false }
    end
    private_class_method :result

    # policy.rs matches_pattern: "*" matches everything; "*.suffix" matches
    # identities ending in ".suffix" (or equal to suffix); otherwise exact.
    def self.literal_matches?(pattern, identity)
      return true if pattern == "*"

      if pattern.start_with?("*.")
        suffix = pattern[2..]
        return identity.end_with?(".#{suffix}") || identity == suffix
      end

      identity == pattern
    end

    def self.rule_label(rule)
      case rule.subject_type
      when "any" then "any"
      when "role" then "role"
      when "group" then "group"
      when "user" then "user"
      when "device" then "device"
      else rule.subject_type.to_s
      end
    end

    # => ["allow"|"deny", why-string].
    def self.rule_result(rule, device:, owner:, zone:, kind:, ns_client:, ns_port:, ns_secret:)
      if kind == "elixir" && %w[group role user].include?(rule.subject_type)
        return [ "deny", "#{rule.subject_type} rules never match a device on elixir gateways " \
                         "(no owner lookup); use '*' or the device" ]
      end
      if owner.nil? && %w[group role].include?(rule.subject_type)
        return [ "deny", "device has no owner, so #{rule.subject_type} rules cannot match it" ]
      end

      case rule.subject_type
      when "any"
        [ "allow", "'*' matches every authenticated identity" ]
      when "group"
        group = Group.find_by(id: rule.subject_id)
        ns_name = rule.subject_value || group&.ns_name
        return [ "deny", "group #{ns_name} no longer exists in the panel" ] if ns_name.blank?
        return [ "deny", "group #{ns_name} no longer exists in the panel" ] if group.nil?

        members = group_members(ns_name, zone, ns_client, ns_port, ns_secret,
                                fallback: group)
        if members.nil?
          [ "deny", "NS group record unavailable for #{ns_name} (fail-closed)" ]
        elsif members.include?(owner.ns_name)
          [ "allow", "owner #{owner.username} is a member of group #{ns_name}" ]
        else
          [ "deny", "owner #{owner.username} is not a member of group #{ns_name}" ]
        end
      when "role"
        if owner.role == rule.subject_value
          [ "allow", "owner #{owner.username} has role #{owner.role}" ]
        else
          [ "deny", "owner #{owner.username} has role #{owner.role}, not #{rule.subject_value}" ]
        end
      when "user"
        # Gateway semantics (policy.rs matches_pattern): a user literal is a
        # plain literal compared against the DEVICE identity — it can never
        # equal a device ns name. Mirrored here, with the operator-facing
        # note the review pinned.
        [ "deny", "user rules don't match devices on rust_listen gateways; use a group" ]
      when "device"
        if rule.render == device.ns_name
          [ "allow", "exact device match #{device.ns_name}" ]
        else
          [ "deny", "device literal #{rule.render} does not equal #{device.ns_name}" ]
        end
      else
        [ "deny", "unknown subject type #{rule.subject_type.inspect}" ]
      end
    end

    # Group membership from the NS GROUP record (the same source the
    # gateway resolves), with a fail-closed fallback to the panel row.
    # `fallback:` is the panel Group (nil when the row was deleted).
    def self.group_members(ns_name, zone, ns_client, ns_port, ns_secret, fallback:)
      if ns_secret.present? && ns_client
        records = ns_client.list(ns_port, ns_secret, type: "group", zone: zone.name)
        record = records.find { |r| (r[:name] || r["name"]) == ns_name }
        if record
          data = record[:data] || record["data"] || {}
          members = data["members"]
          return Array(members).map(&:to_s) if members.is_a?(Array)
        end
        return nil # NS reachable but no such group record: fail-closed
      end

      if fallback
        fallback.users.pluck(:ns_name).compact
      else
        nil
      end
    rescue NsClient::NsError
      fallback ? fallback.users.pluck(:ns_name).compact : nil
    end
  end
end
