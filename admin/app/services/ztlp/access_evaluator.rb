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
  class AccessEvaluator
    # `ns_client:` is the seam for NS group-membership lookups (default:
    # Ztlp::NsClient, whose `list(port, secret, type:, zone:)` class method
    # is the same seam Reconciler uses). When nil or when the NS list call
    # fails, group rules fall back to the panel's Group row (stale but
    # honest: the rule still renders, and a dead NS must not silently
    # widen access — a group with an unreachable NS row denies).
    def self.evaluate(device, application, ns_client: NsClient)
      trace = []
      reason = nil
      decision = nil
      enforced = false

      unless device.enrolled?
        return deny!("device is #{device.status} (not enrolled)", trace, enforced: enforced)
      end
      unless (owner = device.user)
        return deny!("device has no owner assigned", trace, enforced: enforced)
      end
      if %w[revoked disabled].include?(owner.status)
        return deny!("owner #{owner.username} is #{owner.status}", trace, enforced: enforced)
      end
      unless application.enabled
        return deny!("application #{application.name} is disabled", trace, enforced: enforced)
      end

      # min_assurance: computed against the panel gate (not the gateway).
      # devices.assurance and applications.min_assurance are both integers
      # (1..4); Assurance.wire is the display/NS label only.
      if device.assurance.to_i < application.min_assurance.to_i
        return deny!("assurance #{device.assurance} below application minimum #{application.min_assurance}", trace)
      end
      enforced = true

      rules = application.policy_rules.order(:position, :id).to_a
      zone = device.zone
      ns_port = Reconciler.ns_admin_port(zone)
      ns_secret = zone.ns_admin_api_secret_ct

      rules.each do |rule|
        result, why = rule_result(rule, device: device, owner: owner, zone: zone,
                                  ns_client: ns_client, ns_port: ns_port, ns_secret: ns_secret)
        trace << { rule: rule_label(rule), result: result, why: why }
        if result == "allow"
          return { decision: "allow", reason: "rule #{rule_label(rule)} matched",
                   trace: trace, assurance_enforced: enforced }
        end
      end

      last = trace.last
      reason = if last && last[:result] == "deny" && last[:why]
                 last[:why]
      else
                 "default deny (no rule matched)"
      end
      deny!(reason, trace)
    end

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
    def self.rule_result(rule, device:, owner:, zone:, ns_client:, ns_port:, ns_secret:)
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

    def self.deny!(reason, trace, enforced: false)
      { decision: "deny", reason: reason, trace: trace, assurance_enforced: enforced }
    end

    private_class_method :deny!
  end
end
