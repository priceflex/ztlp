# frozen_string_literal: true

module Ztlp
  # Renders a gateway's policy allow-list from its applications + rules
  # (Slice 9a). This is the panel's VIEW of the policy the gateway sees; the
  # gateway reads its own records — the renderer exists so an operator can see
  # and copy exactly what the gateway will enforce before restarting it
  # (spec Slice 9: "Rule changes need a gateway restart").
  #
  # Output is per gateway kind:
  #   rust_listen -> TOML (default = "deny", one [[services]] per enabled app)
  #   elixir      -> YAML (default: deny, one list entry per enabled app)
  #
  # Fail-closed: a rule whose subject cannot be resolved (the group row lost
  # its ns_name, the user was deleted) renders nothing for that rule rather
  # than emitting a literal the gateway would match against.
  class PolicyRenderer
    # Renders the gateway's policy document, or nil if it has no enabled
    # applications (an empty allow-list is the default-deny state and needs
    # no document).
    def self.render(gateway)
      apps = gateway.applications.where(enabled: true).order(:name).includes(:policy_rules)
      return nil if apps.empty?

      case gateway.kind
      when "elixir" then render_yaml(gateway, apps)
      else render_toml(gateway, apps)
      end
    end

    class << self
      private

      # The rule's literal as the gateway sees it. `PolicyRule#render`
      # resolves the subject by DB id; when the group row is deleted it falls
      # back to the rule's stored subject_value (the ns_name, pinned at create
      # time), so the operator sees the exact literal the gateway will match
      # even if the group row is gone. role/any subjects cannot be
      # unresolvable (no entity lookup).
      def rule_literal(rule)
        rule.render
      end

      def toml_string(value)
        %("#{value.to_s.gsub('"', '\\"').gsub("\\", "\\\\\\")}")
      end

      # Backends: when the protocol has a scheme in the backend string, the
      # protocol is redundant and the backend stands alone; otherwise the
      # protocol prefixes the bare address (e.g. protocol "http" + backend
      # "10.0.0.5:8080" -> "http://10.0.0.5:8080").
      def backend_urls(app)
        backend = app.backend.to_s
        return [ backend ] if backend.match?(%r{\Ahttps?://})

        protocol = app.protocol.to_s
        protocol.empty? ? [ backend ] : [ "#{protocol}://#{backend}" ]
      end

      def render_toml(gateway, apps)
        lines = [ "default = \"deny\"", "" ]
        apps.each do |app|
          lines << "[[services]]"
          lines << "ztlp = #{toml_string(app.ztlp_name)}"
          backends = backend_urls(app)
          lines << "backends = #{backends.map { |b| toml_string(b) }.join(", ")}" if backends.any?
          literals = app.policy_rules.order(:position, :id).map { |r| rule_literal(r) }.compact
          lines << "allow = [#{literals.map { |l| toml_string(l) }.join(", ")}]"
          lines << ""
        end
        lines.join("\n")
      end

      def render_yaml(gateway, apps)
        lines = [ "default: deny", "services:" ]
        apps.each do |app|
          lines << "  - ztlp: #{app.ztlp_name}"
          backend_urls(app).each { |b| lines << "    backend: #{b}" }
          literals = app.policy_rules.order(:position, :id).map { |r| rule_literal(r) }.compact
          if literals.any?
            lines << "    allow:"
            literals.each { |l| lines << "      - #{l}" }
          else
            lines << "    allow: []"
          end
        end
        lines.join("\n")
      end
    end
  end
end
