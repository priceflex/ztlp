# frozen_string_literal: true

module Ztlp
  # Renders a gateway's access policy in the format THAT gateway parses (Slice 9a, reviewed
  # 2026-10-23 against the gateway sources in priceflex/ztlp):
  #
  #   rust_listen -> policy.toml for `ztlp listen --policy`, read by proto/src/policy.rs
  #                  `from_toml`, a LINE-BASED parser: `default = "deny"`, then per service
  #                  `[[services]]` / `name = "<service>"` / single-line `allow = [ ... ]`.
  #                  `<service>` is the listener's `--forward <name>:<addr>` name, i.e. the
  #                  application name; the backend is shown as that `--forward` flag (comment).
  #   elixir      -> one env line `ZTLP_GATEWAY_POLICIES=<identity>:<service>,...`
  #                  (gateway/lib/ztlp_gateway/config.ex parse_policy_entry).
  #
  # Always renders a document: a missing/unloadable policy file means ALLOW-ALL on the Rust
  # gateway (ztlp-cli.rs:5242), so "no applications" must still say default deny.
  # Fail-closed: a rule literal that could corrupt either line parser (anything outside
  # [A-Za-z0-9*._@:-]) is omitted and listed as an "# OMITTED" comment, never emitted.
  # Disabled applications are left out (Rust: absent service = default deny).
  class PolicyRenderer
    SAFE_LITERAL = /\A[A-Za-z0-9*._@:-]+\z/
    SAFE_SERVICE = /\A[A-Za-z0-9._-]+\z/

    def self.render(gateway)
      apps = gateway.applications.where(enabled: true).order(:name).includes(:policy_rules).to_a
      gateway.kind == "elixir" ? render_elixir(gateway, apps) : render_toml(gateway, apps)
    end

    # Applications (all of the gateway's) that carry a `group:` rule pointing at
    # `group` — regardless of the application's enabled state, because a disabled
    # app's rule is still stored and re-appears if it is re-enabled. Powers the
    # Groups directory's "Applications referencing this group" (7a placeholder) and
    # the pre-destroy guard on the group page.
    def self.apps_for_group(gateway, group)
      rule_app_ids = PolicyRule.where(subject_type: "group", subject_value: group.ns_name).select(:application_id)
      gateway.applications.where(id: rule_app_ids).order(:name).to_a
    end

    class << self
      private

      # [[safe literals], [omitted literals]] in rule order.
      def literals(app)
        all = app.policy_rules.sort_by { |r| [ r.position.to_i, r.id ] }.map(&:render).compact
        all.partition { |l| l.match?(SAFE_LITERAL) }
      end

      def forward_flag(app)
        app.backend.present? ? "--forward #{app.name}:#{app.backend.to_s.sub(%r{\Ahttps?://}, "")}" : nil
      end

      def render_toml(gateway, apps)
        lines = [ "# policy.toml for gateway #{gateway.name} (ztlp listen --policy)",
                  "# Rule changes need a gateway restart; group membership changes are live.",
                  "default = \"deny\"" ]
        apps.each do |app|
          lines << ""
          unless app.name.match?(SAFE_SERVICE)
            lines << "# OMITTED application with an unsafe name"
            next
          end
          safe, omitted = literals(app)
          lines << "# #{app.ztlp_name}" << "[[services]]" << "name = \"#{app.name}\""
          lines << "allow = [#{safe.map { |l| "\"#{l}\"" }.join(", ")}]"
          flag = forward_flag(app)
          lines << "# #{flag}" if flag
          omitted.each { lines << "# OMITTED unsafe rule literal (fix the rule)" }
        end
        "#{lines.join("\n")}\n"
      end

      def render_elixir(gateway, apps)
        entries = []
        notes = []
        apps.each do |app|
          next notes << "# OMITTED application with an unsafe name" unless app.name.match?(SAFE_SERVICE)

          safe, omitted = literals(app)
          safe.each { |l| entries << "#{l}:#{app.name}" }
          omitted.each { notes << "# OMITTED unsafe rule literal (fix the rule) on #{app.name}" }
          notes << "# #{app.name}: no rules (denied)" if safe.empty?
        end
        [ "# Elixir gateway #{gateway.name}: set in its environment, then restart it.",
          *notes,
          "ZTLP_GATEWAY_POLICIES=#{entries.join(",")}" ].join("\n") + "\n"
      end
    end
  end
end
