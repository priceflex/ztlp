# frozen_string_literal: true

# Slice 9a (reviewed 2026-10-23): Ztlp::PolicyRenderer must emit what the REAL gateways parse.
#
# rust_listen = `ztlp listen --policy policy.toml`, parsed by proto/src/policy.rs `from_toml`: a
#   LINE-BASED parser that reads only `default = "…"`, `[[services]]`, `name = "<service>"` and a
#   single-line `allow = [ … ]` (split on ',', each item trimmed of '"'); every other line is
#   ignored. `<service>` is the listener's `--forward <name>:<addr>` name (ztlp-cli.rs resolves
#   svc_name from that registry). A policy file that fails to load, or no policy at all, means
#   ALLOW-ALL (ztlp-cli.rs:5242, PolicyEngine::allow_all), so a document is ALWAYS rendered.
# elixir = env ZTLP_GATEWAY_POLICIES, comma-separated "<identity>:<service>" entries
#   (gateway/lib/ztlp_gateway/config.ex parse_policy_entry; role:/group: consume 2 segments).
#
# RustPolicyPort below is a line-for-line port of from_toml + extract_string_value/array, so the
# goldens are checked by the parser's rules, not by eye. (No CLI exposes the parser; the Slice 12
# smoke run is the end-to-end check.)
require "test_helper"

class PolicyRendererTest < ActiveSupport::TestCase
  module RustPolicyPort
    def self.extract_string_value(line)
      eq = line.index("=") or return nil
      val = line[(eq + 1)..].strip
      val.start_with?('"') && val.end_with?('"') && val.length >= 2 ? val[1...-1] : nil
    end

    def self.extract_string_array(line)
      eq = line.index("=") or return nil
      val = line[(eq + 1)..].strip
      return nil unless val.start_with?("[") && val.end_with?("]")

      val[1...-1].split(",").map { |s| s.strip.delete_prefix('"').delete_suffix('"') }.reject(&:empty?)
    end

    # => [default_allow, { service => [patterns] }]
    def self.parse(content)
      rules = {}
      default_allow = false
      current = nil
      allow = []
      content.each_line do |raw|
        line = raw.strip
        next if line.empty? || line.start_with?("#")

        if line.start_with?("default")
          v = extract_string_value(line)
          default_allow = (v == "allow") if v
        elsif line == "[[services]]"
          rules[current] = allow if current
          current = nil
          allow = []
        elsif line.start_with?("name")
          v = extract_string_value(line)
          current = v if v
        elsif line.start_with?("allow")
          a = extract_string_array(line)
          allow = a if a
        end
      end
      rules[current] = allow if current
      [ default_allow, rules ]
    end
  end

  # Port of config.ex parse_policy_entry + group_by service.
  def elixir_parse(env_line)
    value = env_line.delete_prefix("ZTLP_GATEWAY_POLICIES=")
    value.split(",").reject(&:empty?).filter_map do |e|
      parts = e.start_with?("role:", "group:") ? e.split(":", 3) : e.split(":", 2)
      if e.start_with?("role:", "group:")
        parts.size == 3 ? [ parts[2], "#{parts[0]}:#{parts[1]}" ] : nil
      else
        parts.size == 2 ? [ parts[1], parts[0] ] : nil
      end
    end.group_by(&:first).transform_values { |v| v.map(&:last) }
  end

  setup do
    @zone = Zone.primary
    @gw = @zone.gateways.create!(name: "web", kind: "rust_listen")
    @app1 = @gw.applications.create!(name: "comms", enabled: true, min_assurance: 3,
                                     backend: "10.0.0.5:8080", protocol: "http")
    @app2 = @gw.applications.create!(name: "vault", enabled: false)
    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson", role: "tech", status: "active")
    @eng = @zone.groups.create!(name: "eng")
    @dev = @zone.devices.create!(name: "alice-mac")
  end

  test "a gateway with no applications still renders an explicit default deny (missing policy = allow-all)" do
    empty = @zone.gateways.create!(name: "quiet", kind: "rust_listen")
    default_allow, rules = RustPolicyPort.parse(Ztlp::PolicyRenderer.render(empty))
    refute default_allow
    assert_equal({}, rules)
  end

  test "rust_listen: the Rust line parser sees one service per ENABLED app, keyed by the app (forward) name" do
    @app1.policy_rules.create!(subject_type: "group", subject_id: @eng.id, position: 0)
    @app1.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 1)
    @app1.policy_rules.create!(subject_type: "user", subject_id: @alice.id, position: 2)
    @app1.policy_rules.create!(subject_type: "device", subject_id: @dev.id, position: 3)
    out = Ztlp::PolicyRenderer.render(@gw)
    default_allow, rules = RustPolicyPort.parse(out)
    refute default_allow
    assert_equal({ "comms" => [ "group:eng.groups.test.ztlp", "role:tech", "alice.users.test.ztlp",
                                "alice-mac.test.ztlp" ] }, rules)
    assert_includes out, "# --forward comms:10.0.0.5:8080", "backend shown as the matching --forward flag"
  end

  test "rust_listen: an enabled app with no rules is present with an empty allow (deny), not absent" do
    _d, rules = RustPolicyPort.parse(Ztlp::PolicyRenderer.render(@gw))
    assert_equal({ "comms" => [] }, rules)
  end

  test "rust_listen: 'any' renders the universal pattern" do
    @app1.policy_rules.create!(subject_type: "any")
    _d, rules = RustPolicyPort.parse(Ztlp::PolicyRenderer.render(@gw))
    assert_equal [ "*" ], rules["comms"]
  end

  test "a literal that would corrupt the line parsers is omitted (fail-closed) and reported" do
    @app1.policy_rules.create!(subject_type: "role", subject_value: "tech\", \"*", position: 0)
    @app1.policy_rules.create!(subject_type: "role", subject_value: "ops", position: 1)
    out = Ztlp::PolicyRenderer.render(@gw)
    _d, rules = RustPolicyPort.parse(out)
    assert_equal [ "role:ops" ], rules["comms"], "the injected '*' must never reach the allow list"
    assert_includes out, "# OMITTED unsafe rule literal"
  end

  test "a rule whose group was deleted still renders its pinned subject_value (stale but honest)" do
    ghost = @zone.groups.create!(name: "ghost")
    @app1.policy_rules.create!(subject_type: "group", subject_id: ghost.id)
    ghost.destroy!
    _d, rules = RustPolicyPort.parse(Ztlp::PolicyRenderer.render(@gw))
    assert_equal [ "group:ghost.groups.test.ztlp" ], rules["comms"]
  end

  test "elixir: renders one ZTLP_GATEWAY_POLICIES line the gateway's parser reads back exactly" do
    @gw.update!(kind: "elixir")
    @app1.policy_rules.create!(subject_type: "user", subject_id: @alice.id, position: 0)
    @app1.policy_rules.create!(subject_type: "group", subject_id: @eng.id, position: 1)
    @app1.policy_rules.create!(subject_type: "role", subject_value: "admin", position: 2)
    out = Ztlp::PolicyRenderer.render(@gw)
    line = out.lines.map(&:strip).find { |l| l.start_with?("ZTLP_GATEWAY_POLICIES=") }
    assert line, "no ZTLP_GATEWAY_POLICIES line in:\n#{out}"
    assert_equal({ "comms" => [ "alice.users.test.ztlp", "group:eng.groups.test.ztlp", "role:admin" ] },
                 elixir_parse(line))
    refute_includes out, "vault"
  end

  # A newline in a free-text field interpolated into a comment would start a REAL line the
  # line-based Rust parser reads (here: allow everyone). Anything unsafe must never be emitted.
  test "a backend with a newline cannot inject an allow line" do
    @app1.update_column(:backend, "10.0.0.5:80\nallow = [\"*\"]")
    @app1.policy_rules.create!(subject_type: "role", subject_value: "ops")
    out = Ztlp::PolicyRenderer.render(@gw)
    _d, rules = RustPolicyPort.parse(out)
    assert_equal [ "role:ops" ], rules["comms"]
    refute_match(/^allow = \["\*"\]/, out)
  end
end
