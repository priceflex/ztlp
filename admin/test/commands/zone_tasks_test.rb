# frozen_string_literal: true

require "test_helper"
require "json"
require "open3"

# Slice 5a: zone rake tasks — authority import (identity.json) and
# secret setters (value from stdin, never argv).
class ZoneTasksTest < ActiveSupport::TestCase
  # The rake subprocess runs in a separate process and cannot see uncommitted
  # rows from the test's transactional fixtures. Disable transactions so the
  # zones created here are visible to the rake subprocess.
  self.use_transactional_tests = false

  def with_zone(name: "test.ztlp", ns_addr: "127.0.0.1:23096")
    Zone.where(name: name).first_or_create!(ns_addr: ns_addr)
  end

  # The non-transactional zones persist across the full suite; clean them up
  # so other tests (which use transactional fixtures) don't hit unique-name
  # collisions.
  teardown do
    Zone.where(name: %w[test.ztlp bad.ztlp empty.ztlp short.ztlp]).delete_all
    AuditLog.where(action: %w[zone.authority_imported zone.authority_exported zone.enrollment_secret_set
                              zone.relay_secret_set zone.ns_admin_api_secret_set]).delete_all
  end

  # Returns [ok, stdout]. Runs against the TEST database (RAILS_ENV=test).
  def run_rake_out(verb, *args, stdin: nil, env: {})
    cmd = "bin/rake zone:#{verb}"
    cmd += "[#{args.join(",")}]" unless args.empty?
    out, _err, st = Open3.capture3({ "RAILS_ENV" => "test" }.merge(env), cmd, stdin_data: stdin.to_s)
    [ st.success?, out ]
  end

  def run_rake(verb, *args, stdin: nil, env: {})
    run_rake_out(verb, *args, stdin: stdin, env: env).first
  end

  def identity_file(seed)
    path = File.join(Dir.tmpdir, "identity_#{rand(1 << 32)}.json")
    File.write(path, { "node_id" => "n", "signing_key_seed" => seed }.to_json)
    path
  end

  def import_authority_task
    @zone = with_zone
    seed, pub = Ztlp::Ed25519.generate
    identity_path = File.join(Dir.tmpdir, "identity_#{rand(1 << 32)}.json")
    File.write(identity_path, {
                "node_id" => "node-1234",
                "static_private_key" => "unrelated-static-key",
                "static_public_key" => "unrelated-static-pub",
                "signing_key_seed" => seed
              }.to_json)
    ok = run_rake("import_authority", identity_path)
    [ @zone, seed, pub, identity_path, ok ]
  end

  test "import_authority stores the 64-hex seed and derived pubkey, audits pubkey only" do
    zone, seed, pub, path, ok = import_authority_task
    assert ok, "the rake task must exit 0 (output suppressed)"
    zone.reload
    assert_equal seed, zone.authority_seed_ct, "seed stored exactly as identity.json signing_key_seed"
    assert_equal pub, zone.authority_pubkey_hex
    # encrypted at rest: the raw column must not contain the plaintext seed
    raw = ActiveRecord::Base.connection.select_value(
      "SELECT authority_seed_ct FROM zones WHERE name = #{ActiveRecord::Base.connection.quote(zone.name)}"
    )
    refute_includes raw.to_s, seed, "seed must be encrypted at rest, not stored raw"
    audit = AuditLog.where(action: "zone.authority_imported", target_id: zone.id).order(:id).last
    assert audit, "audit row zone.authority_imported expected"
    details = audit.details.to_s
    assert_includes details, pub, "audit details carry the pubkey"
    refute_includes details, seed, "audit details must never carry the seed"
    File.delete(path)
  end

  test "import_authority without a signing_key_seed fails loudly" do
    zone = with_zone(name: "bad.ztlp")
    path = File.join(Dir.tmpdir, "identity_bad_#{rand(1 << 32)}.json")
    File.write(path, { "node_id" => "x", "static_private_key" => "a", "static_public_key" => "b" }.to_json)
    ok = run_rake("import_authority", path)
    refute ok, "a malformed identity.json must exit nonzero"
    zone.reload
    assert_nil zone.authority_seed_ct
    refute AuditLog.where(action: "zone.authority_imported", target_id: zone.id).any?
    File.delete(path)
  end

  VALID_SECRET = {
    "enrollment" => "a" * 64,
    "ns_admin_api" => "b" * 64,
    "relay" => "Zq7" * 16 # 48 alphanumerics, NOT hex (spec F20)
  }.freeze

  def secret_task(verb, zone_name: "test.ztlp")
    with_zone(name: zone_name)
    assert run_rake("set_secret", verb, stdin: "#{VALID_SECRET.fetch(verb)}\n"), "set_secret[#{verb}] must exit 0"
    with_zone(name: zone_name).reload
  end

  test "set_secret reads the value from stdin and stores it encrypted" do
    %w[enrollment relay ns_admin_api].each do |verb|
      zone = secret_task(verb)
      col = "#{verb}_secret_ct"
      assert zone.public_send(col).present?, "#{verb}_secret_ct should be set"
      # encrypted at rest: the raw column must not contain the plaintext
      raw = ActiveRecord::Base.connection.select_value(
        "SELECT #{col} FROM zones WHERE name = #{ActiveRecord::Base.connection.quote(zone.name)}"
      )
      assert_equal VALID_SECRET[verb], zone.public_send(col)
      refute_includes raw.to_s, VALID_SECRET[verb], "#{col} must not be stored in plaintext"
      assert AuditLog.where(action: "zone.#{verb}_secret_set", target_id: zone.id).any?
    end
  end

  test "set_secret is a no-op on empty stdin and does not audit" do
    zone = with_zone(name: "empty.ztlp")
    AuditLog.delete_all
    run_rake("set_secret", "enrollment", stdin: "\n")
    zone.reload
    assert_nil zone.enrollment_secret_ct
    refute AuditLog.where(action: "zone.enrollment_secret_set").any?
  end

  test "set_secret[enrollment] with a non-64-hex value fails and stores nothing" do
    zone = with_zone(name: "short.ztlp")
    refute run_rake("set_secret", "enrollment", stdin: "tooshort\n")
    assert_nil zone.reload.enrollment_secret_ct
    refute AuditLog.where(action: "zone.enrollment_secret_set", target_id: zone.id).any?
  end

  test "set_secret[relay] rejects a hex secret (spec F20: relay hex-decodes, Rust gateway does not)" do
    zone = with_zone(name: "short.ztlp")
    refute run_rake("set_secret", "relay", stdin: "#{"c" * 64}\n"), "a 64-hex relay secret must be refused"
    refute run_rake("set_secret", "relay", stdin: "#{"c" * 48}\n"), "48 hex chars is still hex"
    refute run_rake("set_secret", "relay", stdin: "short1\n")
    assert_nil zone.reload.relay_secret_ct
  end

  test "import_authority refuses to replace a different seed unless FORCE=1; same seed is a no-op" do
    zone = with_zone
    seed1, = Ztlp::Ed25519.generate
    seed2, pub2 = Ztlp::Ed25519.generate
    p1 = identity_file(seed1)
    p2 = identity_file(seed2)
    assert run_rake("import_authority", p1)
    assert run_rake("import_authority", p1), "re-importing the same seed is fine"
    refute run_rake("import_authority", p2), "a different seed must be refused without FORCE=1"
    assert_equal seed1, zone.reload.authority_seed_ct
    assert run_rake("import_authority", p2, env: { "FORCE" => "1" })
    assert_equal seed2, zone.reload.authority_seed_ct
    assert_equal pub2, zone.authority_pubkey_hex
  ensure
    [ p1, p2 ].compact.each { |f| File.delete(f) if File.exist?(f) }
  end

  test "export_authority prints the seed only with CONFIRM=1, and audits the pubkey not the seed" do
    zone = with_zone
    seed, pub = Ztlp::Ed25519.generate
    path = identity_file(seed)
    assert run_rake("import_authority", path)
    ok, out = run_rake_out("export_authority")
    refute ok
    refute_includes out, seed
    ok, out = run_rake_out("export_authority", env: { "CONFIRM" => "1" })
    assert ok
    assert_includes out, seed
    row = AuditLog.where(action: "zone.authority_exported", target_id: zone.id).last
    assert row
    assert_includes row.details.to_s, pub
    refute_includes row.details.to_s, seed
  ensure
    File.delete(path) if path && File.exist?(path)
  end
end
