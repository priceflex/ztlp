# frozen_string_literal: true

require "test_helper"
require "json"

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
    AuditLog.where(action: %w[zone.authority_imported zone.enrollment_secret_set zone.relay_secret_set zone.ns_admin_api_secret_set]).delete_all
  end

  def run_rake(verb, *args, stdin: nil)
    # Run the task against the TEST database so the test can assert on the
    # same rows it creates. RAILS_ENV=test is inherited from the test process.
    cmd = "RAILS_ENV=test bin/rake zone:#{verb}"
    cmd += "[#{args.join(",")}]" unless args.empty?
    return system(cmd, out: File::NULL, err: File::NULL) if stdin.nil?

    # Ruby 3.2 `system(StringIO, cmd)` raises TypeError; feed stdin from a temp file.
    f = File.join(Dir.tmpdir, "stdin_#{rand(1 << 32)}.txt")
    File.write(f, stdin)
    system("cat #{Shellwords.shellescape(f)} | #{cmd}", out: File::NULL, err: File::NULL)
  ensure
    File.delete(f) if f
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

  def secret_task(verb, zone_name: "test.ztlp")
    with_zone(name: zone_name)
    run_rake("set_secret", verb, stdin: "#{"a" * 64}\n")
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
      refute_includes raw.to_s, "a" * 64, "#{col} must not be stored in plaintext"
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

  test "set_secret with a non-64-hex value fails and stores nothing" do
    zone = with_zone(name: "short.ztlp")
    ok = run_rake("set_secret", "relay", stdin: "tooshort\n")
    refute ok, "a non-64-hex secret must exit nonzero"
    zone.reload
    assert_nil zone.relay_secret_ct
    refute AuditLog.where(action: "zone.relay_secret_set", target_id: zone.id).any?
  end
end
