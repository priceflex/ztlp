# frozen_string_literal: true

require "test_helper"

class UserValidationTest < ActiveSupport::TestCase
  def setup
    @zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
  end

  def build(over = {})
    @zone.users.build(username: "jane", **over)
  end

  test "valid person user" do
    u = build(kind: "person", role: "user", status: "active", email: "jane@example.com", phone: "555-1212")
    assert u.valid?
    assert_equal "jane.users.trs.ztlp", u.ns_name
  end

  test "username must match the DNS label regex (after normalisation)" do
    # "JANE" is downcased before the format check, so it is accepted
    assert build(username: "JANE").valid?
    refute build(username: "-jane").valid?
    refute build(username: "").valid?
    assert build(username: "jane").valid?
    assert build(username: "j2-1").valid?
  end

  test "username is unique within a zone only" do
    build(username: "jane").save!
    zone2 = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:9104")
    refute @zone.users.build(username: "jane").valid?
    assert zone2.users.build(username: "jane").valid?
  end

  test "kind, role, status inclusions" do
    refute build(kind: "robot").valid?
    refute build(role: "superhero").valid?
    refute build(status: "banned").valid?
    assert build(kind: "service", role: "tech", status: "invited").valid?
  end

  test "ns_name is computed before validation and length-checked" do
    u = build(username: "jane")
    assert u.valid?
    assert_equal "jane.users.trs.ztlp", u.ns_name
    # username fits the column (63) but the computed ns_name exceeds its 255 limit
    long = build(username: ("a" * 63))
    long.zone.name = ("z" * 200)
    refute long.valid?
    assert long.errors[:ns_name].any?
  end

  test "email is encrypted and deterministic on save" do
    u = build(email: "jane@example.com")
    assert u.save
    assert_equal "jane@example.com", u.reload.email
    c1 = ActiveRecord::Base.connection.select_value("SELECT email FROM users WHERE id=#{u.id}")
    refute_equal "jane@example.com", c1 # ciphertext, not plaintext
    u2 = build(username: "jane2", email: "jane@example.com")
    assert u2.save
    c2 = ActiveRecord::Base.connection.select_value("SELECT email FROM users WHERE id=#{u2.id}")
    # deterministic: same plaintext yields the same ciphertext (email lookup works)
    assert_equal c1, c2
  end
end

class GroupValidationTest < ActiveSupport::TestCase
  def setup
    @zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
  end

  test "valid group with computed ns_name" do
    g = @zone.groups.build(name: "Staff")
    assert g.valid?
    assert_equal "staff", g.name
    assert_equal "staff.groups.trs.ztlp", g.ns_name
  end

  test "name is label-checked and unique per zone" do
    @zone.groups.create!(name: "staff")
    refute @zone.groups.build(name: "staff").valid?
    refute @zone.groups.build(name: "bad name").valid?
    zone2 = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:9104")
    assert zone2.groups.build(name: "staff").valid?
  end

  test "members go through group_memberships with unique pair" do
    g = @zone.groups.create!(name: "staff")
    u = @zone.users.create!(username: "jane")
    g.group_memberships.create!(user: u)
    assert g.member?(u)
    assert_raises(ActiveRecord::RecordInvalid) { g.group_memberships.create!(user: u) }
  end
end

class DeviceValidationTest < ActiveSupport::TestCase
  def setup
    @zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
  end

  def build(over = {})
    @zone.devices.build(name: "laptop1", **over)
  end

  test "valid device with ns_name and defaults" do
    d = build
    assert d.valid?
    assert_equal "laptop1.trs.ztlp", d.ns_name
    assert_equal "unknown", d.key_source
    assert_equal 1, d.assurance
    assert_equal "pending", d.status
  end

  test "key_source inclusion" do
    Device::KEY_SOURCES.each do |ks|
      assert build(key_source: ks).valid?, "#{ks} should be allowed"
    end
    refute build(key_source: "magical").valid?
  end

  test "assurance must be 1..4" do
    [ 1, 2, 3, 4 ].each do |n|
      assert build(assurance: n).valid?
    end
    refute build(assurance: 0).valid?
    refute build(assurance: 5).valid?
    refute build(assurance: nil).valid?
  end

  test "status inclusion and revoked?/enrolled? helpers" do
    d = build(status: "revoked")
    assert d.valid?
    assert d.revoked?
    assert build(status: "enrolled").enrolled?
    refute build(status: "pending").revoked?
  end

  test "name is unique within a zone" do
    build.save!
    refute @zone.devices.build(name: "laptop1").valid?
    zone2 = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:9104")
    assert zone2.devices.build(name: "laptop1").valid?
  end
end

class EnrollmentValidationTest < ActiveSupport::TestCase
  def setup
    @zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
  end

  def build(over = {})
    @zone.enrollments.build(**over)
  end

  test "token_id must be 16 bytes of hex" do
    assert build(token_id: SecureRandom.hex(16)).valid?
    refute build(token_id: "ab").valid?
    refute build(token_id: "zz" * 16).valid?
    # blank token_id is rejected, not auto-filled
    refute build.valid?
  end

  test "code is auto-generated: 8 chars from the unambiguous alphabet, unique" do
    e = build(token_id: SecureRandom.hex(16))
    assert e.valid?
    assert_match(/\A[A-Z2-9]{8}\z/, e.code)
    refute_match(/[IO01]/, e.code) # alphabet excludes I, O, 0, 1 (L is not in [A-Z2-9])
  end

  test "kind and status inclusions" do
    assert build(kind: "user_device", token_id: SecureRandom.hex(16)).valid?
    refute build(kind: "both", token_id: SecureRandom.hex(16)).valid?
    assert build(status: "redeemed", token_id: SecureRandom.hex(16)).valid?
    refute build(status: "lost", token_id: SecureRandom.hex(16)).valid?
  end

  test "generators never collide with existing rows" do
    e1 = @zone.enrollments.create!(token_id: SecureRandom.hex(16), code: "ABCDEFGH")
    tid = Enrollment.generate_token_id
    code = Enrollment.generate_code
    e2 = build(token_id: tid, code: code)
    assert e2.valid?
    refute_equal e1.token_id, tid
    refute_equal "ABCDEFGH", code
  end
end

class GatewayServicePolicyRuleTest < ActiveSupport::TestCase
  def setup
    @zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
    @gw = @zone.gateways.create!(name: "edge", kind: "rust_listen")
  end

  test "gateway kind and status inclusions, computed ns_name" do
    assert_equal "edge.trs.ztlp", @gw.ns_name
    assert @zone.gateways.build(name: "edge2", kind: "elixir").valid?
    refute @zone.gateways.build(name: "edge2", kind: "caddy").valid?
    assert @zone.gateways.build(name: "edge2", status: "online").valid?
    refute @zone.gateways.build(name: "edge2", status: "offline").valid?
  end

  test "service min_assurance 1..4 and ztlp_name" do
    a = @gw.services.build(name: "web", min_assurance: 3)
    assert a.valid?
    assert_equal "web.trs.ztlp", a.ztlp_name
    refute @gw.services.build(name: "web2", min_assurance: 5).valid?
    refute @gw.services.build(name: "web2", min_assurance: 0).valid?
  end

  def make(subject_type, subject: nil, subject_value: nil, app: "app1")
    rule = @gw.services.create!(name: app).policy_rules.build(subject_type:, subject_value:)
    rule.subject_id = subject.id if subject
    rule
  end

  test "policy rule subject_type inclusion" do
    group = @zone.groups.create!(name: "staff")
    user = @zone.users.create!(username: "jane2")
    device = @zone.devices.create!(name: "laptop2")
    entity = { "group" => group, "user" => user, "device" => device }
    PolicyRule::SUBJECT_TYPES.each_with_index do |st, i|
      value = st == "role" ? "tech" : "x" # role rules must name a User::ROLES role
      assert make(st, subject: entity[st], subject_value: value, app: "a#{i}").valid?, st
    end
    refute make("tenant", app: "b1").valid?
  end

  test "render maps to the gateway allow-list literals" do
    group = @zone.groups.create!(name: "staff")
    user = @zone.users.create!(username: "jane")
    device = @zone.devices.create!(name: "laptop1")
    assert_equal "group:staff.groups.trs.ztlp", make("group", subject: group, app: "r1").render
    assert_equal "role:tech", make("role", subject_value: "tech", app: "r2").render
    assert_equal "jane.users.trs.ztlp", make("user", subject: user, app: "r3").render
    assert_equal "laptop1.trs.ztlp", make("device", subject: device, app: "r4").render
    assert_equal "*", make("any", app: "r5").render
  end

  test "typed rule without a subject is invalid" do
    refute make("group", app: "s1").valid?
    assert make("role", subject_value: "tech", app: "s2").valid?
    assert make("any", app: "s3").valid?
  end
end

class ZoneHasManyTest < ActiveSupport::TestCase
  test "zone associations enumerate directory rows" do
    zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
    user = zone.users.create!(username: "jane")
    group = zone.groups.create!(name: "staff")
    device = zone.devices.create!(name: "laptop1")
    enrollment = zone.enrollments.create!(token_id: SecureRandom.hex(16))
    gw = zone.gateways.create!(name: "edge")
    assert zone.users.include?(user)
    assert zone.groups.include?(group)
    assert zone.devices.include?(device)
    assert zone.enrollments.include?(enrollment)
    assert zone.gateways.include?(gw)
    group.group_memberships.create!(user: user)
    assert user.groups.include?(group)
  end
end
