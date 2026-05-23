# frozen_string_literal: true

require "test_helper"

# Unit tests for the ApiClient model — pure DB / validation behaviour.
# The HMAC-signature integration is covered in
# `test/services/ztlp/api_authenticator_test.rb`; this file just pins
# the allowlist semantics.
class ApiClientTest < ActiveSupport::TestCase
  test "the z2ls_acme fixture is valid" do
    assert api_clients(:z2ls_acme).valid?
  end

  test "name + zone are required" do
    refute ApiClient.new(name: nil, zone: "acme.ztlp").valid?
    refute ApiClient.new(name: "foo", zone: nil).valid?
  end

  test "the (zone, name) pair is unique" do
    ApiClient.create!(name: "duplicate", zone: "acme.ztlp")
    dup = ApiClient.new(name: "duplicate", zone: "acme.ztlp")
    refute dup.valid?
    assert_match(/unique per zone/, dup.errors.full_messages.join)
  end

  test "the same name in a different zone is allowed" do
    ApiClient.create!(name: "shared-name", zone: "acme.ztlp")
    other = ApiClient.create!(name: "shared-name", zone: "evil.ztlp")
    assert other.persisted?
  end

  test "find_active returns the row when active=true" do
    found = ApiClient.find_active(zone: "acme.ztlp", name: "z2ls.acme")
    assert_equal api_clients(:z2ls_acme), found
  end

  test "find_active returns nil for an inactive row" do
    api_clients(:z2ls_acme).update!(active: false)
    assert_nil ApiClient.find_active(zone: "acme.ztlp", name: "z2ls.acme")
  end

  test "find_active returns nil for a missing row" do
    assert_nil ApiClient.find_active(zone: "nonexistent.ztlp", name: "whatever")
  end

  test "find_active is nil-safe on blank inputs" do
    assert_nil ApiClient.find_active(zone: "", name: "x")
    assert_nil ApiClient.find_active(zone: "acme.ztlp", name: nil)
  end

  test "touch_last_used! bumps the timestamp without invoking validations" do
    client = api_clients(:z2ls_acme)
    client.update_column(:last_used_at, 1.hour.ago)

    pre = Time.current
    client.touch_last_used!
    post = Time.current

    client.reload
    assert client.last_used_at >= pre
    assert client.last_used_at <= post
  end
end
