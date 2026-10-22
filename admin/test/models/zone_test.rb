# frozen_string_literal: true

require "test_helper"

# Zone.primary creates the zone on first use. It must come from the deployment's
# ZTLP_ZONE / ZTLP_NS_ADDR (docker-compose.yml sets both), never a hard-coded name
# or a 0.0.0.0 placeholder address.
class ZonePrimaryTest < ActiveSupport::TestCase
  setup do
    @saved = ENV.to_h.slice("ZTLP_ZONE", "ZTLP_NS_ADDR")
    Zone.delete_all
  end

  teardown do
    %w[ZTLP_ZONE ZTLP_NS_ADDR].each { |k| @saved.key?(k) ? ENV[k] = @saved[k] : ENV.delete(k) }
  end

  test "created from ZTLP_ZONE and ZTLP_NS_ADDR" do
    ENV["ZTLP_ZONE"] = "acme.ztlp"
    ENV["ZTLP_NS_ADDR"] = "10.0.0.5:23096"
    z = Zone.primary
    assert_equal "acme.ztlp", z.name
    assert_equal "10.0.0.5:23096", z.ns_addr
  end

  test "an existing zone is returned unchanged" do
    Zone.create!(name: "first.ztlp", ns_addr: "1.2.3.4:23096")
    ENV["ZTLP_ZONE"] = "other.ztlp"
    assert_equal "first.ztlp", Zone.primary.name
    assert_equal 1, Zone.count
  end

  test "without ZTLP_ZONE it refuses to invent a zone" do
    ENV.delete("ZTLP_ZONE")
    assert_raises(KeyError) { Zone.primary }
    assert_equal 0, Zone.count
  end

  test "authority_seed_ct must be the 64-hex seed" do
    ENV["ZTLP_ZONE"] = "acme.ztlp"
    z = Zone.primary
    z.authority_seed_ct = [ "x" * 32 ].pack("m")
    assert_not z.valid?
    z.authority_seed_ct = "ab" * 32
    assert z.valid?
  end
end
