# frozen_string_literal: true

require "test_helper"

# Slice 5b-ii: Ztlp::Republisher — the 6-hourly re-publish (spec Slice 5).
# Publishes the zone's NS records in a fixed order — authority KEY first,
# then active users, groups, enrolled devices — spaced ~1.1 s between writes
# (NS rate-limit headroom). Every write flows through Ztlp::Publisher (the
# injectable `publisher:` seam; the real one writes `ns.publish` audit rows,
# never the record data). The `sleep:` seam keeps the suite from really
# sleeping 1.1 s per write.
#
# NOTE: mocha BLOCK stubs do not run in this harness (mocha 3.1.0 block form
# returns nil / block body not invoked — probed 2026-10-22); expectations
# (.times/.ordered) and .returns chains DO work, so this test drives the
# service through a hand-written FakePublisher (plain objects, no mocha) and
# a recorder lambda for sleep.
class RepublisherTest < ActiveSupport::TestCase
  class FakePublisher
    attr_reader :calls

    def initialize
      @calls = []
      @fails = {}
    end

    def fail_with!(key, err)
      @fails[key] = err
    end

    def publish_user!(user, ns_client: nil, admin: nil, **kw)
      maybe_raise(:user, user.ns_name)
      @calls << [ user.ns_name, "user" ]
      :ok
    end

    def publish_group!(group, ns_client: nil, admin: nil, **kw)
      maybe_raise(:group, group.ns_name)
      @calls << [ group.ns_name, "group" ]
      :ok
    end

    def publish_device!(device, ns_client: nil, admin: nil, **kw)
      maybe_raise(:device, device.ns_name)
      @calls << [ device.ns_name, "device" ]
      :ok
    end

    def authority!(zone, ns_client: nil, admin: nil, **kw)
      maybe_raise(:key, zone.name)
      @calls << [ zone.name, "key" ]
      :ok
    end

    def maybe_raise(key, name)
      raise @fails[key] if @fails[key]
    end
  end

  def setup
    seed, pub = Ztlp::Ed25519.generate
    @zone = Zone.create!(name: "test.ztlp", ns_addr: "127.0.0.1:23096", authority_seed_ct: seed)
    @active = @zone.users.create!(username: "alice", ns_name: "alice.users.test.ztlp",
                                  role: "user", status: "active", signing_pubkey_hex: "00" * 32)
    @invited = @zone.users.create!(username: "bob", ns_name: "bob.users.test.ztlp",
                                   role: "user", status: "invited", signing_pubkey_hex: "11" * 32)
    @group = @zone.groups.create!(name: "staff", ns_name: "staff.groups.test.ztlp")
    @device = @zone.devices.create!(name: "alice-mbp", ns_name: "alice-mbp.test.ztlp",
                                    node_id_hex: "ab" * 16, noise_pubkey_hex: "cd" * 32,
                                    assurance: 2, key_source: "file", status: "enrolled",
                                    user: @active)
    @pending = @zone.devices.create!(name: "bob-laptop", ns_name: "bob-laptop.test.ztlp",
                                     node_id_hex: "bb" * 16, noise_pubkey_hex: "cc" * 32,
                                     assurance: 1, key_source: "file", status: "pending")
    @admin = Admin.create!(username: "steve", display_name: "Steve", pubkey_hex: pub,
                           role: "super_admin")
  end

  def test_publishes_key_then_active_users_then_groups_then_enrolled_devices_in_order
    publisher = FakePublisher.new
    Ztlp::Republisher.run(@zone, admin: @admin, publisher: publisher,
                          sleep: ->(_s) { nil })

    assert_equal [
      [ "test.ztlp", "key" ],
      [ "alice.users.test.ztlp", "user" ],
      [ "staff.groups.test.ztlp", "group" ],
      [ "alice-mbp.test.ztlp", "device" ]
    ], publisher.calls
  end

  def test_excludes_invited_users_and_pending_devices
    publisher = FakePublisher.new
    Ztlp::Republisher.run(@zone, admin: @admin, publisher: publisher,
                          sleep: ->(_s) { nil })

    refute_includes publisher.calls.map(&:first), "bob.users.test.ztlp"
    refute_includes publisher.calls.map(&:first), "bob-laptop.test.ztlp"
  end

  def test_spaces_writes_1_1_seconds_apart
    publisher = FakePublisher.new
    sleeps = []
    Ztlp::Republisher.run(@zone, admin: @admin, publisher: publisher,
                          sleep: ->(s) { sleeps << s })

    # 4 writes → 3 sleeps of exactly 1.1 s, no more, no less.
    assert_equal [ 1.1, 1.1, 1.1 ], sleeps
  end

  def test_no_sleeps_when_fewer_than_two_writes
    @group.destroy
    @device.destroy
    @active.update!(status: "invited") # only the KEY write remains
    publisher = FakePublisher.new
    sleeps = []
    Ztlp::Republisher.run(@zone, admin: @admin, publisher: publisher,
                          sleep: ->(s) { sleeps << s })

    assert_equal [ [ "test.ztlp", "key" ] ], publisher.calls
    assert_equal [], sleeps
  end

  def test_real_publisher_proxy_routes_through_ztlp_publisher
    # The default publisher (NsClientPublisherProxy) must delegate to
    # Ztlp::Publisher's class methods so the real `ns.publish` audit rows
    # are written. We prove the routing by stubbing Ztlp::Publisher's four
    # class methods (mocha EXPECTATIONS — block stubs don't work here) and
    # asserting the proxy calls each one with the right args.
    # The proxy passes its own `ns_client:` default (Ztlp::NsClient) through
    # to the real publisher — the expectation must match that kwarg.
    Ztlp::Publisher.expects(:publish_user!).with(@active, ns_client: Ztlp::NsClient, admin: @admin).returns(:ok)
    Ztlp::Publisher.expects(:publish_group!).with(@group, ns_client: Ztlp::NsClient, admin: @admin).returns(:ok)
    Ztlp::Publisher.expects(:publish_device!).with(@device, ns_client: Ztlp::NsClient, admin: @admin).returns(:ok)
    Ztlp::Publisher.expects(:publish_authority!).with(@zone, ns_client: Ztlp::NsClient, admin: @admin).returns(:ok)

    Ztlp::Republisher.run(@zone, admin: @admin)
  end

  def test_raises_ns_error_on_write_failure
    publisher = FakePublisher.new
    err = Ztlp::NsClient::NsError.new(0x0C, "timeout")
    publisher.fail_with!(:user, err)

    assert_raises(Ztlp::NsClient::NsError) do
      Ztlp::Republisher.run(@zone, admin: @admin, publisher: publisher, sleep: ->(_s) { nil })
    end
  end
end
