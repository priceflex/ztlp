# frozen_string_literal: true

require "test_helper"

class DeployChannelTest < ActionCable::Channel::TestCase
  setup do
    @network = networks(:office)
  end

  test "subscribes to deploy stream for network" do
    subscribe network_id: @network.id
    assert subscription.confirmed?
    assert_has_stream "deploy_network_#{@network.id}"
  end

  test "rejects without network_id" do
    subscribe
    refute subscription.confirmed?, "subscription should be rejected without network_id"
  end

  test "rejects with nil network_id" do
    subscribe network_id: nil
    refute subscription.confirmed?, "subscription should be rejected with nil network_id"
  end

  test "rejects with blank network_id" do
    subscribe network_id: ""
    refute subscription.confirmed?, "subscription should be rejected with blank network_id"
  end

  test "rejects with non-numeric network_id" do
    subscribe network_id: "not-a-number"
    refute subscription.confirmed?, "subscription should be rejected with non-numeric network_id"
  end

  test "rejects with negative network_id" do
    subscribe network_id: -1
    refute subscription.confirmed?, "subscription should be rejected with negative network_id"
  end

  test "rejects with zero network_id" do
    subscribe network_id: 0
    refute subscription.confirmed?, "subscription should be rejected with zero network_id"
  end

  test "rejects with non-existent network_id" do
    subscribe network_id: 999999
    refute subscription.confirmed?, "subscription should be rejected for non-existent network"
  end

  test "stream name uses validated network id" do
    subscribe network_id: @network.id
    assert subscription.confirmed?
    assert_has_stream "deploy_network_#{@network.id}"
  end
end
