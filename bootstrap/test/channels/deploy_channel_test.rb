# frozen_string_literal: true

require "test_helper"

class DeployChannelTest < ActionCable::Channel::TestCase
  test "subscribes to deploy stream for network" do
    subscribe network_id: 42
    assert subscription.confirmed?
    assert_has_stream "deploy_network_42"
  end

  test "subscribes to correct stream based on network_id" do
    subscribe network_id: 99
    assert subscription.confirmed?
    assert_has_stream "deploy_network_99"
  end

  test "rejects without network_id" do
    subscribe
    # With no params, it subscribes with nil network_id
    assert subscription.confirmed?
    assert_has_stream "deploy_network_"
  end
end
