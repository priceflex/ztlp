# frozen_string_literal: true

# ActionCable channel for live deploy log streaming.
# Clients subscribe with a network_id to receive Turbo Stream broadcasts
# as each component deploys across machines.
class DeployChannel < ApplicationCable::Channel
  def subscribed
    network_id = params[:network_id]

    # [zig-wyxu fix] Reject subscriptions that lack a valid network_id
    return reject unless network_id.present? && network_id.to_i > 0

    # [zig-wyxu fix] Ensure the network actually exists
    network = Network.find_by(id: network_id.to_i)
    return reject unless network.present?

    stream_from "deploy_network_#{network.id}"
  end

  def unsubscribed
    # Cleanup if needed
  end
end
