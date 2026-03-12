# frozen_string_literal: true

# ActionCable channel for live deploy log streaming.
# Clients subscribe with a network_id to receive Turbo Stream broadcasts
# as each component deploys across machines.
class DeployChannel < ApplicationCable::Channel
  def subscribed
    stream_from "deploy_network_#{params[:network_id]}"
  end

  def unsubscribed
    # Cleanup if needed
  end
end
