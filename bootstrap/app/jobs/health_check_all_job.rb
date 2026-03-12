# frozen_string_literal: true

# Checks health of all machines across all networks.
# Enqueues a HealthCheckJob for each network.
class HealthCheckAllJob < ApplicationJob
  queue_as :default

  def perform
    Network.find_each do |network|
      next unless network.machines.any?

      HealthCheckJob.perform_later(network.id)
    end
  end
end
