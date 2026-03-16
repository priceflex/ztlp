# frozen_string_literal: true

# Auto-register Bootstrap with the ZTLP Namespace Server on boot.
# Runs in a background thread to avoid blocking startup.
# Re-registers every 4 minutes (TTL is 5 minutes) to keep the record fresh.
if defined?(Rails::Server) && ENV["BOOTSTRAP_URL"].present?
  Rails.application.config.after_initialize do
    Thread.new do
      loop do
        begin
          Network.find_each do |network|
            next unless network.ns_machines.any?

            registrar = NsRegistrar.new(network)
            result = registrar.register!
            Rails.logger.info("[NsRegistrar] Registered #{result[:name]} → #{result[:addr]} at #{result[:ns]}")
          rescue NsRegistrar::RegistrationError => e
            Rails.logger.warn("[NsRegistrar] Failed to register for #{network.name}: #{e.message}")
          end
        rescue => e
          Rails.logger.error("[NsRegistrar] Registration loop error: #{e.message}")
        end

        sleep 240 # Re-register every 4 minutes
      end
    end
  end
end
