# frozen_string_literal: true

# Periodic background health checks for all machines.
# Runs every 5 minutes in production to keep the dashboard current.
# This ensures the dashboard shows accurate status without manual clicks.

if defined?(Rails::Server) && (Rails.env.production? || ENV["ENABLE_PERIODIC_HEALTH_CHECK"] == "true")
  Rails.application.config.after_initialize do
    Thread.new do
      # Wait for app to fully boot before starting checks
      sleep 30

      loop do
        begin
          Machine.all.find_each do |machine|
            next unless machine.role_list.any?

            begin
              checker = HealthChecker.new(machine)
              results = checker.check_all
              healthy = results.count { |r| r.status == "healthy" }
              Rails.logger.info("[PeriodicHealth] #{machine.hostname}: #{healthy}/#{results.count} healthy")
            rescue StandardError => e
              Rails.logger.warn("[PeriodicHealth] #{machine.hostname} failed: #{e.message}")
            end
          end
        rescue StandardError => e
          Rails.logger.error("[PeriodicHealth] Loop error: #{e.message}")
        end

        sleep 300 # 5 minutes
      end
    end
  end
end
