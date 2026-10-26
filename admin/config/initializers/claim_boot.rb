# frozen_string_literal: true

# Print a claim code on boot when no administrator exists (spec §4.1 step 2).
Rails.application.config.after_initialize do
  next if defined?(Rails::Console) || Rails.env.test? || ENV["SKIP_CLAIM_BOOT"] == "1"

  begin
    Claim.ensure_code! if ActiveRecord::Base.connection.table_exists?("admins")
  rescue StandardError => e
    Rails.logger.warn("claim boot check skipped: #{e.class}: #{e.message}")
  end
end
