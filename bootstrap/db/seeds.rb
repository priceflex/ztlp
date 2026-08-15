# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).

# Default admin user — credentials come from the environment, never
# hardcoded. In dev/test, falls back to a per-boot random password so
# nothing predictable ever ships, but that password is only usable for
# that single process's lifetime (it's never persisted anywhere you'd
# find it later).
admin_email = ENV.fetch("ZTLP_ADMIN_INITIAL_EMAIL", "admin@techrockstars.com")
admin_password = ENV["ZTLP_ADMIN_INITIAL_PASSWORD"]

if admin_password.blank?
  if Rails.env.production?
    raise "ZTLP_ADMIN_INITIAL_PASSWORD must be set in production — refusing to seed a default admin with a known password."
  end

  admin_password = SecureRandom.hex(16)
  Rails.logger.warn("[seeds] ZTLP_ADMIN_INITIAL_PASSWORD not set — generated a random one-time password for #{admin_email} (dev/test only, not persisted).")
end

AdminUser.find_or_create_by!(email: admin_email) do |u|
  u.name = ENV.fetch("ZTLP_ADMIN_INITIAL_NAME", "Steve")
  u.password = admin_password
  u.password_confirmation = admin_password
  u.role = "super_admin"
end

puts "Default admin user ensured: #{admin_email} (password from ZTLP_ADMIN_INITIAL_PASSWORD env var; not printed)"

# Seed built-in policy templates
PolicyTemplate.seed_built_in!
puts "Built-in policy templates seeded (#{PolicyTemplate.built_in.count} templates)."

