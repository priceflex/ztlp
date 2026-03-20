# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).

# Default admin user
AdminUser.find_or_create_by!(email: "admin@techrockstars.com") do |u|
  u.name = "Steve"
  u.password = "changeme123!"
  u.password_confirmation = "changeme123!"
  u.role = "super_admin"
end

puts "Default admin user created: admin@techrockstars.com / changeme123!"

# Seed built-in policy templates
PolicyTemplate.seed_built_in!
puts "Built-in policy templates seeded (#{PolicyTemplate.built_in.count} templates)."
