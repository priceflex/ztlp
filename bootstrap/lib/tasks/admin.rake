# frozen_string_literal: true

namespace :admin do
  desc "Create an admin user: bin/rails admin:create[email,name,password]"
  task :create, [:email, :name, :password] => :environment do |_t, args|
    email = args[:email]
    name = args[:name]
    password = args[:password]

    unless email.present? && name.present? && password.present?
      puts "Usage: bin/rails admin:create[email,name,password]"
      puts "Example: bin/rails admin:create[admin@example.com,Admin,secretpass123]"
      exit 1
    end

    admin = AdminUser.new(
      email: email,
      name: name,
      password: password,
      password_confirmation: password,
      role: "super_admin"
    )

    if admin.save
      puts "Admin user created successfully!"
      puts "  Email: #{admin.email}"
      puts "  Name:  #{admin.name}"
      puts "  Role:  #{admin.role}"
    else
      puts "Failed to create admin user:"
      admin.errors.full_messages.each { |msg| puts "  - #{msg}" }
      exit 1
    end
  end
end
