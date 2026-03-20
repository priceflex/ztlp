ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "mocha/minitest"

class ActiveSupport::TestCase
  include ActiveJob::TestHelper

  # Run tests in parallel with specified workers
  parallelize(workers: :number_of_processors)

  # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
  fixtures :all
end

class ActionDispatch::IntegrationTest
  # Sign in as an admin user for controller tests that require authentication
  def sign_in_as_admin(admin = nil)
    admin ||= admin_users(:super_admin)
    post login_path, params: { email: admin.email, password: "password123" }
  end

  # Sign in as a specific admin fixture by name
  # Usage: sign_in(admin_users(:regular_admin))  or  sign_in_as(:regular_admin)
  def sign_in(admin_user)
    post login_path, params: { email: admin_user.email, password: "password123" }
  end

  def sign_in_as(fixture_name = :regular_admin)
    sign_in(admin_users(fixture_name))
  end
end
