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

  setup do
    # NotificationService.validate_webhook_url! (SSRF guard, finding
    # cpt-ochr) does a real DNS lookup before delivering any webhook.
    # Test fixtures use non-resolving example domains
    # (hooks.example.com, etc.) — stub DNS globally so any test that
    # exercises the notification path doesn't depend on live network
    # access or a specific domain actually existing. Tests that need to
    # exercise a REJECTED case (private/loopback) should override this
    # stub locally with a more specific expectation.
    Resolv.stubs(:getaddresses).returns(["93.184.216.34"])
  end
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
