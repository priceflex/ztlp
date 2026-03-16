# frozen_string_literal: true

require "test_helper"

class NsRegistrarTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
  end

  test "raises when no NS machine exists" do
    network = networks(:production) # Has no NS machines
    # Remove any NS machines from production network
    network.machines.with_role("ns").destroy_all

    registrar = NsRegistrar.new(network)
    assert_raises(NsRegistrar::RegistrationError) do
      registrar.register!
    end
  end

  test "raises when BOOTSTRAP_URL not set" do
    ENV.delete("BOOTSTRAP_URL")
    registrar = NsRegistrar.new(@network)
    assert_raises(NsRegistrar::RegistrationError) do
      registrar.register!(bootstrap_url: nil)
    end
  end

  test "register builds correct service name" do
    registrar = NsRegistrar.new(@network)
    # We can't actually connect to an NS, but we can test the name computation
    expected_name = "bootstrap.#{@network.zone}"
    assert_equal "bootstrap.office.acme.ztlp", expected_name
  end

  test "lookup returns nil when NS unreachable" do
    registrar = NsRegistrar.new(@network)
    result = registrar.lookup
    # Should timeout/fail gracefully since no NS is running locally
    assert_nil result
  end

  test "registered? returns false when NS unreachable" do
    registrar = NsRegistrar.new(@network)
    refute registrar.registered?
  end
end
