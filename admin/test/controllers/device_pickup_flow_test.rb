# frozen_string_literal: true

require "test_helper"

# The panel buttons for device pickup: "Check now" on a pending token, and "Add an existing device"
# on a user's page (adopts a device that is already enrolled, by name, without re-keying it).
class DevicePickupFlowTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary
    @heidy = @zone.users.create!(username: "heidy", display_name: "Heidy", role: "user", status: "invited")
    @enr = @zone.enrollments.create!(kind: "user_device", user: @heidy, device_name: "heidy-mba",
                                     embed_relay_secret: true, max_uses: 1, uses: 0, status: "pending",
                                     expires_at: 1.hour.from_now, created_by_admin: @admin, token_id: "cc" * 16)
  end

  # minitest 6 has no minitest/mock: swap a module method for the block, then restore it.
  def with_stub(mod, name, impl)
    original = mod.method(name)
    mod.define_singleton_method(name, &impl)
    yield
  ensure
    mod.define_singleton_method(name, original)
  end

  def stub_check(result, &)
    calls = []
    with_stub(Ztlp::DevicePickup, :check, ->(enr, **) { calls << enr.id; result }, &)
    calls
  end

  test "a pending token's page has Check now, and it reports what the name server said" do
    get "/enrollments/#{@enr.id}"
    assert_select "form[action=?]", "/enrollments/#{@enr.id}/check"
    stub_check(:pending) { post "/enrollments/#{@enr.id}/check" }
    assert_redirected_to "/enrollments/#{@enr.id}"
    follow_redirect!
    assert_match(/not enrolled yet/i, response.body)
  end

  test "Check now on a redeemed pickup says so" do
    stub_check(:redeemed) { post "/enrollments/#{@enr.id}/check" }
    follow_redirect!
    assert_match(/enrolled/i, response.body)
  end

  test "the user page offers Add an existing device to a write-capable admin" do
    get "/users/#{@heidy.id}"
    assert_select "form[action=?]", "/users/#{@heidy.id}/adopt_device"
  end

  test "adopting a device by name lists it under the user" do
    adopted = nil
    fake = lambda do |zone, user, name, **|
      adopted = zone.devices.create!(name: name, user: user, status: "enrolled", node_id_hex: "3f" * 16,
                                     noise_pubkey_hex: "0e" * 32, enrolled_at: Time.current)
    end
    with_stub(Ztlp::DevicePickup, :adopt!, fake) do
      post "/users/#{@heidy.id}/adopt_device", params: { device_name: "heidys-macbook-air-2" }
    end
    assert_redirected_to "/users/#{@heidy.id}"
    follow_redirect!
    assert_includes response.body, "heidys-macbook-air-2"
    assert adopted
  end

  test "adopting a name with no KEY record says so" do
    with_stub(Ztlp::DevicePickup, :adopt!, ->(*, **) { raise Ztlp::DevicePickup::NotFound, "no KEY record for ghost.x" }) do
      post "/users/#{@heidy.id}/adopt_device", params: { device_name: "ghost" }
    end
    follow_redirect!
    assert_match(/no KEY record/i, response.body)
  end

  test "a read-only admin cannot adopt or check" do
    ro, seed = make_admin(role: "read_only", username: "ro")
    sign_in_as(ro, seed)
    post "/users/#{@heidy.id}/adopt_device", params: { device_name: "x" }
    assert_includes [ 302, 403 ], response.status
    post "/enrollments/#{@enr.id}/check"
    assert_includes [ 302, 403 ], response.status
    assert_equal 0, @zone.devices.count
  end

  test "the pickup job is scheduled every 5 minutes" do
    sched = YAML.safe_load(File.read(Rails.root.join("config/recurring.yml")), aliases: true)
    jobs = sched.values.flat_map { |env| env.is_a?(Hash) ? env.values : [] }
    pick = jobs.find { |j| j["class"] == "EnrollmentPickupJob" }
    assert pick, "EnrollmentPickupJob is in recurring.yml"
    assert_match(/every 5 minutes/, pick["schedule"])
  end
end
