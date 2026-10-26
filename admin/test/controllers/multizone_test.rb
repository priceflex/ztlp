# frozen_string_literal: true

require "test_helper"

# Phase A of docs/admin-panel/PLAN-multizone-and-app-registration.md: a zone switcher in the rail,
# a per-admin default zone, "Add zone", and every directory page scoped to the current zone.
class MultizoneTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @home = Zone.primary
    @cf = Zone.create!(name: "cf.test", ns_addr: "203.0.113.9:23096")
    @home.users.create!(username: "homer", display_name: "Homer Home", role: "user", status: "active")
    @cf.users.create!(username: "cora", display_name: "Cora Client", role: "user", status: "active")
  end

  test "the rail has a zone picker listing every zone with the current one selected" do
    get "/users"
    assert_select "form[action=?][method=post]", "/zone/switch" do
      assert_select "select[name=zone_id] option", Zone.count
      assert_select "select[name=zone_id] option[selected][value=?]", @home.id.to_s
    end
  end

  test "switching zones scopes the directory to that zone" do
    get "/users"
    assert_match "Homer Home", response.body
    assert_no_match(/Cora Client/, response.body)

    post "/zone/switch", params: { zone_id: @cf.id }
    assert_redirected_to "/"
    get "/users"
    assert_match "Cora Client", response.body
    assert_no_match(/Homer Home/, response.body)
    assert_select ".brand-zone", "cf.test"
    assert AuditLog.exists?(action: "zone.switch")
  end

  test "switching back to a page keeps the admin on that page when a same-site referer is given" do
    post "/zone/switch", params: { zone_id: @cf.id }, headers: { "Referer" => "http://www.example.com/devices" }
    assert_redirected_to "/devices"
    post "/zone/switch", params: { zone_id: @cf.id }, headers: { "Referer" => "http://evil.example/x" }
    assert_redirected_to "/"
  end

  test "an unknown zone id is refused and the current zone is unchanged" do
    post "/zone/switch", params: { zone_id: 0 }
    assert_redirected_to "/"
    get "/users"
    assert_match "Homer Home", response.body
  end

  test "a zone that disappears from the session falls back to the default zone" do
    gone = Zone.create!(name: "gone.test", ns_addr: "203.0.113.10:23096")
    post "/zone/switch", params: { zone_id: gone.id }
    gone.destroy!
    get "/users"
    assert_response :success
    assert_match "Homer Home", response.body
  end

  test "set my default zone: a fresh sign-in lands in it" do
    post "/zone/switch", params: { zone_id: @cf.id }
    post "/zone/default"
    assert_equal @cf, @admin.reload.default_zone
    delete logout_path
    sign_in_as(@admin, @seed)
    get "/users"
    assert_match "Cora Client", response.body
  end

  test "super admins can add a zone; the new zone is listed in the picker" do
    get "/zones/new"
    assert_response :success
    post "/zones", params: { zone: { name: "new.test", ns_addr: "203.0.113.11:23096",
                                     relay_addrs_text: "203.0.113.11:23095, 203.0.113.12:23095" } }
    z = Zone.find_by!(name: "new.test")
    assert_equal %w[203.0.113.11:23095 203.0.113.12:23095], z.relay_addrs
    assert_redirected_to "/zone"
    get "/users"
    assert_select "select[name=zone_id] option", text: "new.test"
    assert AuditLog.exists?(action: "zone.create", target_id: z.id)
  end

  test "an invalid zone name is refused" do
    post "/zones", params: { zone: { name: "Bad Zone!", ns_addr: "203.0.113.11:23096" } }
    assert_response :unprocessable_content
    assert_nil Zone.find_by(name: "Bad Zone!")
  end

  test "non-super admins cannot add zones (but can switch)" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly-mz")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get "/zones/new"
    assert_response :forbidden
    post "/zones", params: { zone: { name: "x.test", ns_addr: "203.0.113.11:23096" } }
    assert_response :forbidden
    post "/zone/switch", params: { zone_id: @cf.id }
    get "/users"
    assert_match "Cora Client", response.body
  end

  test "the recurring jobs run for every zone" do
    Ztlp::Reconciler.expects(:run).times(Zone.count)
    ReconcileNsJob.perform_now
    Ztlp::Republisher.expects(:run).times(Zone.count)
    RepublishNsJob.perform_now
  end

  test "the NS admin API secret is shared by every zone on the NS (falls back to the default zone's)" do
    @home.update!(ns_admin_api_secret_ct: "ab" * 32)
    assert_equal "ab" * 32, @cf.ns_admin_secret
    @cf.update!(ns_admin_api_secret_ct: "cd" * 32)
    assert_equal "cd" * 32, @cf.reload.ns_admin_secret
  end

  test "Zone.resolve! picks a zone by name for rake tasks, defaulting to the home zone" do
    assert_equal @cf, Zone.resolve!("cf.test")
    assert_equal Zone.default, Zone.resolve!(nil)
    assert_raises(ActiveRecord::RecordNotFound) { Zone.resolve!("nope.test") }
  end

  test "each zone keeps its own drift record (a second zone's reconcile never overwrites the home zone's)" do
    Ztlp::Reconciler.run(@home) # not configured -> records status for the home zone
    Ztlp::Reconciler.run(@cf)
    assert_equal @home.name, JSON.parse(SystemSetting["ns_drift_json"])["zone"]
    assert_equal "cf.test", JSON.parse(SystemSetting["ns_drift_json:cf.test"])["zone"]
  end
end
