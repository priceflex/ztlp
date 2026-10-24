# frozen_string_literal: true

require "test_helper"

# Adding a user can mint their first enrollment token in the same step, landing on the show-once
# result page (string + QR + command) so a phone can scan it. The user page offers "Enroll a device"
# (enrollments/new pre-selected for that user) for later devices.
class EnrollOnAddUserTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary
    @zone.update!(enrollment_secret_ct: "cd" * 32)
    @zone.relay_addrs = %w[10.0.0.9:23095]
    @zone.save!
  end

  def user_params(username = "dana", **extra)
    { user: { username: username, display_name: "Dana Diaz", role: "user", kind: "person" } }.merge(extra)
  end

  test "the new-user form offers 'Enroll a device now', ticked by default, with device name and expiry" do
    get "/users/new"
    assert_response :success
    assert_select "input[type=checkbox][name=?][checked]", "enroll[now]"
    assert_select "input[name=?]", "enroll[device_name]"
    assert_select "input[name=?][max='24']", "enroll[expiry_hours]"
  end

  test "creating a user with enroll now mints a token for that user and lands on the show-once result page" do
    post "/users", params: user_params(enroll: { now: "1", device_name: "dana-iphone", expiry_hours: "24" })
    user = @zone.users.find_by!(username: "dana")
    tok = @zone.enrollments.order(:id).last
    assert_equal user, tok.user
    assert_equal "user_device", tok.kind
    assert_equal "dana-iphone", tok.device_name
    assert_in_delta 24.hours.from_now.to_i, tok.expires_at.to_i, 60
    assert_redirected_to "/enrollments/#{tok.id}/result"
    follow_redirect!
    assert_response :success
    assert_includes response.body, tok.token_uri_ct
    assert_select "#token-qr svg", 1
    assert_match(/Dana Diaz/, response.body, "the page names the user it was minted for")
    assert AuditLog.exists?(action: "user.create", target_id: user.id)
    assert AuditLog.exists?(action: "enrollment.mint", status: "ok")
  end

  test "unticked: the user is created and no token is minted" do
    assert_no_difference -> { @zone.enrollments.count } do
      post "/users", params: user_params(enroll: { now: "0" })
    end
    assert_redirected_to "/users/#{@zone.users.find_by!(username: 'dana').id}"
  end

  test "no enrollment secret: the user is still created, with an honest alert and no token" do
    @zone.update!(enrollment_secret_ct: nil)
    assert_no_difference -> { @zone.enrollments.count } do
      post "/users", params: user_params(enroll: { now: "1" })
    end
    user = @zone.users.find_by!(username: "dana")
    assert_redirected_to "/users/#{user.id}"
    assert_match(/enrollment secret/i, flash[:alert].to_s)
  end

  test "an invalid user mints nothing" do
    assert_no_difference -> { @zone.enrollments.count } do
      post "/users", params: user_params("Bad Name!", enroll: { now: "1" })
    end
    assert_response :unprocessable_content
  end

  test "the user page links 'Enroll a device' to the mint form pre-selected for that user" do
    user = @zone.users.create!(username: "erin", display_name: "Erin Eads", role: "user", status: "active")
    get "/users/#{user.id}"
    assert_select "a.btn[href=?]", "/enrollments/new?user_id=#{user.id}", text: /Enroll a device/
  end

  test "read_only admins do not get the 'Enroll a device' button" do
    user = @zone.users.create!(username: "erin", display_name: "Erin Eads", role: "user", status: "active")
    ro, ro_seed = make_admin(role: "read_only", username: "readonly-enr")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get "/users/#{user.id}"
    assert_select "a[href=?]", "/enrollments/new?user_id=#{user.id}", count: 0
  end

  test "enrollments/new?user_id= pre-selects that user" do
    user = @zone.users.create!(username: "erin", display_name: "Erin Eads", role: "user", status: "active")
    get "/enrollments/new", params: { user_id: user.id }
    assert_select "select[name=?] option[value=?][selected]", "enrollment[user_id]", user.id.to_s
  end

  test "the result page tells a phone user to scan with the ZTLP app" do
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    follow_redirect!
    assert_match(/ZTLP app/, response.body)
  end
end
