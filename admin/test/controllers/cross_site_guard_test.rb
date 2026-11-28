# frozen_string_literal: true

require "test_helper"

# Requests that a browser marks as coming from another website must not reach the panel, except a
# plain link click (top-level GET navigation). The panel signs people in from the ZTLP tunnel, so a
# page on any other site could otherwise make the browser act as the signed-in administrator.
class CrossSiteGuardTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
  end

  def fetch_headers(site:, mode: "cors", dest: "empty")
    { "Sec-Fetch-Site" => site, "Sec-Fetch-Mode" => mode, "Sec-Fetch-Dest" => dest }
  end

  test "a request with no fetch metadata is served (command-line clients, old browsers)" do
    get admins_path
    assert_response :success
  end

  test "same-origin and user-typed requests are served" do
    get admins_path, headers: fetch_headers(site: "same-origin")
    assert_response :success
    get admins_path, headers: fetch_headers(site: "none", mode: "navigate", dest: "document")
    assert_response :success
  end

  test "a cross-site POST is refused and nothing changes" do
    other, = make_admin(role: "admin", username: "pat")
    assert_no_changes -> { other.reload.disabled? } do
      post toggle_admin_path(other), params: { disabled: "1" }, headers: fetch_headers(site: "cross-site", mode: "navigate", dest: "document")
    end
    assert_response :forbidden
    assert_equal "auth.cross_site_blocked", AuditLog.order(:id).last.action
  end

  test "a POST from another site in the same zone is refused too" do
    other, = make_admin(role: "admin", username: "pat")
    assert_no_changes -> { other.reload.disabled? } do
      post toggle_admin_path(other), params: { disabled: "1" }, headers: fetch_headers(site: "same-site")
    end
    assert_response :forbidden
  end

  test "a cross-site script, image or frame GET is refused" do
    get search_path(q: "a"), headers: fetch_headers(site: "cross-site")
    assert_response :forbidden
    get admins_path, headers: fetch_headers(site: "cross-site", mode: "no-cors", dest: "image")
    assert_response :forbidden
    get admins_path, headers: fetch_headers(site: "cross-site", mode: "navigate", dest: "iframe")
    assert_response :forbidden
  end

  test "following a link from another site still opens the page" do
    get admins_path, headers: fetch_headers(site: "cross-site", mode: "navigate", dest: "document")
    assert_response :success
  end

  test "the same POST from the panel itself still works" do
    other, = make_admin(role: "admin", username: "pat")
    assert_changes -> { other.reload.disabled? } do
      post toggle_admin_path(other), params: { disabled: "1" }, headers: fetch_headers(site: "same-origin", mode: "navigate", dest: "document")
    end
  end

  test "over plain http a POST whose Origin is another host is refused" do
    other, = make_admin(role: "admin", username: "pat")
    assert_no_changes -> { other.reload.disabled? } do
      post toggle_admin_path(other), params: { disabled: "1" }, headers: { "Origin" => "http://evil.example" }
    end
    assert_response :forbidden
    assert_no_changes -> { other.reload.disabled? } do
      post toggle_admin_path(other), params: { disabled: "1" }, headers: { "Origin" => "null" }
    end
    assert_response :forbidden
  end

  test "over plain http a POST whose Origin is the panel itself works" do
    other, = make_admin(role: "admin", username: "pat")
    assert_changes -> { other.reload.disabled? } do
      post toggle_admin_path(other), params: { disabled: "1" }, headers: { "Origin" => "http://#{host}" }
    end
  end
end
