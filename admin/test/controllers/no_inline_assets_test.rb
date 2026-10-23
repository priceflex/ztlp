# frozen_string_literal: true

# Review follow-up (9b-4, 2026-10-23): the CSP is script-src 'self' / style-src 'self'
# with NO nonce, so in a real browser every inline <script> and style="" attribute is
# silently dropped (inline styles die; inline scripts never run). Rails integration tests
# render the raw ERB and never enforce the CSP, so they cannot see this — these tests pin
# the absence of both, on EVERY route an administrator can reach (plus the no-auth pages).
#
# Every route below is either public (the gateway gate is off in the test env by default)
# or reached signed in, so the assertions see the real rendered HTML.
require "test_helper"

class NoInlineAssetsTest < ActionDispatch::IntegrationTest
  # /login is the no-auth sign-in page; /claim 302s a signed-in admin (an admin
  # already exists in the test DB). Test both unauthenticated, like a first visitor
  # over the tunnel. /enrollments landed in Slice 10b (the mint result page
  # /enrollments/:id lands in sub-slice 2 and is added to the device/show
  # list below when it exists).
  PAGE_ROUTES = [
    "/", "/users", "/devices", "/groups", "/applications", "/policies",
    "/zone", "/admins", "/audit_logs", "/login", "/claim", "/enrollments",
    "/enrollments/new"
  ].freeze

  PAGE_ROUTES.each do |route|
    test "page #{route} has no inline script or style attributes (blocked by the CSP)" do
      @admin, @seed = make_admin
      # /claim 302s a signed-in admin (an admin already exists in the test DB) and
      # /session/new 404s (the route is /sign_in). Test both unauthenticated, like
      # a first visitor over the tunnel.
      public_page = route.start_with?("/claim") || route == "/login"
      get route
      if public_page
        # /claim redirects a signed-in admin to /; /session/new is the
        # no-auth sign-in page. Either is a valid landing for a fresh visitor.
        assert [ 200, 302 ].include?(response.status)
      else
        sign_in_as(@admin, @seed)
        get route
        assert_response :success
      end
      # assert_select does not print the offending nodes on failure; the scan
      # below does, so a RED run says exactly which attribute on which tag.
      offenders = response.body.scan(/<([a-z][a-z0-9-]*)((?:\s[^>]*)?)>/).select do |_tag, attrs|
        attrs.match?(/\sstyle=/) || attrs.match?(/\son[a-z]+=/)
      end
      assert offenders.empty?, "inline attributes (CSP-blocked) on #{route}:\n#{offenders.map { |t, a| "  <#{t}> #{a[0, 90]}" }.join("\n")}"
      assert_select "script:not([src])", false
      assert_select "[style]", false
    end
  end

  # A real <select>/<input> must not use on*= either (same CSP block class); grep the two
  # most JS-heavy pages.
  test "directory pages have no inline event handlers" do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    %w[/applications /policies].each do |route|
      get route
      %w[onclick onchange onsubmit oninput].each do |attr|
        assert_select "[#{attr}]", false
      end
    end
  end

  # Most of the inline styles lived on show/new/edit pages, not the indexes: cover every one.
  test "show, new and edit pages have no inline script, style or on* attributes" do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    zone = Zone.primary
    user = zone.users.create!(username: "jane", display_name: "Jane", role: "user", status: "active")
    device = zone.devices.create!(name: "jane-mbp", user: user, status: "enrolled",
                                  node_id_hex: "ab" * 16, noise_pubkey_hex: "cd" * 32)
    pending_dev = zone.devices.create!(name: "fresh-box", status: "pending")
    group = zone.groups.create!(name: "techs")
    gw = zone.gateways.create!(name: "gw1", kind: "rust_listen")
    app = gw.applications.create!(name: "wiki", backend: "10.0.0.5:80")
    app.policy_rules.create!(subject_type: "group", subject_id: group.id, position: 1)
    routes = [ "/users/#{user.id}", "/users/new", "/users/#{user.id}/edit",
               "/devices/#{device.id}", "/devices/#{pending_dev.id}", "/groups/#{group.id}", "/groups/new", "/groups/#{group.id}/edit",
               "/applications/#{app.id}", "/applications/new", "/applications/#{app.id}/edit",
               "/apps/new_gateway", "/admins/new" ]
    routes.each do |route|
      get route
      assert_response :success, route
      offenders = response.body.scan(/<([a-z][a-z0-9-]*)((?:\s[^>]*)?)>/).select do |_t, attrs|
        attrs.match?(/\sstyle=/) || attrs.match?(/\son[a-z]+=/)
      end
      assert offenders.empty?, "inline attributes on #{route}: #{offenders.map { |t, a| "<#{t}>#{a[0, 80]}" }}"
      assert_select "script:not([src])", false, "inline <script> on #{route}"
    end
  end
end
