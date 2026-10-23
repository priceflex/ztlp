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
  # over the tunnel. There is no /enrollments page yet (Slice 10) — the route is
  # not in this list.
  PAGE_ROUTES = [
    "/", "/users", "/devices", "/groups", "/applications", "/policies",
    "/zone", "/admins", "/audit_logs", "/login", "/claim"
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
end
