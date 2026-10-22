# frozen_string_literal: true

# Slice 1: strict content security policy, no nonces (no inline scripts).
require "test_helper"

class CspTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
  end

  test "responses carry a strict CSP with script-src 'self' and no nonce" do
    get root_path
    assert_response :success
    csp = response.headers["Content-Security-Policy"]
    assert csp, "expected a Content-Security-Policy header"
    assert_match(/script-src 'self'(;|$)/, csp)
    assert_match(/default-src 'self'(;|$)/, csp)
    assert_match(/style-src 'self'(;|$)/, csp)
    assert_match(/frame-ancestors 'none'/, csp)
    refute_match(/'nonce-/, csp, "no nonces (no inline scripts)")
    refute csp.include?("'unsafe-inline'")
  end
end
