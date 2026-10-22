# frozen_string_literal: true

# Slice 1: the directory shell. Signed-in GET / must render the mock shell
# (.rail nav with aria-current), exactly one script tag (Propshaft
# directory.js, deferred), and no external <link>/<script> sources.
require "test_helper"

class LayoutTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
  end

  test "root renders the directory shell with current nav" do
    get root_path
    assert_response :success
    body = response.body
    assert body.include?('class="rail"'), "expected the rail shell"
    assert body.include?("nav-sec"), "expected nav sections"
    # Note: Rails 7 ERB html_escape escapes attribute quotes as &quot;
    has_current = body.include?('aria-current="page"') || body.include?("aria-current=&quot;page&quot;")
    assert has_current, "expected current nav marker"
    assert body.include?('class="app"'), "expected the .app grid shell"
    assert body.include?("topbar"), "expected the topbar"
    assert body.include?("brand"), "expected the brand block"
  end

  test "only the directory.js asset script tag is present" do
    get root_path
    scripts = response.body.scan(/<script[^>]*src=["'][^"']*["'][^>]*>/)
    assert_equal 1, scripts.size, "expected exactly one <script src> tag, got: #{scripts}"
    src = scripts.first[/src=["']([^"']+)["']/, 1]
    assert src.start_with?("/assets/directory"), "script must be the /assets/directory bundle, got #{src}"
    refute src.match?(/http/), "script src must be relative"
    assert response.body.include?("defer"), "directory.js must load with defer"
  end

  test "no external stylesheet or script sources" do
    get root_path
    externals = response.body.scan(/<(?:link|script)[^>]*\b(?:href|src)=["'](https?:[^"']+)["']/i)
    assert_empty externals, "no external href/src allowed in <link>/<script>: #{externals}"
    refute response.body.include?("fonts.googleapis"), "no Google Fonts"
    refute response.body.include?("cdnjs"), "no cdnjs"
  end
end
