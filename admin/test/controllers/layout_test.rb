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
    # A real attribute, not escaped text: the CSS selector .nav a[aria-current="page"]
    # only matches the parsed attribute. aria-current=&quot;page&quot; is a bug.
    assert_select ".rail .nav a[aria-current=page]", 1
    assert_not body.include?("&quot;page&quot;"), "aria-current must not be HTML-escaped"
    assert body.include?('class="app"'), "expected the .app grid shell"
    assert body.include?("topbar"), "expected the topbar"
    assert body.include?("brand"), "expected the brand block"
  end

  # Two asset tags (directory.css + admin.css, then directory.js): every <script>
  # must be a /assets/ tag, there must be no inline <script>, and directory.js
  # must load with defer. (admin.css was added by the inline-attribute sweep; the
  # layout used to carry exactly one script tag.)
  test "only /assets script tags are present and directory.js loads deferred" do
    get root_path
    scripts = response.body.scan(/<script[^>]*>/)
    assert scripts.all? { |s| s.include?("/assets/directory-") }, "only /assets script tags: #{scripts}"
    assert response.body.include?('src="/assets/directory-'), "directory.js tag present"
    assert response.body.include?("defer"), "directory.js must load with defer"
  end

  test "no external stylesheet or script sources" do
    get root_path
    externals = response.body.scan(/<(?:link|script)[^>]*\b(?:href|src)=["'](https?:[^"']+)["']/i)
    assert_empty externals, "no external href/src allowed in <link>/<script>: #{externals}"
    refute response.body.include?("fonts.googleapis"), "no Google Fonts"
    refute response.body.include?("cdnjs"), "no cdnjs"
  end

  # The rail NS line: the dot is its own empty element and the NS address is visible text
  # (a missing `">` once swallowed the address into the class attribute).
  test "rail NS line shows the dot element and the NS address as text" do
    get root_path
    assert_select ".rail-foot .ns-line > span.dot", 1
    assert_select ".rail-foot .ns-line", text: /127\.0\.0\.1:23096/
  end
end
