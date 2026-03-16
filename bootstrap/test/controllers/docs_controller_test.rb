require "test_helper"

class DocsControllerTest < ActionDispatch::IntegrationTest
  test "GET docs index" do
    get docs_path
    assert_response :success
  end

  test "GET docs overview page" do
    get doc_page_path(page: "overview")
    assert_response :success
  end

  test "GET docs networks page" do
    get doc_page_path(page: "networks")
    assert_response :success
  end

  test "GET docs machines page" do
    get doc_page_path(page: "machines")
    assert_response :success
  end

  test "GET docs users page" do
    get doc_page_path(page: "users")
    assert_response :success
  end

  test "GET docs devices page" do
    get doc_page_path(page: "devices")
    assert_response :success
  end

  test "GET docs groups page" do
    get doc_page_path(page: "groups")
    assert_response :success
  end

  test "GET docs enrollment page" do
    get doc_page_path(page: "enrollment")
    assert_response :success
  end

  test "GET docs deployment page" do
    get doc_page_path(page: "deployment")
    assert_response :success
  end

  test "invalid docs page redirects to index" do
    get doc_page_path(page: "nonexistent")
    assert_redirected_to docs_path
  end

  test "docs index has links to all pages" do
    get docs_path
    assert_select "a[href=?]", doc_page_path(page: "overview")
    assert_select "a[href=?]", doc_page_path(page: "networks")
    assert_select "a[href=?]", doc_page_path(page: "machines")
    assert_select "a[href=?]", doc_page_path(page: "users")
    assert_select "a[href=?]", doc_page_path(page: "devices")
    assert_select "a[href=?]", doc_page_path(page: "groups")
    assert_select "a[href=?]", doc_page_path(page: "enrollment")
    assert_select "a[href=?]", doc_page_path(page: "deployment")
  end

  test "docs pages have sidebar navigation" do
    get doc_page_path(page: "overview")
    assert_select "nav"
  end

  test "docs pages have prev/next links" do
    get doc_page_path(page: "networks")
    assert_select "a", /Previous/
    assert_select "a", /Next/
  end
end
