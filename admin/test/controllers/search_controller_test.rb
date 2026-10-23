# frozen_string_literal: true

# Slice 11b: global search (spec Slice 11, §2.1 routes).
#
# GET /search.json?q=  search#index  JSON [{type,id,name,sub,url}]
# ILIKE over users (username/display_name/email-deterministic exact), devices
# (name/node_id), groups, applications; max 20; JSON response (never HTML),
# so a `<script>` query returns escaped JSON and no HTML markup.
require "test_helper"

class SearchControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "user", status: "active", email: "alice@example.com")
    @bob = @zone.users.create!(username: "bob", display_name: "Bob Brown",
                               role: "tech", status: "invited")
    @eng = @zone.groups.create!(name: "eng", description: "Engineering")
    @eng.users << @alice
    @ops = @zone.groups.create!(name: "ops", description: "Operations")
    @device = @zone.devices.create!(name: "alice-mbp", user: @alice, node_id_hex: "ab" * 16,
                                    noise_pubkey_hex: "cd" * 32, key_source: "secure-enclave",
                                    assurance: 3, status: "enrolled")
    @gw = @zone.gateways.create!(name: "portal", kind: "rust_listen")
    @app = @gw.applications.create!(name: "crm", backend: "http://10.0.0.5:8080", protocol: "http",
                                    enabled: true)
  end

  test "returns json (not html) with type id name sub url rows" do
    get "/search.json?q=alice"
    assert_response :success
    assert_equal "application/json", response.media_type
    refute_match %r{<html|<div|<span}, response.body, "search is JSON only, never HTML"

    rows = JSON.parse(response.body)
    assert_kind_of Array, rows
    alice = rows.find { |r| r["type"] == "user" && r["name"] == "Alice Anderson" }
    assert alice, "the matching user must be present"
    assert_equal "alice.users.test.ztlp", alice["sub"]
    assert_equal("/users/#{@alice.id}", alice["url"])

    dev = rows.find { |r| r["type"] == "device" && r["name"] == "alice-mbp" }
    assert dev, "the matching device must be present"
    assert_equal("alice-mbp.#{Zone.primary.name}", dev["sub"])
    assert_equal("/devices/#{@device.id}", dev["url"])

    # only matching entities appear
    assert_empty rows.map { |r| r["name"] }.reject { |n| n =~ /alice/i },
                 "no non-matching rows: #{rows.inspect}"
  end

  test "matches users by username and display name" do
    get "/search.json?q=bob"
    rows = JSON.parse(response.body)
    assert rows.any? { |r| r["type"] == "user" && r["name"] == "Bob Brown" }

    get "/search.json?q=anderson"
    rows = JSON.parse(response.body)
    assert rows.any? { |r| r["type"] == "user" && r["name"] == "Alice Anderson" }
  end

  test "matches devices by name and node_id fragment" do
    get "/search.json?q=mbp"
    assert JSON.parse(response.body).any? { |r| r["type"] == "device" && r["name"] == "alice-mbp" }

    get "/search.json?q=#{"ab" * 4}"
    assert JSON.parse(response.body).any? { |r| r["type"] == "device" && r["name"] == "alice-mbp" }
  end

  test "matches groups by name and description" do
    get "/search.json?q=ops"
    rows = JSON.parse(response.body)
    g = rows.find { |r| r["type"] == "group" }
    assert g && g["name"] == "ops"
    assert_equal("Operations", g["sub"])
    assert_equal("/groups/#{@ops.id}", g["url"])

    get "/search.json?q=engineering"
    assert JSON.parse(response.body).any? { |r| r["type"] == "group" && r["name"] == "eng" }
  end

  test "matches applications by name" do
    get "/search.json?q=crm"
    rows = JSON.parse(response.body)
    a = rows.find { |r| r["type"] == "application" }
    assert a && a["name"] == "crm"
    assert_equal("/applications/#{@app.id}", a["url"])
  end

  test "a script-tag query returns escaped json and no html" do
    get "/search.json?q=%3Cscript%3E"
    assert_response :success
    refute_match %r{<script>}i, response.body
    rows = JSON.parse(response.body) # must be valid JSON even when q is markup
    assert_kind_of Array, rows
  end

  test "is capped at 20 rows and user rows come first" do
    30.times do |i|
      @zone.groups.create!(name: "g#{i.to_s.rjust(2, '0')}", description: "bulk group")
    end
    get "/search.json?q=g"
    rows = JSON.parse(response.body)
    assert_operator rows.length, :<=, 20, "the response is capped at 20"
    assert_equal "group", rows.first["type"] # type order: users, devices, groups, applications
  end

  test "blank or missing q returns an empty array" do
    get "/search.json"
    assert_response :success
    assert_equal [], JSON.parse(response.body)

    get "/search.json?q=%20%20"
    assert_response :success
    assert_equal [], JSON.parse(response.body)
  end

  test "read-only admins may search" do
    ro, seed2 = make_admin(username: "ro6", role: "read_only")
    sign_in_as(ro, seed2)
    get "/search.json?q=alice"
    assert_response :success
    assert JSON.parse(response.body).any? { |r| r["type"] == "user" }
  end
end
