# frozen_string_literal: true

# Slice 9b sub-slice 3: Application mutations — new/create + edit/update.
#
# GET  /apps/new         new     form with gateway pick (every gateway in the
#                               zone), name, backend, protocol, min assurance,
#                               description.
# POST /apps             create  gateway comes from the form; the application
#                               lands on that gateway. Invalid params re-render
#                               with errors, nothing persisted.
# GET  /apps/:id/edit    edit    same form pre-filled.
# PATCH /apps/:id        update  name is IMMUTABLE after create (it drives the
#                               gateway's service name and the ztlp name
#                               <name>.<zone> — a rename would leave the old
#                               service live on the gateway with no panel row
#                               to fix it); the rest of the fields update.
#
# Scoping: every action is scoped to the zone's gateways. An application id
# that does not belong to this zone's gateways 404s on edit/update (no
# cross-zone mutation).
#
# Access: read_only admin gets 403 on new/create/edit/update.
#
# Publishing: creating or editing an application does NOT publish anything to
# the NS — the rendered policy is a gateway-side artifact the operator deploys
# at gateway deploy/restart time (the page says so). No Publisher calls here.
require "test_helper"

class ApplicationsMutationsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @gw_elixir = @zone.gateways.create!(name: "gw-e", kind: "elixir", status: "planned")
    @app = @gw.applications.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2,
                                    description: "Blitz terminal")
  end

  # -------------------------------------------------------------- new / create

  test "new renders the form with the zone's gateways" do
    get new_application_path
    assert_response :success
    body = response.body
    assert_includes body, "New application"
    # every zone gateway is a pickable option
    assert_includes body, "gw1"
    assert_includes body, "gw-e"
  end

  test "create makes an application on the picked gateway and redirects to it" do
    post applications_path, params: {
      application: {
        gateway_id: @gw_elixir.id.to_s,
        name: "portal",
        backend: "10.0.0.5:3000",
        protocol: "https",
        min_assurance: "3",
        description: "Web portal"
      }
    }
    app = Application.find_by(name: "portal")
    assert_not_nil app
    assert_equal @gw_elixir.id, app.gateway_id
    assert_equal "10.0.0.5:3000", app.backend
    assert_equal "https", app.protocol
    assert_equal 3, app.min_assurance
    assert_equal "Web portal", app.description
    assert_equal true, app.enabled
    assert_redirected_to application_path(app)
    follow_redirect!
    assert_includes response.body, "portal"
    assert_includes response.body, "portal.test.ztlp"
  end

  test "create with an invalid name re-renders the form with errors and persists nothing" do
    post applications_path, params: {
      application: { gateway_id: @gw.id.to_s, name: "Bad Name", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_equal 1, @gw.applications.count
    assert_includes response.body, "errors"
  end

  test "create rejects a name that is not a lowercase DNS label" do
    post applications_path, params: {
      application: { gateway_id: @gw.id.to_s, name: "Bad Name", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_nil Application.find_by(name: "Bad Name")
  end

  test "create rejects a backend that is not host:port" do
    post applications_path, params: {
      application: { gateway_id: @gw.id.to_s, name: "okname",
                     backend: "1.2.3.4:80\nallow = [\"*\"]" }
    }
    assert_response :unprocessable_content
    assert_nil Application.find_by(name: "okname")
  end

  test "create with an unknown gateway id re-renders with an error" do
    post applications_path, params: {
      application: { gateway_id: "999999", name: "orphan", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_nil Application.find_by(name: "orphan")
  end

  test "create with a gateway from another zone re-renders with an error" do
    other = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:24000")
    foreign = other.gateways.create!(name: "gw-x", kind: "rust_listen", status: "planned")
    post applications_path, params: {
      application: { gateway_id: foreign.id.to_s, name: "cross", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_nil Application.find_by(name: "cross")
    assert_equal 0, foreign.applications.count
  end

  # -------------------------------------------------------------- edit / update

  test "edit renders the form pre-filled with the current values" do
    get edit_application_path(@app)
    assert_response :success
    doc = Nokogiri::HTML(response.body)
    name_input = doc.at_css("input[name='application[name]']")
    assert_equal "comms-blitz", name_input["value"]
    assert_includes name_input["readonly"].to_s, "readonly"
    # the gateway select is disabled (immutable after create)
    gw_select = doc.at_css("select[name='application[gateway_id]']")
    assert_includes gw_select["disabled"].to_s, "disabled"
    backend_input = doc.at_css("input[name='application[backend]']")
    assert_equal "10.42.42.112:5200", backend_input["value"]
  end

  test "edit 404s for an application that is not on the zone's gateways" do
    other = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:24000")
    foreign_gw = other.gateways.create!(name: "gw-x", kind: "rust_listen", status: "planned")
    foreign_app = foreign_gw.applications.create!(name: "cross")
    get edit_application_path(foreign_app)
    assert_response :not_found
  end

  test "update changes the mutable fields and redirects to the show page" do
    patch application_path(@app), params: {
      application: {
        name: "comms-blitz", # immutable: must be ignored
        backend: "10.9.9.9:9999",
        protocol: "http2",
        min_assurance: "4",
        description: "Blitz terminal (renamed)"
      }
    }
    @app.reload
    assert_equal "comms-blitz", @app.name
    assert_equal "10.9.9.9:9999", @app.backend
    assert_equal "http2", @app.protocol
    assert_equal 4, @app.min_assurance
    assert_equal "Blitz terminal (renamed)", @app.description
    assert_redirected_to application_path(@app)
  end

  test "update silently ignores a renamed name (no cross-gateway move, no rename)" do
    other_gw = @zone.gateways.create!(name: "gw2", kind: "rust_listen", status: "planned")
    patch application_path(@app), params: { application: { name: "renamed", gateway_id: other_gw.id.to_s } }
    @app.reload
    assert_equal "comms-blitz", @app.name
    assert_equal @gw.id, @app.gateway_id
  end

  test "update with invalid params re-renders edit and changes nothing" do
    patch application_path(@app), params: { application: { backend: "not a host:port" } }
    assert_response :unprocessable_content
    @app.reload
    assert_equal "10.42.42.112:5200", @app.backend
  end

  # -------------------------------------------------------------- access control

  test "read_only admin gets 403 on new, create, edit and update" do
    ro_admin, ro_seed = make_admin(role: "read_only", username: "ro-user")
    delete logout_path
    sign_in_as(ro_admin, ro_seed)

    get new_application_path
    assert_response :forbidden

    post applications_path, params: { application: { gateway_id: @gw.id.to_s, name: "nope", backend: "1.2.3.4:80" } }
    assert_response :forbidden
    assert_nil Application.find_by(name: "nope")

    get edit_application_path(@app)
    assert_response :forbidden

    patch application_path(@app), params: { application: { backend: "9.9.9.9:9" } }
    assert_response :forbidden
    @app.reload
    assert_equal "10.42.42.112:5200", @app.backend
  end

  test "unauthenticated request is redirected to sign in" do
    delete logout_path
    get new_application_path
    assert_redirected_to login_path
  end

  test "create with no application params is a 400, never a 500" do
    assert_no_difference -> { Application.count } do
      post applications_path, params: {}
    end
    assert_response :bad_request
  end
end
