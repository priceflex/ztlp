# frozen_string_literal: true

# Slice 9b sub-slice 3: Service mutations — new/create + edit/update.
#
# GET  /services/new         new     form with gateway pick (every gateway in the
#                               zone), name, backend, protocol, min assurance,
#                               description.
# POST /services             create  gateway comes from the form; the service
#                               lands on that gateway. Invalid params re-render
#                               with errors, nothing persisted.
# GET  /services/:id/edit    edit    same form pre-filled.
# PATCH /services/:id        update  name is IMMUTABLE after create (it drives the
#                               gateway's service name and the ztlp name
#                               <name>.<zone> — a rename would leave the old
#                               service live on the gateway with no panel row
#                               to fix it); the rest of the fields update.
#
# Scoping: every action is scoped to the zone's gateways. A service id
# that does not belong to this zone's gateways 404s on edit/update (no
# cross-zone mutation).
#
# Access: read_only admin gets 403 on new/create/edit/update.
#
# Publishing: creating or editing a service does NOT publish anything to
# the NS — the rendered policy is a gateway-side artifact the operator deploys
# at gateway deploy/restart time (the page says so). No Publisher calls here.
require "test_helper"

class ServicesMutationsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @gw_elixir = @zone.gateways.create!(name: "gw-e", kind: "elixir", status: "planned")
    @app = @gw.services.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2,
                                    description: "Blitz terminal")
  end

  # -------------------------------------------------------------- new / create

  test "new renders the form with the zone's gateways" do
    get new_service_path
    assert_response :success
    body = response.body
    assert_includes body, "New service"
    # every zone gateway is a pickable option
    assert_includes body, "gw1"
    assert_includes body, "gw-e"
  end

  test "create makes a service on the picked gateway and redirects to it" do
    post services_path, params: {
      service: {
        gateway_id: @gw_elixir.id.to_s,
        name: "portal",
        backend: "10.0.0.5:3000",
        protocol: "https",
        min_assurance: "3",
        description: "Web portal"
      }
    }
    app = Service.find_by(name: "portal")
    assert_not_nil app
    assert_equal @gw_elixir.id, app.gateway_id
    assert_equal "10.0.0.5:3000", app.backend
    assert_equal "https", app.protocol
    assert_equal 3, app.min_assurance
    assert_equal "Web portal", app.description
    assert_equal true, app.enabled
    assert_redirected_to service_path(app)
    follow_redirect!
    assert_includes response.body, "portal"
    assert_includes response.body, "portal.test.ztlp"
  end

  test "create with an invalid name re-renders the form with errors and persists nothing" do
    post services_path, params: {
      service: { gateway_id: @gw.id.to_s, name: "Bad Name", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_equal 1, @gw.services.count
    assert_includes response.body, "errors"
  end

  test "create rejects a name that is not a lowercase DNS label" do
    post services_path, params: {
      service: { gateway_id: @gw.id.to_s, name: "Bad Name", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_nil Service.find_by(name: "Bad Name")
  end

  test "create rejects a backend that is not host:port" do
    post services_path, params: {
      service: { gateway_id: @gw.id.to_s, name: "okname",
                     backend: "1.2.3.4:80\nallow = [\"*\"]" }
    }
    assert_response :unprocessable_content
    assert_nil Service.find_by(name: "okname")
  end

  test "create with an unknown gateway id re-renders with an error" do
    post services_path, params: {
      service: { gateway_id: "999999", name: "orphan", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_nil Service.find_by(name: "orphan")
  end

  test "create with a gateway from another zone re-renders with an error" do
    other = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:24000")
    foreign = other.gateways.create!(name: "gw-x", kind: "rust_listen", status: "planned")
    post services_path, params: {
      service: { gateway_id: foreign.id.to_s, name: "cross", backend: "1.2.3.4:80" }
    }
    assert_response :unprocessable_content
    assert_nil Service.find_by(name: "cross")
    assert_equal 0, foreign.services.count
  end

  # -------------------------------------------------------------- edit / update

  test "edit renders the form pre-filled with the current values" do
    get edit_service_path(@app)
    assert_response :success
    doc = Nokogiri::HTML(response.body)
    name_input = doc.at_css("input[name='service[name]']")
    assert_equal "comms-blitz", name_input["value"]
    assert_includes name_input["readonly"].to_s, "readonly"
    # the gateway select is disabled (immutable after create)
    gw_select = doc.at_css("select[name='service[gateway_id]']")
    assert_includes gw_select["disabled"].to_s, "disabled"
    backend_input = doc.at_css("input[name='service[backend]']")
    assert_equal "10.42.42.112:5200", backend_input["value"]
  end

  test "edit 404s for a service that is not on the zone's gateways" do
    other = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:24000")
    foreign_gw = other.gateways.create!(name: "gw-x", kind: "rust_listen", status: "planned")
    foreign_app = foreign_gw.services.create!(name: "cross")
    get edit_service_path(foreign_app)
    assert_response :not_found
  end

  test "update changes the mutable fields and redirects to the show page" do
    patch service_path(@app), params: {
      service: {
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
    assert_redirected_to service_path(@app)
  end

  test "update silently ignores a renamed name (no cross-gateway move, no rename)" do
    other_gw = @zone.gateways.create!(name: "gw2", kind: "rust_listen", status: "planned")
    patch service_path(@app), params: { service: { name: "renamed", gateway_id: other_gw.id.to_s } }
    @app.reload
    assert_equal "comms-blitz", @app.name
    assert_equal @gw.id, @app.gateway_id
  end

  test "update with invalid params re-renders edit and changes nothing" do
    patch service_path(@app), params: { service: { backend: "not a host:port" } }
    assert_response :unprocessable_content
    @app.reload
    assert_equal "10.42.42.112:5200", @app.backend
  end

  # -------------------------------------------------------------- access control

  test "read_only admin gets 403 on new, create, edit and update" do
    ro_admin, ro_seed = make_admin(role: "read_only", username: "ro-user")
    delete logout_path
    sign_in_as(ro_admin, ro_seed)

    get new_service_path
    assert_response :forbidden

    post services_path, params: { service: { gateway_id: @gw.id.to_s, name: "nope", backend: "1.2.3.4:80" } }
    assert_response :forbidden
    assert_nil Service.find_by(name: "nope")

    get edit_service_path(@app)
    assert_response :forbidden

    patch service_path(@app), params: { service: { backend: "9.9.9.9:9" } }
    assert_response :forbidden
    @app.reload
    assert_equal "10.42.42.112:5200", @app.backend
  end

  test "unauthenticated request is redirected to sign in" do
    delete logout_path
    get new_service_path
    assert_redirected_to login_path
  end

  test "create with no service params is a 400, never a 500" do
    assert_no_difference -> { Service.count } do
      post services_path, params: {}
    end
    assert_response :bad_request
  end
end
