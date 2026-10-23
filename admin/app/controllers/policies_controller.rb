# frozen_string_literal: true

# Slice 9c: the Policies page — read-only overview of every application's
# rules (grouped by application, across the zone's gateways) plus the Test
# access widget (device + application pickers).
#
# index: no mutations, no Publisher calls.
# test:  POST {device_id, application_id} (sub-slice 2) — runs
#        Ztlp::AccessEvaluator over the zone-scoped device x application and
#        re-renders the page with the decision under the widget; a real check
#        writes audit row policy.test. The decision is a panel-side
#        simulation of the gateway walk, never a probe of the running gateway.
class PoliciesController < ApplicationController
  def index
    load_overview
  end

  def test
    if params[:device_id].blank? || params[:application_id].blank?
      flash.now[:alert] = "Choose a device and an application to check."
      if request.format.json?
        return render json: { error: "Choose a device and an application to check." },
                     status: :unprocessable_content
      end
      load_overview
      return render :index, status: :unprocessable_content
    end

    device = @zone.devices.find_by(id: params[:device_id])
    raise ActiveRecord::RecordNotFound, "device" if device.nil?

    # Zone-scoped the same way ApplicationsController#zone_application does:
    # a cross-zone application id 404s without revealing it exists elsewhere.
    application = Application
                  .where(id: params[:application_id])
                  .where(gateway_id: @zone.gateways.select(:id))
                  .includes(gateway: :zone)
                  .first
    raise ActiveRecord::RecordNotFound, "application" if application.nil?

    @test_result = Ztlp::AccessEvaluator.evaluate(device, application)
    audit!("policy.test", target: application,
          device_name: device.name, application_name: application.name,
          decision: @test_result[:decision], reason: @test_result[:reason])
    # Slice 9c sub-slice 3: the directory.js widget posts JSON (X-CSRF-Token
    # from the meta tag) and renders the decision client-side with
    # createElement/textContent. The plain HTML form re-renders the page.
    if request.format.json?
      render json: @test_result
    else
      load_overview
      @test_result_device_name = device.name
      @test_result_application_name = application.name
      render :index
    end
  end

  private

  def load_overview
    @gateways = @zone.gateways.order(:name).includes(applications: :policy_rules)
    @policy_docs = @gateways.index_with { |gw| Ztlp::PolicyRenderer.render(gw) }
    @test_devices = @zone.devices.order(:name).limit(500)
    @test_apps = @gateways.flat_map { |gw| gw.applications.order(:name).to_a.map { |a| [ gw, a ] } }
  end
end
