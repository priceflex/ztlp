# frozen_string_literal: true

# Slice 9c: the Policies page — read-only overview of every service's
# rules (grouped by service, across the zone's gateways) plus the Test
# access widget (device + service pickers).
#
# index: no mutations, no Publisher calls.
# test:  POST {device_id, service_id} (sub-slice 2) — runs
#        Ztlp::AccessEvaluator over the zone-scoped device x service and
#        re-renders the page with the decision under the widget; a real check
#        writes audit row policy.test. The decision is a panel-side
#        simulation of the gateway walk, never a probe of the running gateway.
class PoliciesController < ApplicationController
  def index
    load_overview
  end

  def test
    if params[:device_id].blank? || params[:service_id].blank?
      flash.now[:alert] = "Choose a device and a service to check."
      if request.format.json?
        return render json: { error: "Choose a device and a service to check." },
                     status: :unprocessable_content
      end
      load_overview
      return render :index, status: :unprocessable_content
    end

    device = @zone.devices.find_by(id: params[:device_id])
    raise ActiveRecord::RecordNotFound, "device" if device.nil?

    # Zone-scoped the same way ServicesController#zone_service does:
    # a cross-zone service id 404s without revealing it exists elsewhere.
    service = Service
                  .where(id: params[:service_id])
                  .where(gateway_id: @zone.gateways.select(:id))
                  .includes(gateway: :zone)
                  .first
    raise ActiveRecord::RecordNotFound, "service" if service.nil?

    @test_result = Ztlp::AccessEvaluator.evaluate(device, service)
    audit!("policy.test", target: service,
          device_name: device.name, service_name: service.name,
          decision: @test_result[:decision], reason: @test_result[:reason])
    # Slice 9c sub-slice 3: the directory.js widget posts JSON (X-CSRF-Token
    # from the meta tag) and renders the decision client-side with
    # createElement/textContent. The plain HTML form re-renders the page.
    if request.format.json?
      render json: @test_result
    else
      load_overview
      @test_result_device_name = device.name
      @test_result_service_name = service.name
      render :index
    end
  end

  private

  def load_overview
    @gateways = @zone.gateways.order(:name).includes(services: :policy_rules)
    @policy_docs = @gateways.index_with { |gw| Ztlp::PolicyRenderer.render(gw) }
    @test_devices = @zone.devices.order(:name).limit(500)
    @test_apps = @gateways.flat_map { |gw| gw.services.order(:name).to_a.map { |a| [ gw, a ] } }
  end
end
