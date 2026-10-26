# frozen_string_literal: true

# Slice 9b sub-slice 2: Services directory — read side (spec Slice 9).
# Index across the zone's gateways; show = page or drawer fragment (X-Drawer: 1,
# same contract as users/groups show). No Publisher calls: the rendered policy
# is computed locally with Ztlp::PolicyRenderer; publishing it is the operator's
# job at gateway deploy time (the page says so).
#
# Slice 9b sub-slice 3: new/create + edit/update. Name is immutable after
# create (it drives the gateway's service name and the ztlp name
# <name>.<zone> — a rename would leave the old service live on the gateway).
# Every action is scoped to the zone's gateways (cross-zone ids 404 on
# edit/update; a gateway pick from another zone fails create). Creating or
# editing a service publishes NOTHING to the NS: the rendered policy is a
# gateway-side artifact deployed by the operator at gateway restart.
class ServicesController < ApplicationController
  before_action :require_operator, only: %i[new create edit update enable disable]

  APP_FIELDS = %i[backend protocol min_assurance description].freeze

  def index
    @apps = @zone.gateways.includes(services: %i[policy_rules]).flat_map(&:services)
  end

  def show
    @service = Service
                     .where(id: params[:id])
                     .where(gateway_id: @zone.gateways.select(:id))
                     .includes(gateway: :zone, policy_rules: [])
                     .first
    raise ActiveRecord::RecordNotFound, "service" if @service.nil?

    load_rule_subjects
    render :show, layout: false if request.headers["X-Drawer"] == "1"
  end

  def new
    @gateways = @zone.gateways.order(:name)
    @service = Service.new
  end

  def create
    gateway = scoped_gateway(params.require(:service)[:gateway_id]) # missing -> 400, not 500
    if gateway.nil?
      @gateways = @zone.gateways.order(:name)
      @service = Service.new(service_params)
      @service.errors.add(:base, "Pick a gateway from this zone.")
      return render :new, status: :unprocessable_content
    end

    @service = gateway.services.build(service_params)
    if @service.save
      audit!("service.create", target: @service,
                                details: { gateway: @service.gateway.name, name: @service.name })
      redirect_to service_path(@service), notice: "Service #{@service.name} created. Deploy the rendered policy and restart the gateway to make it live."
    else
      @gateways = @zone.gateways.order(:name)
      render :new, status: :unprocessable_content
    end
  end

  def edit
    @service = zone_service
    @gateways = @zone.gateways.order(:name)
  end

  def update
    @service = zone_service
    # Name and gateway are immutable after create: the name drives the
    # gateway's service entry and the ztlp name; moving gateways would leave
    # the old gateway's policy still allowing the (now missing) service.
    if @service.update(service_params.except(:name, :gateway_id))
      audit!("service.update", target: @service, details: { name: @service.name })
      redirect_to service_path(@service), notice: "Service #{@service.name} updated. Deploy the rendered policy and restart the gateway to make it live."
    else
      @gateways = @zone.gateways.order(:name)
      render :edit, status: :unprocessable_content
    end
  end

  # Slice 9b sub-slice 5: enable/disable. The rendered policy only lists
  # enabled services as [[services]] (PolicyRenderer), so disabling is how
  # an operator takes a service off the gateway's allow-list without deleting
  # its rules. No NS publish: the operator deploys the rendered policy and
  # restarts the gateway for the change to take effect (the redirect says so).
  # Toggling to the current state is a no-op (no audit row).
  def enable
    set_enabled(true)
  end

  def disable
    set_enabled(false)
  end

  private

  # One shared toggle so enable/disable can't drift apart. A no-op toggle
  # (already in the requested state) writes no audit row and just re-renders.
  def set_enabled(want)
    @service = zone_service
    if @service.enabled != want
      @service.update!(enabled: want)
      audit!(want ? "service.enable" : "service.disable", target: @service,
            details: { name: @service.name, enabled: want })
      redirect_to service_path(@service),
                  notice: "Service #{@service.name} #{want ? 'enabled' : 'disabled'}. " \
                          "Deploy the rendered policy and restart the gateway to make it live."
    else
      redirect_to service_path(@service),
                  notice: "Service #{@service.name} is already #{want ? 'enabled' : 'disabled'}."
    end
  end

  # The show/edit/update target, scoped to the zone's gateways (cross-zone id
  # -> 404, same as show).
  def zone_service
    @service ||= Service
                      .where(id: params[:id])
                      .where(gateway_id: @zone.gateways.select(:id))
                      .includes(gateway: :zone)
                      .first
    raise ActiveRecord::RecordNotFound, "service" if @service.nil?

    @service
  end

  # The rule form's subject picker (sub-slice 4) lists rows in THIS zone.
  def load_rule_subjects
    @zone_users = @zone.users.order(:display_name).limit(500)
    @zone_devices = @zone.devices.order(:name).limit(500)
    @zone_groups = @zone.groups.order(:name).limit(500)
  end


  # A gateway the form may target must belong to THIS zone; an unknown id or a
  # foreign-zone gateway is not a persistence target.
  def scoped_gateway(gateway_id)
    @zone.gateways.find_by(id: gateway_id)
  end

  def service_params
    params.require(:service).permit(:gateway_id, :name, *APP_FIELDS)
  end
end
