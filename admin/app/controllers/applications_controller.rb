# frozen_string_literal: true

# Slice 9b sub-slice 2: Applications directory — read side (spec Slice 9).
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
# editing an application publishes NOTHING to the NS: the rendered policy is a
# gateway-side artifact deployed by the operator at gateway restart.
class ApplicationsController < ApplicationController
  before_action :require_write_access, only: %i[new create edit update]

  APP_FIELDS = %i[backend protocol min_assurance description].freeze

  def index
    @apps = @zone.gateways.includes(applications: %i[policy_rules]).flat_map(&:applications)
  end

  def show
    @application = Application
                     .where(id: params[:id])
                     .where(gateway_id: @zone.gateways.select(:id))
                     .includes(gateway: :zone, policy_rules: [])
                     .first
    raise ActiveRecord::RecordNotFound, "application" if @application.nil?

    render :show, layout: false if request.headers["X-Drawer"] == "1"
  end

  def new
    @gateways = @zone.gateways.order(:name)
    @application = Application.new
  end

  def create
    gateway = scoped_gateway(params.require(:application)[:gateway_id]) # missing -> 400, not 500
    if gateway.nil?
      @gateways = @zone.gateways.order(:name)
      @application = Application.new(application_params)
      @application.errors.add(:base, "Pick a gateway from this zone.")
      return render :new, status: :unprocessable_content
    end

    @application = gateway.applications.build(application_params)
    if @application.save
      audit!("application.create", target: @application,
                                details: { gateway: @application.gateway.name, name: @application.name })
      redirect_to application_path(@application), notice: "Application #{@application.name} created. Deploy the rendered policy and restart the gateway to make it live."
    else
      @gateways = @zone.gateways.order(:name)
      render :new, status: :unprocessable_content
    end
  end

  def edit
    @application = zone_application
    @gateways = @zone.gateways.order(:name)
  end

  def update
    @application = zone_application
    # Name and gateway are immutable after create: the name drives the
    # gateway's service entry and the ztlp name; moving gateways would leave
    # the old gateway's policy still allowing the (now missing) service.
    if @application.update(application_params.except(:name, :gateway_id))
      audit!("application.update", target: @application, details: { name: @application.name })
      redirect_to application_path(@application), notice: "Application #{@application.name} updated. Deploy the rendered policy and restart the gateway to make it live."
    else
      @gateways = @zone.gateways.order(:name)
      render :edit, status: :unprocessable_content
    end
  end

  private

  # The show/edit/update target, scoped to the zone's gateways (cross-zone id
  # -> 404, same as show).
  def zone_application
    @application ||= Application
                      .where(id: params[:id])
                      .where(gateway_id: @zone.gateways.select(:id))
                      .includes(gateway: :zone)
                      .first
    raise ActiveRecord::RecordNotFound, "application" if @application.nil?

    @application
  end

  # A gateway the form may target must belong to THIS zone; an unknown id or a
  # foreign-zone gateway is not a persistence target.
  def scoped_gateway(gateway_id)
    @zone.gateways.find_by(id: gateway_id)
  end

  def application_params
    params.require(:application).permit(:gateway_id, :name, *APP_FIELDS)
  end
end
