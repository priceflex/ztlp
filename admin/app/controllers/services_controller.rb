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
  before_action :require_operator, only: %i[new create edit update enable disable install_script check_gateway]

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

  # Add Service (slice 4): one form for a new service + its gateway. `?existing=1` keeps the older
  # form that adds a service to a gateway that already exists.
  def new
    if params[:existing].present?
      @gateways = @zone.gateways.order(:name)
      @service = Service.new
      return render :new_existing
    end

    @setup = ServiceSetup.new
    load_setup_pickers
  end

  def create
    return create_from_setup if params.key?(:setup)

    gateway = scoped_gateway(params.require(:service)[:gateway_id]) # missing -> 400, not 500
    if gateway.nil?
      @gateways = @zone.gateways.order(:name)
      @service = Service.new(service_params)
      @service.errors.add(:base, "Pick a gateway from this zone.")
      return render :new_existing, status: :unprocessable_content
    end

    @service = gateway.services.build(service_params)
    if @service.save
      audit!("service.create", target: @service,
                                details: { gateway: @service.gateway.name, name: @service.name })
      redirect_to service_path(@service), notice: "Service #{@service.name} created. Deploy the rendered policy and restart the gateway to make it live."
    else
      @gateways = @zone.gateways.order(:name)
      render :new_existing, status: :unprocessable_content
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
    attrs = service_params.except(:name, :gateway_id)
    if attrs[:gateway_attributes].present?
      attrs[:gateway_attributes] = attrs[:gateway_attributes].merge(id: @service.gateway_id)
    end
    if @service.update(attrs)
      # Turning sign-in headers on for the first time needs a secret for the gateway and the app.
      @service.gateway.rotate_header_secret! if @service.gateway.inject_headers && @service.gateway.header_secret_ct.blank?
      audit!("service.update", target: @service, details: { name: @service.name,
                                                            gateway: @service.gateway.saved_changes.keys - %w[updated_at header_secret_ct] })
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

  INSTALL_WINDOW = 30.minutes

  # The gateway install script (slice 5). It carries the zone relay secret and the header secret, so
  # it is rendered straight into this POST response (no-store), operators only, audited without
  # values; viewable for INSTALL_WINDOW after the first show, then only via Regenerate (which
  # rotates the header secret: the app must get the new one too).
  def install_script
    @service = zone_service
    gw = @service.gateway
    missing = Ztlp::GatewayInstall.missing(gw)
    if missing.any?
      return redirect_to service_path(@service), alert: "No install script yet: #{missing.to_sentence}."
    end

    @regenerated = params[:regenerate] == "1"
    if gw.install_shown_at && gw.install_shown_at < INSTALL_WINDOW.ago && !@regenerated
      return redirect_to service_path(@service),
                         alert: "The install script was shown at #{gw.install_shown_at.utc.strftime('%Y-%m-%d %H:%M UTC')} " \
                                "and is no longer viewable. Use Regenerate to show it again (it rotates the header secret)."
    end

    gw.rotate_header_secret! if gw.inject_headers && (@regenerated || gw.header_secret_ct.blank?)
    gw.update!(install_shown_at: Time.current) if @regenerated || gw.install_shown_at.nil?
    @script = Ztlp::GatewayInstall.script(gw, relay_secret: gw.zone.relay_secret_ct, header_secret: gw.header_secret_ct)
    @app_env = gw.inject_headers ? Ztlp::GatewayInstall.app_env(gw, header_secret: gw.header_secret_ct) : nil
    @expires_at = gw.install_shown_at + INSTALL_WINDOW
    audit!(@regenerated ? "gateway.install_regenerated" : "gateway.install_shown", target: gw,
           details: { fqdn: gw.ns_name, header_secret_rotated: @regenerated && gw.inject_headers })
    response.headers["Cache-Control"] = "no-store"
    render :install_script
  rescue Ztlp::GatewayInstall::Unsafe => e
    redirect_to service_path(@service), alert: "Cannot build the install script: #{e.message}."
  end

  def check_gateway
    @service = zone_service
    gw = @service.gateway
    result = Ztlp::GatewayStatus.check!(gw)
    audit!("gateway.check", target: gw, details: { fqdn: gw.ns_name, result: result.to_s })
    message = case result
    when :online then [ :notice, "#{gw.ns_name} is on the name server: online." ]
    when :not_found then [ :alert, "#{gw.ns_name} is not on the name server yet. Run the install script on the box, then check again." ]
    else [ :alert, "This zone has no name server admin secret in the panel, so it cannot check." ]
    end
    redirect_to service_path(@service), message[0] => message[1]
  rescue Ztlp::NsClient::NsError, SystemCallError, IOError, Timeout::Error => e
    redirect_to service_path(@service), alert: "Could not reach the name server (#{e.class.name.demodulize}). Try again."
  end

  private

  def create_from_setup
    @setup = ServiceSetup.new(setup_params)
    if @setup.save
      svc = @setup.service
      session[:zone_id] = svc.gateway.zone_id
      audit!("service.setup", target: svc, details: {
               fqdn: svc.ztlp_name, gateway: svc.gateway.name, backend: svc.backend, protocol: svc.protocol,
               inject_headers: svc.gateway.inject_headers, bind_port: svc.gateway.bind_port,
               access: @setup.access, rules: svc.policy_rules.count
             })
      redirect_to service_path(svc), notice: "#{svc.ztlp_name} created (planned). Install its gateway with the script below."
    else
      load_setup_pickers
      render :new, status: :unprocessable_content
    end
  end

  def load_setup_pickers
    @zone_groups = @zone.groups.order(:name).limit(500)
    @zone_devices = @zone.devices.where.not(status: "revoked").order(:name).limit(500)
  end

  def setup_params
    params.require(:setup).permit(*ServiceSetup.attribute_names.map(&:to_sym))
  end

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

  GATEWAY_FIELDS = %i[host_note bind_port max_sessions punch inject_headers policy_file ns_server relay_addr
                      image_tag subject_map_text].freeze

  def service_params
    params.require(:service).permit(:gateway_id, :name, *APP_FIELDS, gateway_attributes: GATEWAY_FIELDS)
  end
end
