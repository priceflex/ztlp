# frozen_string_literal: true

# Multi-zone (PLAN-multizone-and-app-registration.md, Phase A): switch the current zone (rail picker),
# set the admin's default zone, and add a zone. Secrets and the zone authority are NEVER taken from a
# form: they stay on the stdin rake tasks (`zone:set_secret[...] ZONE=`, `zone:import_authority`).
class ZonesController < ApplicationController
  before_action :require_super_admin, only: %i[new create]

  # POST /zone/switch  zone_id=
  def switch
    zone = Zone.find_by(id: params[:zone_id])
    return redirect_to root_path, alert: "Unknown zone." unless zone

    session[:zone_id] = zone.id
    audit!("zone.switch", target: zone, status: "ok", details: { zone: zone.name })
    redirect_to same_site_back_path || root_path, notice: "Now working in #{zone.name}."
  end

  # POST /zone/default  (makes the CURRENT zone the admin's default)
  def make_default
    current_admin.update!(default_zone: @zone)
    audit!("admin.default_zone", target: @zone, status: "ok", details: { zone: @zone.name })
    redirect_to zone_path, notice: "#{@zone.name} is now your default zone."
  end

  def new
    @new_zone = Zone.new(ns_addr: @zone&.ns_addr, relay_addrs: @zone&.relay_addrs)
  end

  def create
    @new_zone = Zone.new(zone_params)
    if @new_zone.save
      audit!("zone.create", target: @new_zone, status: "ok", details: { zone: @new_zone.name })
      session[:zone_id] = @new_zone.id
      redirect_to zone_path, notice: "Zone #{@new_zone.name} added. Set its secrets with " \
                                     "`zone:set_secret[...]` (ZONE=#{@new_zone.name}) on the server."
    else
      render :new, status: :unprocessable_content
    end
  end

  private

  def zone_params
    p = params.require(:zone).permit(:name, :ns_addr, :relay_addrs_text, :ns_pubkey_hex)
    p[:name] = p[:name].to_s.strip.downcase if p.key?(:name)
    p
  end

  # Only a same-origin Referer path (never an off-site redirect).
  def same_site_back_path
    uri = URI.parse(request.referer.to_s)
    return nil unless uri.host == request.host && uri.path.to_s.start_with?("/")

    uri.path
  rescue URI::InvalidURIError
    nil
  end
end
