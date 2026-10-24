# frozen_string_literal: true

# "Register application" (PLAN-multizone-and-app-registration.md, Phase B).
#   GET  /applications/register            the form + services discovered on the NS
#   GET  /applications/register?fqdn=...   look the name up (NS read only) and show what will happen
#   POST /applications/register            create the gateway + application (write access)
# Registering never publishes to the NS.
class ApplicationRegistrationsController < ApplicationController
  before_action :require_write_access, only: :create

  def new
    @fqdn = params[:fqdn].to_s.strip.downcase.presence
    if @fqdn
      lookup_fqdn
    else
      @discovered, @discover_errors = safe_ns { Ztlp::AppRegistrar.discover }
      @discovered ||= []
      @discover_errors ||= []
    end
  end

  def create
    @fqdn = params[:fqdn].to_s.strip.downcase
    @reg_zone = Ztlp::AppRegistrar.zone_for(@fqdn)
    return refuse("#{@fqdn.presence || 'That name'} is in no zone this panel knows. Add the zone first.") unless @reg_zone
    return refuse("#{@fqdn} must be ONE label inside #{@reg_zone.name} (e.g. www.#{@reg_zone.name}).") unless Ztlp::AppRegistrar.label_for(@fqdn, @reg_zone)

    backend = params[:backend].to_s.strip
    if backend.present? && !backend.match?(Application::BACKEND_FORMAT)
      return refuse("Backend must be host:port (for example 10.0.0.5:8080).")
    end

    record, = safe_ns { Ztlp::AppRegistrar.lookup(@fqdn, @reg_zone) }
    record = nil unless record.is_a?(Hash)
    existed = @reg_zone.gateways.exists?(name: Ztlp::AppRegistrar.label_for(@fqdn, @reg_zone))
    app = Ztlp::AppRegistrar.register!(@fqdn, @reg_zone, record: record, backend: backend)
    audit!("application.register", target: app, status: "ok",
                                   details: { fqdn: @fqdn, zone: @reg_zone.name, found_on_ns: record.present?, existed: existed })
    session[:zone_id] = @reg_zone.id
    note = if existed then "#{@fqdn} was already registered."
    elsif record then "#{@fqdn} registered from the name server. Add access rules, then deploy the gateway policy."
    else "#{@fqdn} registered as planned. Start its gateway with the command below."
    end
    redirect_to application_path(app), notice: note
  rescue Ztlp::AppRegistrar::Error, ActiveRecord::RecordInvalid => e
    refuse(e.message)
  end

  private

  def lookup_fqdn
    @reg_zone = Ztlp::AppRegistrar.zone_for(@fqdn)
    return unless @reg_zone

    @label = Ztlp::AppRegistrar.label_for(@fqdn, @reg_zone)
    @existing = @reg_zone.gateways.find_by(ns_name: @fqdn)
    result, errors = safe_ns { Ztlp::AppRegistrar.lookup(@fqdn, @reg_zone) }
    @ns_error = errors&.first
    @not_configured = result == :not_configured
    @record = result.is_a?(Hash) ? result : nil
  end

  # Run an NS read; never 500 on an unreachable NS. Returns [value, errors].
  def safe_ns
    value = yield
    value.is_a?(Array) && value.size == 2 && value[1].is_a?(Array) ? value : [ value, [] ]
  rescue Ztlp::NsClient::NsError, SystemCallError, IOError, Timeout::Error, Net::OpenTimeout => e
    [ nil, [ "name server: #{e.class}" ] ]
  end

  def refuse(message)
    flash.now[:alert] = message
    @discovered = []
    @discover_errors = []
    render :new, status: :unprocessable_content
  end
end
