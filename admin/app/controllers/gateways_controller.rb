# frozen_string_literal: true

# Slice 9b sub-slice 6: gateway minimal CRUD inline from the service form
# (spec Slice 9). Gateways front zone services and stamp ZTLP identity headers;
# a service always lives ON a gateway, so the panel needs a way to add the
# zone's gateway rows from inside the service flow rather than a separate
# top-level page.
#
# Minimal CRUD:
#   new        — the inline "New gateway" form (name, kind, host_note)
#   create     — create a gateway on the current zone
#   update_kind— minimal edit: kind + host_note only. Name is immutable (it
#                drives ns_name <name>.<zone> and the rendered service entry).
#
# Access: write-gated (read_only 403s). No NS publish: creating a gateway row is
# panel-local; the operator deploys the rendered policy and restarts the gateway.
class GatewaysController < ApplicationController
  before_action :require_operator, only: %i[new create update_kind]

  def new
    @gateway = Gateway.new
  end

  def create
    @gateway = @zone.gateways.build(gateway_params)
    if @gateway.save
      audit!("gateway.create", target: @gateway,
                            details: { name: @gateway.name, kind: @gateway.kind })
      redirect_to services_path,
                  notice: "Gateway #{@gateway.name} created. Add a service on it, then deploy the rendered policy and restart the gateway."
    else
      render :new, status: :unprocessable_content
    end
  end

  # Minimal edit: kind + host_note. Name is immutable — it drives ns_name and
  # the rendered service entry; renaming would leave the old service live on the
  # gateway with no panel row to fix it. Cross-zone / unknown id 404s.
  def update_kind
    @gateway = scoped_gateway
    raise ActiveRecord::RecordNotFound, "gateway" if @gateway.nil?

    if @gateway.update(gateway_update_params)
      audit!("gateway.update", target: @gateway,
                            details: { name: @gateway.name, kind: @gateway.kind })
      redirect_to services_path,
                  notice: "Gateway #{@gateway.name} updated. Deploy the rendered policy and restart the gateway to make it live."
    else
      render :new, status: :unprocessable_content
    end
  end

  private

  def scoped_gateway
    @zone.gateways.find_by(id: params[:id])
  end

  def gateway_params
    params.require(:gateway).permit(:name, :kind, :host_note)
  end

  def gateway_update_params
    params.permit(:kind, :host_note)
  end
end
