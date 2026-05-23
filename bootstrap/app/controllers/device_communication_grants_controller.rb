# frozen_string_literal: true

# DeviceCommunicationGrantsController — dashboard CRUD for the
# device-to-device communication permissions table BS-PR-5 introduced.
#
# Nested under a Network so the URL space is:
#
#   GET    /networks/:network_id/device_communication_grants
#   GET    /networks/:network_id/device_communication_grants/new
#   POST   /networks/:network_id/device_communication_grants
#   POST   /networks/:network_id/device_communication_grants/:id/revoke
#
# The nested URL space (vs. a flat `/admin/device_grants`) reflects
# the underlying invariant: a grant is always between two devices in
# the SAME network. Surfacing the network context in the URL makes
# the form trivially scoped — only that network's devices show up
# in the source/target dropdowns.
class DeviceCommunicationGrantsController < ApplicationController
  before_action :set_network
  before_action :set_grant, only: %i[revoke destroy]

  # GET /networks/:network_id/device_communication_grants
  def index
    @device_ids_in_network = @network.ztlp_devices.pluck(:id)
    @grants = DeviceCommunicationGrant
                .where(source_device_id: @device_ids_in_network)
                .includes(:source_device, :target_device)
                .order(:revoked_at, :created_at)
  end

  # GET /networks/:network_id/device_communication_grants/new
  def new
    @grant = DeviceCommunicationGrant.new
    @devices = @network.ztlp_devices.order(:name)
  end

  # POST /networks/:network_id/device_communication_grants
  def create
    @grant = DeviceCommunicationGrant.new(grant_params)
    @grant.granted_by_admin_user_id = current_admin&.id

    if @grant.save
      AuditLog.record(
        action: "device_grant.created",
        target: @grant,
        status: "success",
        details: {
          source_device_id: @grant.source_device_id,
          target_device_id: @grant.target_device_id,
          network_id: @network.id,
          granted_by_admin_user_id: current_admin&.id
        },
        ip_address: request.remote_ip
      )
      redirect_to network_device_communication_grants_path(@network),
                  notice: "Grant created: #{@grant.source_device.name} → #{@grant.target_device.name}"
    else
      @devices = @network.ztlp_devices.order(:name)
      render :new, status: :unprocessable_entity
    end
  end

  # POST /networks/:network_id/device_communication_grants/:id/revoke
  def revoke
    if @grant.revoke!(admin_user: current_admin)
      redirect_to network_device_communication_grants_path(@network),
                  notice: "Grant revoked."
    else
      redirect_to network_device_communication_grants_path(@network),
                  alert: "Grant already revoked."
    end
  end

  # DELETE /networks/:network_id/device_communication_grants/:id
  #
  # Hard-delete for accidentally-created rows. Prefer revoke for the
  # normal kill-switch path (revoke keeps the audit trail intact).
  def destroy
    src = @grant.source_device_id
    tgt = @grant.target_device_id
    @grant.destroy!

    AuditLog.record(
      action: "device_grant.deleted",
      target: nil,
      status: "success",
      details: { source_device_id: src, target_device_id: tgt, network_id: @network.id },
      ip_address: request.remote_ip
    )

    redirect_to network_device_communication_grants_path(@network),
                notice: "Grant deleted."
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_grant
    # Constrain lookups to the network — prevents an admin from
    # tampering with a grant for some other network by URL-walking.
    device_ids = @network.ztlp_devices.pluck(:id)
    @grant = DeviceCommunicationGrant
               .where(source_device_id: device_ids)
               .find(params[:id])
  end

  def grant_params
    params.require(:device_communication_grant)
          .permit(:source_device_id, :target_device_id, :notes)
  end
end
