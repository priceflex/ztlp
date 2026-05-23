# frozen_string_literal: true

# Admin::ApiClientsController — dashboard CRUD for the `api_clients`
# allowlist that BS-PR-2 added.
#
# Lets a super admin:
#
#   * View every api_client (active + inactive), grouped by zone
#   * Create a new client for a (zone, name) pair
#   * Reactivate / deactivate (the kill switch from BS-PR-2)
#   * See last_used_at — useful for spotting dormant credentials
#
# The actual HMAC secret is NOT managed here — secrets live in the
# per-zone secret store (`ZTLP_HMAC_SECRET_<UPCASE_ZONE>`) shared with
# the relay and gateway. This UI manages **authorization**: who is
# permitted to talk to the v1 API at all. The HMAC is the credential
# that proves the caller actually holds the per-zone secret.
#
# Every mutation writes an AuditLog row so a downstream observer can
# trace "who authorized this client / who revoked it."
module Admin
  class ApiClientsController < ApplicationController
    before_action :require_super_admin
    before_action :set_api_client, only: %i[edit update destroy deactivate reactivate]

    # GET /admin/api_clients
    def index
      @api_clients = ApiClient.order(:zone, :name)
    end

    # GET /admin/api_clients/new
    def new
      @api_client = ApiClient.new
    end

    # POST /admin/api_clients
    def create
      @api_client = ApiClient.new(api_client_params)
      @api_client.created_by_admin_user_id = current_admin&.id

      if @api_client.save
        AuditLog.record(
          action: "api_client.created",
          target: @api_client,
          status: "success",
          details: {
            name: @api_client.name,
            zone: @api_client.zone,
            created_by_admin_user_id: current_admin&.id
          },
          ip_address: request.remote_ip
        )
        redirect_to admin_api_clients_path,
                    notice: "API client #{@api_client.name} (#{@api_client.zone}) created."
      else
        render :new, status: :unprocessable_entity
      end
    end

    # GET /admin/api_clients/:id/edit
    def edit
    end

    # PATCH /admin/api_clients/:id
    def update
      if @api_client.update(api_client_params)
        AuditLog.record(
          action: "api_client.updated",
          target: @api_client,
          status: "success",
          details: { name: @api_client.name, zone: @api_client.zone },
          ip_address: request.remote_ip
        )
        redirect_to admin_api_clients_path, notice: "API client updated."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    # DELETE /admin/api_clients/:id
    #
    # Hard-deletes the row. Use `deactivate` instead if you want a
    # reversible kill switch — destroy is for accidentally-created
    # rows that should never have existed (e.g. a typo in `zone`).
    def destroy
      name = @api_client.name
      zone = @api_client.zone
      @api_client.destroy!

      AuditLog.record(
        action: "api_client.deleted",
        target: nil,
        status: "success",
        details: { name: name, zone: zone, deleted_by_admin_user_id: current_admin&.id },
        ip_address: request.remote_ip
      )

      redirect_to admin_api_clients_path, notice: "API client #{name} deleted."
    end

    # POST /admin/api_clients/:id/deactivate
    #
    # The kill switch — flips `active=false` so the authenticator
    # starts rejecting requests from this client without rotating the
    # per-zone secret.
    def deactivate
      if @api_client.update(active: false)
        AuditLog.record(
          action: "api_client.deactivated",
          target: @api_client,
          status: "success",
          details: { name: @api_client.name, zone: @api_client.zone },
          ip_address: request.remote_ip
        )
      end
      redirect_to admin_api_clients_path, notice: "API client #{@api_client.name} deactivated."
    end

    # POST /admin/api_clients/:id/reactivate
    def reactivate
      if @api_client.update(active: true)
        AuditLog.record(
          action: "api_client.reactivated",
          target: @api_client,
          status: "success",
          details: { name: @api_client.name, zone: @api_client.zone },
          ip_address: request.remote_ip
        )
      end
      redirect_to admin_api_clients_path, notice: "API client #{@api_client.name} reactivated."
    end

    private

    def set_api_client
      @api_client = ApiClient.find(params[:id])
    end

    def api_client_params
      params.require(:api_client).permit(:name, :zone, :notes, :active)
    end
  end
end
