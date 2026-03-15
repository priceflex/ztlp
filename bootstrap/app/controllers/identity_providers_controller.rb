# frozen_string_literal: true

# CRUD for identity provider configurations (admin).
class IdentityProvidersController < ApplicationController
  before_action :set_network
  before_action :set_identity_provider, only: [:show, :edit, :update, :destroy]

  def index
    @identity_providers = @network.identity_providers.order(:name)
  end

  def show
  end

  def new
    @identity_provider = @network.identity_providers.new(
      provider_type: "google_oauth2",
      role_default: "user",
      enabled: true,
      auto_create_users: false
    )
  end

  def create
    @identity_provider = @network.identity_providers.new(identity_provider_params)

    if @identity_provider.save
      AuditLog.record(
        action: "idp_config_create",
        target: @identity_provider,
        details: { name: @identity_provider.name, provider_type: @identity_provider.provider_type, network: @network.name }
      )
      redirect_to network_identity_provider_path(@network, @identity_provider),
                  notice: "Identity provider '#{@identity_provider.name}' created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    if @identity_provider.update(identity_provider_params)
      AuditLog.record(
        action: "idp_config_update",
        target: @identity_provider,
        details: { name: @identity_provider.name, network: @network.name }
      )
      redirect_to network_identity_provider_path(@network, @identity_provider),
                  notice: "Identity provider updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    name = @identity_provider.name
    @identity_provider.destroy!
    AuditLog.record(
      action: "idp_config_destroy",
      target: @network,
      details: { name: name, network: @network.name }
    )
    redirect_to network_identity_providers_path(@network), notice: "Identity provider '#{name}' deleted."
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_identity_provider
    @identity_provider = @network.identity_providers.find(params[:id])
  end

  def identity_provider_params
    permitted = params.require(:identity_provider).permit(
      :name, :provider_type, :client_id, :client_secret,
      :issuer_url, :allowed_domains, :auto_create_users,
      :role_default, :enabled
    )
    # On update, don't overwrite secret if left blank
    if @identity_provider&.persisted? && permitted[:client_secret].blank?
      permitted.delete(:client_secret)
    end
    permitted
  end
end
