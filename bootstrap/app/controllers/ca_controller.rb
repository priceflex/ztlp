# frozen_string_literal: true

class CaController < ApplicationController
  before_action :set_network
  before_action :set_ca_service

  # GET /networks/:network_id/ca
  def show
    @status = @ca_service.status
    @expiring_certs = @network.certificates.expiring_soon.order(expires_at: :asc).limit(10)
  end

  # POST /networks/:network_id/ca/init
  def init
    result = @ca_service.init_ca

    if result[:success]
      redirect_to network_ca_path(@network), notice: "Certificate Authority initialized successfully."
    else
      redirect_to network_ca_path(@network), alert: "Failed to initialize CA: #{result[:error]}"
    end
  end

  # GET /networks/:network_id/ca/export_root
  def export_root
    pem = @ca_service.export_root_cert

    if pem
      send_data pem,
                filename: "ztlp-root-#{@network.zone}.pem",
                type: "application/x-pem-file",
                disposition: "attachment"
    else
      redirect_to network_ca_path(@network), alert: "Root certificate not available."
    end
  end

  # POST /networks/:network_id/ca/rotate_intermediate
  def rotate_intermediate
    result = @ca_service.rotate_intermediate

    if result[:success]
      redirect_to network_ca_path(@network), notice: "Intermediate CA rotated. New key: #{result[:new_key]&.first(16)}..."
    else
      redirect_to network_ca_path(@network), alert: "Rotation failed: #{result[:error]}"
    end
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_ca_service
    @ca_service = CaService.new(@network)
  end
end
