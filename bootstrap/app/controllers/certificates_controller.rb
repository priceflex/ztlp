# frozen_string_literal: true

class CertificatesController < ApplicationController
  before_action :set_network
  before_action :set_certificate, only: [:show, :revoke]
  before_action :set_ca_service

  # GET /networks/:network_id/certificates
  def index
    @certificates = @network.certificates.order(created_at: :desc)

    # Mark any expired certs
    Certificate.mark_expired!

    # Filter by status
    if params[:status].present?
      @certificates = @certificates.where(status: params[:status])
    end
  end

  # GET /networks/:network_id/certificates/:id
  def show; end

  # GET /networks/:network_id/certificates/new
  def new
    @certificate = @network.certificates.build
  end

  # POST /networks/:network_id/certificates
  def create
    result = @ca_service.issue_cert(
      hostname: certificate_params[:hostname],
      days: (certificate_params[:days] || 90).to_i,
      assurance_level: certificate_params[:assurance_level] || "software"
    )

    if result[:success]
      redirect_to network_certificate_path(@network, result[:certificate]),
                  notice: "Certificate issued for #{certificate_params[:hostname]}"
    else
      @certificate = @network.certificates.build(certificate_params)
      flash.now[:alert] = "Failed to issue certificate: #{result[:error]}"
      render :new, status: :unprocessable_entity
    end
  end

  # POST /networks/:network_id/certificates/:id/revoke
  def revoke
    result = @ca_service.revoke_cert(@certificate, reason: params[:reason])

    if result[:success]
      redirect_to network_certificates_path(@network), notice: "Certificate #{@certificate.serial} revoked."
    else
      redirect_to network_certificate_path(@network, @certificate),
                  alert: "Revocation failed: #{result[:error]}"
    end
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_certificate
    @certificate = @network.certificates.find(params[:id])
  end

  def set_ca_service
    @ca_service = CaService.new(@network)
  end

  def certificate_params
    params.require(:certificate).permit(:hostname, :days, :assurance_level, :notes)
  end
end
