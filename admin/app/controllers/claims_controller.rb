# frozen_string_literal: true

class ClaimsController < ApplicationController
  skip_before_action :redirect_to_claim_if_unclaimed
  skip_before_action :require_sign_in
  before_action :ensure_unclaimed

  def show
    Claim.ensure_code!
  end

  def create
    admin = Claim.perform!(claim_params, ip: request.remote_ip)
    sign_in!(admin)
    redirect_to root_path, notice: "Welcome, #{admin.display_name}. You are the first administrator."
  rescue Claim::Error, ActiveRecord::RecordInvalid => e
    AuditLog.record!("system.claim_failed", ip: request.remote_ip, status: "error", details: { error: e.message })
    flash.now[:alert] = e.message
    render :show, status: :unprocessable_entity
  end

  private

  def ensure_unclaimed
    redirect_to root_path, notice: "This panel has already been claimed." unless Claim.needed?
  end

  def claim_params
    params.require(:claim).permit(:claim_code, :username, :display_name, :email, :pubkey_hex, :timestamp, :signature)
  end
end
