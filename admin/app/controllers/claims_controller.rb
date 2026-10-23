# frozen_string_literal: true

class ClaimsController < ApplicationController
  skip_before_action :redirect_to_claim_if_unclaimed
  skip_before_action :require_sign_in
  before_action :ensure_unclaimed

  def show
    Claim.ensure_code!
  end

  def create
    # force comes from server state (a pending admin:reset_claim code), never from the request.
    break_glass = Claim.forced_pending?
    admin = Claim.perform!(claim_params, ip: request.remote_ip, force: break_glass)
    sign_in!(admin)
    redirect_to root_path, notice: if break_glass
                                     "Welcome, #{admin.display_name}. Break-glass claim complete: you are an additional " \
                                       "super administrator. Review the other administrators now."
                                   else
                                     "Welcome, #{admin.display_name}. You are the first administrator."
                                   end
  rescue Claim::Error, ActiveRecord::RecordInvalid => e
    AuditLog.record!("system.claim_failed", ip: request.remote_ip, status: "error", details: { error: e.message })
    flash.now[:alert] = e.message
    render :show, status: :unprocessable_entity
  end

  private

  def ensure_unclaimed
    redirect_to root_path, notice: "This panel has already been claimed." unless Claim.open?
  end

  def claim_params
    params.require(:claim).permit(:claim_code, :username, :display_name, :email, :pubkey_hex, :timestamp, :signature)
  end
end
