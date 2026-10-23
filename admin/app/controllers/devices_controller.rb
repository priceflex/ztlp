# frozen_string_literal: true

# Slice 8a: Devices directory — read side (spec Slice 8).
#
# Index: segmented status filter (all/enrolled/pending/revoked), columns
# name (mono ns_name) / platform / owner (link to the user page) /
# key source + assurance badge / agent version / last seen / status.
# Row -> drawer (show).
#
# Show: identity (node id, noise pubkey — fingerprints shown, full values
# copyable via data-act=copy), owner link, assurance, and the Revoke form
# (reason required). No create form: devices come from enrollment redeem
# (Slice 10) or the reconcile import (Slice 12); the page says so.
#
# This slice is the READ side only. Revoke and Assign owner land in the
# sub-slices 8b/8c per the slice queue; until then the Revoke form's
# endpoint exists (route + action) and is tested, and Assign owner is a
# plain link to the user's page (no form, no fake button).
class DevicesController < ApplicationController
  before_action :set_device, only: %i[show revoke]
  before_action :require_write_access, only: %i[revoke]

  FILTERS = [ %w[all All], %w[enrolled Enrolled], %w[pending Pending],
              %w[revoked Revoked] ].freeze

  def index
    @status = FILTERS.map(&:first).include?(params[:status]) ? params[:status] : "all"

    scope = @zone.devices.includes(:user).order(:name)
    scope = scope.where(status: @status) unless @status == "all"
    @devices = scope
  end

  def show
    render layout: false if drawer_request?
  end

  # -------------------------------------------------- slice 8b: revoke
  #
  # Operator decision 2026-10-22 (Slice 6c, extended to devices): a
  # revocation is PERMANENT in the NS — a revoked name can never be
  # re-registered. One REVOKE record names this device. Security action:
  # if the NS write fails, NOTHING changes in the DB (no status stamp, no
  # revoked_at), the alert says so, and the audit row is `failed`.
  def revoke
    if @device.status == "revoked"
      audit!("device.revoke", target: @device, status: "skipped",
                              details: { name: @device.name, reason: "already_revoked" })
      return redirect_to device_path(@device),
                         alert: "#{@device.name} is already revoked."
    end

    reason = params[:reason].to_s.strip
    if reason.blank?
      flash.now[:alert] = "A reason is required to revoke a device."
      return render :show, status: :unprocessable_content
    end

    begin
      Ztlp::Publisher.revoke!(@zone, name: @device.ns_name, target: @device,
                                     reason: reason, admin: current_admin)
    rescue Ztlp::NsClient::NsError => e
      audit!("device.revoke", target: @device, status: "failed",
                               details: { name: @device.name, result: format("0x%02X %s", e.code, e.reason) })
      return redirect_to device_path(@device),
                         alert: format("%s was NOT revoked: the name server refused (0x%02X %s). Nothing changed.",
                                        @device.name, e.code, e.reason)
    end

    @device.update!(status: "revoked", revoked_at: Time.current)
    audit!("device.revoke", target: @device, status: "ok",
                           details: { name: @device.name, reason: reason })
    redirect_to device_path(@device),
                notice: "#{@device.name} revoked permanently. It can never re-enroll under this name."
  end

  private

  def set_device
    # Scoped lookup: a device id from another zone 404s (same rule as users/groups).
    @device = @zone.devices.find(params[:id])
  end

  def drawer_request? = request.headers["X-Drawer"] == "1"

  # The Revoke form posts here with a `reason` field (read side: the form
  # exists on the show page; the action above is the 8b contract).
  def revoke_form_action
    revoke_device_path(@device)
  end
end
