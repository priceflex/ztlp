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
  before_action :set_device, only: %i[show revoke assign_owner]
  before_action :require_write_access, only: %i[revoke assign_owner]

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
      # node_id in the same record: the NS refuses any later registration carrying it, so a
      # stolen key cannot come back under a different device name.
      Ztlp::Publisher.revoke!(@zone, name: @device.ns_name, also: [ @device.node_id_hex ].compact,
                                     target: @device, reason: reason, admin: current_admin)
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
    # Drop it from the owner's USER devices[] now (the revocation already stands, so save-and-warn).
    warning = nil
    if @device.user
      begin
        Ztlp::Publisher.publish_user!(@device.user, admin: current_admin)
      rescue Ztlp::NsClient::NsError => e
        warning = format("Revoked, but the owner's record was not republished (0x%02X %s). " \
                         "The 6-hourly republish will retry.", e.code, e.reason)
      end
    end
    redirect_to device_path(@device), alert: warning,
                notice: "#{@device.name} revoked permanently. It can never re-enroll under this name or key."
  end

  # ------------------------------------------------- slice 8b: assign_owner
  #
  # Spec Slice 8: the owner select publishes the DEVICE record plus BOTH
  # users' `devices[]` — three records in order: device, new owner user,
  # old owner user (the new owner's devices[] must gain the device name and
  # the old owner's must lose it; order matters only in that the DEVICE
  # write stands before the user records are re-published).
  # Fail-closed: if the DEVICE write is refused by the NS, NOTHING changes
  # in the DB (the old ownership stands in the NS too). After the device
  # write stands, the two user republishes are save-and-warn (the
  # ownership change already happened; the 6-hourly republish retries).
  def assign_owner
    new_user = params[:user_id].to_s.strip
    new_user = @device.user if new_user == @device.user&.id.to_s
    target = new_user.blank? ? nil : @zone.users.find_by(id: new_user)

    if target.nil? && !new_user.blank?
      audit!("device.assign_owner", target: @device, status: "skipped",
                                details: { name: @device.name, owner: new_user, reason: "unknown_user" })
      return redirect_to device_path(@device),
                         alert: "No such user (#{new_user})."
    end

    if target == @device.user
      audit!("device.assign_owner", target: @device, status: "skipped",
                                details: { name: @device.name, owner: new_user, reason: "no_change" })
      return redirect_to device_path(@device),
                         notice: target ? "#{target.display_name} is already the owner." : "The device has no owner."
    end

    old_user = @device.user
    begin
      # 1. the DEVICE record: owner field changes in the NS — this is the
      #    security-critical write; a refusal changes nothing below.
      Ztlp::Publisher.publish_device!(@device, admin: current_admin)
    rescue Ztlp::NsClient::NsError => e
      audit!("device.assign_owner", target: @device, status: "failed",
                                 details: { name: @device.name, owner: new_user,
                                           result: format("0x%02X %s", e.code, e.reason) })
      return redirect_to device_path(@device),
                         alert: format("%s was NOT reassigned: the name server refused (0x%02X %s). Nothing changed.",
                                        @device.name, e.code, e.reason)
    end

    @device.update!(user: target)
    audit!("device.assign_owner", target: @device, status: "ok",
                           details: { name: @device.name,
                                     from: old_user&.ns_name, to: target&.ns_name })

    # 2 + 3. republish the two USER records so their devices[] agree.
    # save-and-warn: the ownership already stands in the NS.
    warnings = []
    [ target, old_user ].compact.each do |u|
      begin
        Ztlp::Publisher.publish_user!(u, admin: current_admin)
      rescue Ztlp::NsClient::NsError => e
        warnings << format("%s's record was not republished (0x%02X %s). The 6-hourly republish will retry.",
                           u.display_name, e.code, e.reason)
      end
    end
    redirect_to device_path(@device), alert: warnings.presence,
                notice: old_user ? "Owner changed: #{old_user.display_name} → #{target ? target.display_name : 'Unassigned'}."
                                 : "Owner set: #{target.display_name}."
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
