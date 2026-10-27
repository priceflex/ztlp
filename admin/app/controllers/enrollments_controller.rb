# frozen_string_literal: true

# Slice 10b sub-slice 1: the Enrollments page — read side (spec Slice 10).
#
# GET /enrollments       list of this zone's enrollment tokens: code, kind,
#                        user, device name, expiry, status, created by/when.
#                        Filters: all/pending/redeemed/expired/revoked.
#                        The list is an honest empty state until the zone
#                        enrollment secret is configured — the "New token"
#                        button and the explanatory warning agree about
#                        whether minting is possible (the token is minted
#                        on POST /enrollments, sub-slice 2).
#
# GET /enrollments/new   the mint form: user pick (existing / device only),
#                        optional device name, expiry (1h default, max 24h),
#                        embed-relay-secret (default on).
#
# POST /enrollments/:id/revoke  revoke a pending token (sub-slice 1: the
#                        read side + the one low-risk mutation).
#
# Every mutation requires write access (the read_only role is blocked from
# the new/revoke paths, mirroring the Users controller).
class EnrollmentsController < ApplicationController
  include EnrollmentMinting
  before_action :require_write_access, only: %i[new create revoke check]

  FILTERS = [ %w[all All], %w[pending Pending], %w[redeemed Redeemed],
              %w[expired Expired], %w[revoked Revoked] ].freeze

  # ------------------------------------------------------------------ index

  def index
    @status = FILTERS.map(&:first).include?(params[:status]) ? params[:status] : "all"

    scope = @zone.enrollments.order(created_at: :desc).includes(:user, :created_by_admin)
    scope = scope.where(status: @status) unless @status == "all"
    @enrollments = scope
  end

  # -------------------------------------------------------------------- new

  def new
    @enrollment = @zone.enrollments.build(kind: "user_device", embed_relay_secret: true)
    @users = @zone.users.order(:username)
    # "Enroll a device" on a user page pre-selects that user (only a user of THIS zone).
    @enrollment.user = @users.find_by(id: params[:user_id]) if params[:user_id].present?
  end

  # ------------------------------------------------------------------ create

  # Mint the v1 token, store the URI encrypted at rest (token_uri_ct), and
  # redirect to the show-once result page. The token is exposed EXACTLY ONCE
  # (the result page consumes a one-time reveal set here) and is NEVER written
  # to the audit log.
  #
  # Expiry: 1h default, 24h hard max (spec F8 / Slice 10). `expiry_hours` is a
  # user-supplied number; clamp it rather than trusting it, and a blank value
  # falls back to the 1h default.
  def create
    attrs = enrollment_params
    return render_unprocessable("Choose a token kind (and a user for a user+device token).") if attrs.nil?

    kind = attrs[:kind]
    user = nil
    if kind == "user_device"
      user = @zone.users.find_by(id: attrs[:user_id])
      return render_unprocessable("A user+device token needs a linked user.") if user.nil?
    end

    begin
      enrollment = mint_enrollment!(kind: kind, user: user, device_name: attrs[:device_name],
                                    expiry_hours: attrs[:expiry_hours],
                                    embed_relay_secret: attrs[:embed_relay_secret])
    rescue Ztlp::TokenMinter::EnrollmentSecretMissing
      return redirect_to enrollments_path, alert: ENROLLMENT_SECRET_MISSING
    rescue EnrollmentMinting::InvalidDeviceName, Ztlp::TokenMinter::InvalidField => e
      return render_unprocessable(e.message)
    end
    redirect_to result_enrollment_path(enrollment)
  end

  # ------------------------------------------------------------------- check

  # "Check now": look for the token's device on the name server instead of waiting for the 5-minute
  # EnrollmentPickupJob.
  CHECK_MESSAGES = {
    redeemed: [ :notice, "Enrolled: the device is on the name server and is now listed." ],
    pending: [ :notice, "Not enrolled yet: the name server has no key for this device name." ],
    stale_key: [ :alert, "The name server has an older key under this device name (an earlier enrollment), " \
                         "not one from this token. Use Add an existing device on the user's page to list it." ],
    not_pending: [ :notice, "This token is no longer pending." ],
    no_device_name: [ :alert, "This token has no device name, so the panel cannot look the device up." ],
    ns_error: [ :alert, "The name server did not answer. Try again in a minute." ],
    no_ns_key: [ :alert, "Set this zone's name server key first (Name server page): the panel only trusts answers it can verify." ],
    untrusted: [ :alert, "The name server's answer did not verify against this zone's name server key, so nothing was listed." ],
    revoked_user: [ :alert, "This token's user is revoked, so the device is not listed." ]
  }.freeze

  def check
    enrollment = @zone.enrollments.find(params[:id])
    kind, message = CHECK_MESSAGES.fetch(Ztlp::DevicePickup.check(enrollment), [ :alert, "Unexpected result." ])
    redirect_to enrollment_path(enrollment), kind => message
  rescue ActiveRecord::ActiveRecordError => e
    Rails.logger.error("enrollment check #{params[:id]}: #{e.class}: #{e.message}")
    redirect_to enrollment_path(params[:id]),
                alert: "The device is on the name server but could not be listed (#{e.class.name.demodulize}). " \
                       "Another device may already have this key; check the Devices page."
  end

  # ------------------------------------------------------------------ result

  # The show-once page. It renders the token URI + QR + setup command only for
  # the request chain that just minted it: `create` stashes a one-time reveal in
  # the session, and the first render of this page consumes it. Any other GET
  # (a second request, a bookmarked URL, the plain show page) gets 404 / no
  # token. The URI is stored encrypted and is otherwise never rendered.
  def result
    @enrollment = @zone.enrollments.find(params[:id])
    reveal = session[:enrollment_reveal]
    # The session serializer stringifies hash keys on round-trip, so the stored
    # reveal may come back with string keys; read both shapes.
    reveal_id = reveal.is_a?(Hash) ? (reveal[:enrollment_id] || reveal["enrollment_id"]) : nil
    unless reveal_id == @enrollment.id && @enrollment.token_uri_ct.present?
      return head :not_found
    end

    session[:enrollment_reveal] = nil # consume: exactly one render carries the token
    @token_uri = @enrollment.token_uri_ct
    @qr_svg = Ztlp::TokenQr.svg(@token_uri)
    # The relay secret and the NS key ride INSIDE the token (flags 0x08 / 0x10); read back what this
    # token actually carries rather than what the zone holds now.
    minted = Ztlp::TokenMinter.parse(Ztlp::TokenMinter.from_uri(@token_uri))
    @relay_in_token = minted[:relay_secret].present?
    @relay_missing = @enrollment.embed_relay_secret && !@relay_in_token
    @ns_key_in_token = minted[:ns_key_hex].present?
    # Shown once, stored never: redeem is keyed by token_id, nothing needs the URI after this render.
    @enrollment.update_column(:token_uri_ct, nil)
  end

  # -------------------------------------------------------------------- show

  # The token detail page. The token URI itself is minted + shown once in
  # sub-slice 2; today the page renders the token's facts (code, kind, user,
  # device, expiry, status, created by/when) + a revoke affordance for a
  # pending token.
  def show
    @enrollment = @zone.enrollments.find(params[:id])
  end

  # ------------------------------------------------------------------ revoke

  # Only pending tokens can be revoked: a redeemed token already enrolled a
  # device (nothing to invalidate), and an expired/revoked one is already dead.
  def revoke
    @enrollment = @zone.enrollments.find(params[:id])
    unless @enrollment.pending?
      return redirect_to enrollment_path(@enrollment),
                         alert: "Only pending tokens can be revoked (#{@enrollment.status})."
    end

    @enrollment.update!(status: "revoked", revoked_at: Time.current)
    audit!("enrollment.revoke", target: @enrollment, status: "ok",
                               details: { code: @enrollment.code })
    redirect_to enrollments_path,
                notice: "Token #{@enrollment.code} revoked in the panel. The name server still accepts it until it " \
                        "expires or is used; rotate the zone enrollment secret to kill every outstanding token."
  end

  private

  # Permit + guard the mint form. A missing `enrollment` hash (malformed or
  # non-form POST) is a 400, not a 500 — the same rule as every publishing
  # controller in this app (rails-development-pitfalls §27h). `params[:enrollment]`
  # is already a Parameters object (Rails auto-wraps), so permit on it directly.
  def enrollment_params
    p = params[:enrollment]
    return nil unless p.is_a?(ActionController::Parameters) && p.present?

    p.permit(:kind, :user_id, :device_name, :expiry_hours, :embed_relay_secret)
  rescue NoMethodError
    nil
  end

  def render_unprocessable(message)
    @enrollment = Enrollment.new
    @users = @zone.users.order(:username)
    flash.now[:alert] = message
    render :new, status: :unprocessable_entity
  end
end
