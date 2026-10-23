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
  before_action :require_write_access, only: %i[new create revoke]

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

    hours = attrs[:expiry_hours].to_s.strip
    hours = 1 if hours.empty?
    hours = hours.to_i
    hours = 1 if hours < 1
    hours = 24 if hours > Ztlp::TokenMinter::MAX_EXPIRY_SECONDS / 3600

    kind = attrs[:kind]
    user = nil
    if kind == "user_device"
      user = @zone.users.find_by(id: attrs[:user_id])
      return render_unprocessable("A user+device token needs a linked user.") if user.nil?
    end

    # embed_relay_secret is a NOT NULL boolean column (default false). The form
    # posts "1" when checked and nothing when unchecked — cast to a real boolean
    # (nil would 500 on the NOT NULL column).
    embed_relay = %w[1 true on yes].include?(attrs[:embed_relay_secret].to_s.strip.downcase)

    enrollment = @zone.enrollments.build(
      kind: kind,
      user: user,
      device_name: attrs[:device_name].to_s.strip.presence,
      embed_relay_secret: embed_relay,
      max_uses: 1,
      status: "pending",
      expires_at: hours.hours.from_now,
      created_by_admin: current_admin
    )
    enrollment.token_id = Enrollment.generate_token_id

    begin
      uri = Ztlp::TokenMinter.to_uri(
        Ztlp::TokenMinter.mint(@zone, expires_at: enrollment.expires_at.to_i)
      )
    rescue Ztlp::TokenMinter::EnrollmentSecretMissing
      audit!("enrollment.mint", status: "error",
                               details: { error: "no_zone_enrollment_secret" })
      return redirect_to enrollments_path,
                         alert: "The zone enrollment secret is not set. Run `rails zone:set_secret enrollment` (stdin) first."
    end
    enrollment.token_uri_ct = uri

    enrollment.save!
    # The audit row records the HUMAN code + user — never the token URI.
    audit!("enrollment.mint", target: enrollment, status: "ok",
                               details: { code: enrollment.code, kind: enrollment.kind,
                                          user: (user&.username), embed_relay_secret: enrollment.embed_relay_secret })
    # One-time reveal: the result page will render the URI once, then clear this.
    session[:enrollment_reveal] = { enrollment_id: enrollment.id, nonce: SecureRandom.hex(16) }
    redirect_to result_enrollment_path(enrollment)
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
