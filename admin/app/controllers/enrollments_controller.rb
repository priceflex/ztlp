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
  before_action :require_write_access, only: %i[new revoke]

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
end
