# frozen_string_literal: true

# Slice 6a: Users directory — read side (spec Slice 6). Index with the mock's
# segmented status filter + server-side search, and show (also served as the
# drawer fragment under X-Drawer: 1, per §2.3). create/edit/disable/enable are
# sub-slice 6b. Nothing here publishes to the NS — read-only pages.
class UsersController < ApplicationController
  before_action :set_user, only: [ :show ]

  FILTERS = [ %w[all All], %w[active Active], %w[invited Invited],
              %w[disabled Disabled], %w[revoked Revoked] ].freeze

  def index
    @status = FILTERS.map(&:first).include?(params[:status]) ? params[:status] : "all"
    @q = params[:q].to_s.strip

    scope = @zone.users.includes(:groups, :devices).order(:username)
    scope = scope.where(status: @status) unless @status == "all"
    scope = apply_search(scope, @q) if @q.present?
    @users = scope
  end

  def show
    render layout: false if drawer_request?
  end

  private

  def set_user
    @user = @zone.users.find(params[:id])
  end

  def drawer_request? = request.headers["X-Drawer"] == "1"

  # Name/username are plain columns; email is encrypted at rest. Match name
  # fields in SQL; a full-address query additionally resolves deterministic-
  # encrypted email via an exact ciphertext lookup (never a plaintext scan).
  def apply_search(scope, q)
    like = "%#{ActiveRecord::Base.sanitize_sql_like(q.downcase)}%"
    cond = scope.where(
      "LOWER(username) LIKE :like OR LOWER(display_name) LIKE :like" \
      " OR LOWER(first_name) LIKE :like OR LOWER(last_name) LIKE :like",
      like: like
    )
    # email is `encrypts deterministic: true`, so AR turns where(email:) into an exact
    # ciphertext match in SQL (no plaintext, no per-row decrypt). Try as typed + lowercased.
    email_owner_ids = @zone.users.where(email: [ q, q.downcase ].uniq).pluck(:id)
    cond = cond.or(@zone.users.where(id: email_owner_ids)) if email_owner_ids.any?
    cond
  end
end
