# frozen_string_literal: true

# Slice 6a: Users directory — read side (spec Slice 6). Index with the mock's
# segmented status filter + server-side search, and show (also served as the
# drawer fragment under X-Drawer: 1, per §2.3).
#
# Slice 6b: mutations — new/create and edit/update. Username is immutable
# after create; a new user is `invited`. Per spec decision 2 (§14) a USER
# record is published to the NS on `active` only, so create (always invited)
# never publishes, and update publishes only for an active user. All
# mutations require write access and audit their own action.
class UsersController < ApplicationController
  before_action :set_user, only: %i[show edit update disable enable]
  before_action :require_write_access, only: %i[new create edit update disable enable]

  FILTERS = [ %w[all All], %w[active Active], %w[invited Invited],
              %w[disabled Disabled], %w[revoked Revoked] ].freeze

  # Form fields; username is handled separately (immutable after create).
  EDITABLE = %i[display_name first_name last_name email phone sms_opt_in role kind notes].freeze

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

  def new
    @user = @zone.users.build(status: "invited")
  end

  def create
    @user = @zone.users.build(user_params)
    @user.status = "invited" # spec: new users are always invited

    if @user.save
      warning = publish_if_active!(@user)
      audit!("user.create", target: @user, status: "ok", details: { username: @user.username })
      redirect_to user_path(@user), notice: "#{@user.display_name} created (invited).", alert: warning
    else
      render :new, status: :unprocessable_content
    end
  end

  def edit
  end

  def update
    # Username is immutable after create: never accept it from the form.
    if @user.update(user_params.except(:username))
      warning = publish_if_active!(@user)
      audit!("user.update", target: @user, status: "ok", details: { username: @user.username })
      redirect_to user_path(@user), notice: "#{@user.display_name} updated.", alert: warning
    else
      render :edit, status: :unprocessable_content
    end
  end

  # ------------------------------------------------- slice 6c: lifecycle
  #
  # Disable = REVOKE record for the user's ns name (spec §6.3) + the user's
  # devices marked `revoked` in the DB. Enable = republish the user record
  # (its devices[] no longer includes revoked devices, per Records.user_data)
  # + re-activate the user and their devices. The DB is the source of truth:
  # an NS failure never 500s after the save — the DB change stands, the
  # failure is a warning, the 6-hourly republish retries.

  def disable
    if @user.status == "revoked"
      audit!("user.disable", target: @user, status: "skipped",
                          details: { username: @user.username, reason: "already_revoked" })
      return redirect_to user_path(@user), alert: "#{@user.display_name} is already revoked."
    end

    # One REVOKE record for the user ns name (spec §6.3: a REVOKE "purges
    # device and group indexes"). The devices are then marked `revoked` in
    # the DB, which drops them from every later USER publish — that is how
    # they go revoked in the NS too.
    warning = begin
      Ztlp::Publisher.revoke!(@zone, name: @user.ns_name, target: @user,
                              reason: "user disabled", admin: current_admin)
      nil
    rescue Ztlp::NsClient::NsError => e
      user_warning(e)
    end

    # The DB change stands regardless of the NS outcome.
    revoked_count = @user.devices.where(status: "enrolled").count
    @user.update!(status: "revoked")
    @user.devices.where(status: "enrolled").update_all(status: "revoked",
                                                       revoked_at: Time.current)
    audit!("user.disable", target: @user, status: "ok",
                        details: { username: @user.username,
                                   ns_revoked: warning.nil?,
                                   devices_revoked: revoked_count })
    notice = "#{@user.display_name} disabled."
    notice += " #{revoked_count} device(s) revoked." if revoked_count.positive?
    redirect_to user_path(@user), notice: notice, alert: warning
  end

  def enable
    if @user.active?
      audit!("user.enable", target: @user, status: "skipped",
                          details: { username: @user.username, reason: "already_active" })
      return redirect_to user_path(@user), alert: "#{@user.display_name} is already active."
    end

    warnings = []
    # Re-activate the device rows FIRST so the USER record we publish right
    # after carries them in devices[] (Records.user_data reads live rows).
    # The NS-side revoke of a user covers their device index entries; enable
    # re-publishes the USER record (spec Slice 6: "Enable re-publishes").
    @user.devices.where(status: "revoked").update_all(status: "enrolled", revoked_at: nil)
    @user.update!(status: "active")

    republished = begin
      Ztlp::Publisher.publish_user!(@user, admin: current_admin)
      true
    rescue Ztlp::NsClient::NsError => e
      warnings << user_warning(e)
      false
    end

    audit!("user.enable", target: @user, status: "ok",
                       details: { username: @user.username,
                                  ns_republished: republished })
    redirect_to user_path(@user), notice: "#{@user.display_name} enabled.",
                                 alert: warnings.first
  end

  private

  # Warnings for the flash (never a 500 after the save).
  def user_warning(e)
    format("Saved, but not published to the name server (0x%02X %s). " \
           "The 6-hourly republish will retry.", e.code, e.reason)
  end

  def set_user
    @user = @zone.users.find(params[:id])
  end

  def drawer_request? = request.headers["X-Drawer"] == "1"

  # Spec decision 2 (§14): publish a USER record on `active` only. A fresh
  # user is always `invited` (create never publishes); an edit of an active
  # user re-publishes so the NS sees the change before the 24h TTL.
  # The DB save is the source of truth: an NS failure (no authority imported yet,
  # NS down, rate limit) is audited by Publisher, surfaced as a warning, and
  # retried by the 6-hourly RepublishNsJob — never a 500 after the save.
  # Returns nil on success / not active, or the warning text.
  def publish_if_active!(user)
    return nil unless user.active?

    Ztlp::Publisher.publish_user!(user, admin: current_admin)
    nil
  rescue Ztlp::NsClient::NsError => e
    format("Saved, but not published to the name server (0x%02X %s). " \
           "The 6-hourly republish will retry.", e.code, e.reason)
  end

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

  # Strong params for the user form. `username` is accepted here so the
  # create path can build it, but update explicitly drops it (immutable).
  # `status` is NOT in the allowlist: it is managed by the lifecycle actions
  # (invited on create, disabled/enable in 6c), never by a free-form field.
  def user_params
    params.require(:user).permit(
      :username, :display_name, :first_name, :last_name,
      :email, :phone, :sms_opt_in, :role, :kind, :notes
    )
  end
end
