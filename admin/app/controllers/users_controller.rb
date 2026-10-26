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
  include EnrollmentMinting
  before_action :set_user, only: %i[show edit update revoke]
  before_action :require_write_access, only: %i[new create edit update]
  before_action :require_operator, only: %i[revoke]

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
      return enroll_new_user(warning) if params.dig(:enroll, :now) == "1"

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

  # Operator decision 2026-10-22: PERMANENT "Revoke user" (no Enable). One REVOKE record lists
  # the user + every enrolled device (the gateway does not cascade owner→device). In the NS a
  # revocation can never be lifted. Security action: if the NS write fails, NOTHING changes.
  def revoke
    if @user.status == "revoked"
      audit!("user.revoke", target: @user, status: "skipped",
                            details: { username: @user.username, reason: "already_revoked" })
      return redirect_to user_path(@user), alert: "#{@user.display_name} is already revoked."
    end

    devices = @user.devices.where(status: "enrolled").to_a
    begin
      # node_ids too: the NS refuses any later registration carrying a revoked node_id.
      Ztlp::Publisher.revoke!(@zone, name: @user.ns_name, also: devices.flat_map { |d| [ d.ns_name, d.node_id_hex ] }.compact,
                                     target: @user,
                                     reason: "user revoked", admin: current_admin)
    rescue Ztlp::NsClient::NsError => e
      audit!("user.revoke", target: @user, status: "failed",
                            details: { username: @user.username, result: format("0x%02X %s", e.code, e.reason) })
      return redirect_to user_path(@user),
                         alert: format("%s was NOT revoked: the name server refused (0x%02X %s). Nothing changed.",
                                       @user.display_name, e.code, e.reason)
    end

    User.transaction do
      @user.update!(status: "revoked")
      @user.devices.where(id: devices.map(&:id)).update_all(status: "revoked", revoked_at: Time.current)
    end
    audit!("user.revoke", target: @user, status: "ok",
                          details: { username: @user.username, devices_revoked: devices.size })
    redirect_to user_path(@user), notice: "#{@user.display_name} revoked permanently, with #{devices.size} device(s)."
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
  # (invited on create, revoked by the permanent revoke action), never by a free-form field.
  # "Enroll a device now" on the new-user form: mint the user's first token and land on the
  # show-once result page. The user is already saved; a mint failure keeps it and says why.
  def enroll_new_user(warning)
    e = params[:enroll]
    enrollment = mint_enrollment!(kind: "user_device", user: @user, device_name: e[:device_name],
                                  expiry_hours: e[:expiry_hours].presence || 24, embed_relay_secret: "1")
    redirect_to result_enrollment_path(enrollment),
                notice: "#{@user.display_name} created (invited). Enrollment token below.", alert: warning
  rescue Ztlp::TokenMinter::EnrollmentSecretMissing
    redirect_to user_path(@user), notice: "#{@user.display_name} created (invited).",
                                  alert: "No enrollment token: #{ENROLLMENT_SECRET_MISSING}"
  rescue ActiveRecord::RecordInvalid => err
    redirect_to user_path(@user), notice: "#{@user.display_name} created (invited).",
                                  alert: "No enrollment token: #{err.record.errors.full_messages.to_sentence}"
  end

  # role and kind decide what a user can reach (role:admin rules, service users): operators only.
  # helpdesk-created users are always role user / kind person (the column defaults).
  def user_params
    fields = %i[username display_name first_name last_name email phone sms_opt_in notes]
    fields += %i[role kind] if current_admin.operator?
    params.require(:user).permit(*fields)
  end
end
