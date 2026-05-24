class TokensController < ApplicationController
  before_action :set_network
  before_action :set_token, only: [:show, :revoke]

  # RFC1035 DNS label — same shape `Api::V1::EnrollmentTokensController`
  # uses. Lowercased before match (the regex is case-insensitive but
  # we want to canonicalise storage too).
  COMPUTER_NAME_REGEX = /\A[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\z/i.freeze
  MAX_COMPUTER_NAME_LENGTH = 253

  def index
    @tokens = @network.enrollment_tokens.order(created_at: :desc)
    # Refresh stale statuses
    @tokens.select(&:usable?).each(&:refresh_status!)
  end

  def show
  end

  def new
    @token = @network.enrollment_tokens.new
    # Eager-load the existing-user dropdown for the form.
    @ztlp_users = @network.ztlp_users.where.not(status: "revoked").order(:name)
  end

  # POST /networks/:network_id/tokens
  #
  # Phase A — the form now binds tokens to a principal. Param shape:
  #
  #   target_kind:      "device" | "user" | nil (legacy / unbound)
  #   computer_name:    required when target_kind="device"
  #   ztlp_user_id:     when target_kind="user" — existing user
  #   new_username:     when target_kind="user" — inline-create user
  #   new_email:        optional email for inline-created user
  #
  # The legacy fields keep working:
  #   expires_in:       human-readable ("24h", "7d", …)
  #   max_uses:         integer, default 1
  #   notes:            free-form
  #   roles:            comma-joined into allowed_roles (BS-RBAC scaffolding)
  #
  # Validation strategy: dashboard-level checks (`computer_name`
  # shape, user-network ownership) bail out BEFORE we hit the model
  # so error messages can be user-facing. Anything that slips through
  # raises `ActiveRecord::RecordInvalid` from the model and bubbles
  # back as a flash alert.
  def create
    target_kind = params[:target_kind].to_s.presence

    case target_kind
    when "device"
      create_device_token
    when "user"
      create_user_token
    when nil
      create_legacy_token
    else
      redirect_to network_tokens_path(@network),
                  alert: "Unknown target kind: #{target_kind.inspect}. Use 'device' or 'user'."
    end
  end

  # POST /networks/:network_id/tokens/:id/revoke
  def revoke
    @token.revoke!
    AuditLog.record(action: "token_revoke", target: @token, details: { token_id: @token.token_id })
    redirect_to network_tokens_path(@network), notice: "Token revoked."
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_token
    @token = @network.enrollment_tokens.find(params[:id])
  end

  # ── Phase A: per-target create paths ─────────────────────────────

  # Device-bound mint. Reuses the same DNS-label shape as the BS-PR-3
  # API so a dashboard-minted token and a Z2LS-API-minted token are
  # interchangeable as far as `target_label` semantics go.
  def create_device_token
    computer_name = params[:computer_name].to_s.strip

    if computer_name.empty?
      return redirect_to network_tokens_path(@network),
                         alert: "Computer name is required when binding to a device."
    end

    if computer_name.length > MAX_COMPUTER_NAME_LENGTH
      return redirect_to network_tokens_path(@network),
                         alert: "Computer name exceeds the RFC1035 length limit (#{MAX_COMPUTER_NAME_LENGTH})."
    end

    unless computer_name.match?(COMPUTER_NAME_REGEX)
      return redirect_to network_tokens_path(@network),
                         alert: "Computer name must be a valid DNS label (lowercase letters/digits/hyphens/dots)."
    end

    mint(target_kind: "device", target_label: computer_name, ztlp_user: nil)
  end

  # User-bound mint. Two sub-paths:
  #
  #   1. Existing user: caller passes `ztlp_user_id`. We re-look-up
  #      through the @network scope so a hostile caller can't bind a
  #      token to a user in another tenant (cross-tenant safety
  #      invariant — the same one
  #      `Api::V1::EnrollmentTokensController` enforces by scoping to
  #      `current_api_client.zone`).
  #
  #   2. Inline create: caller passes `new_username` (and optional
  #      `new_email`). We `find_or_create_by!(name:, network:)` so a
  #      sticky-clicker who hits Submit twice with the same name
  #      doesn't get a 500 from the network-scoped name uniqueness
  #      validator.
  def create_user_token
    user =
      if params[:ztlp_user_id].present?
        @network.ztlp_users.find_by(id: params[:ztlp_user_id])
      elsif params[:new_username].present?
        find_or_create_inline_user
      else
        nil
      end

    unless user
      return redirect_to network_tokens_path(@network),
                         alert: "Pick an existing user or fill in a new username when binding to a user."
    end

    mint(target_kind: "user", target_label: user.name, ztlp_user: user)
  end

  # Legacy / unbound mint. Pre-Phase-A behaviour: an unbound token,
  # no target_kind, no target_label. Kept on purpose so external
  # integrations driving the dashboard form survive the rollout.
  # Future work may flip this to "device, hostname=anonymous" or
  # reject outright with a deprecation warning.
  def create_legacy_token
    mint(target_kind: nil, target_label: nil, ztlp_user: nil)
  end

  # Common tail: assemble TokenGenerator kwargs + handle the
  # generator's own raisey paths (NS-machine-missing, validation
  # failure). On success redirect to the show page so the operator
  # immediately sees the URI + QR code.
  def mint(target_kind:, target_label:, ztlp_user:)
    generator = TokenGenerator.new(@network)

    @token = generator.generate!(
      expires_in: parse_duration(params[:expires_in] || "24h"),
      max_uses: (params[:max_uses] || 1).to_i,
      roles: params[:roles],
      notes: params[:notes],
      target_kind: target_kind,
      target_label: target_label,
      ztlp_user: ztlp_user
    )

    redirect_to network_token_path(@network, @token), notice: "Enrollment token generated!"
  rescue TokenGenerator::TokenError => e
    redirect_to network_tokens_path(@network), alert: e.message
  rescue ActiveRecord::RecordInvalid => e
    redirect_to network_tokens_path(@network), alert: "Could not generate token: #{e.message}"
  end

  # Inline-create or look-up a ZtlpUser scoped to the current
  # network. Idempotent on `name` (the network-scoped uniqueness
  # constraint matches `index_ztlp_users_on_network_id_and_name`).
  def find_or_create_inline_user
    name = params[:new_username].to_s.strip
    return nil if name.empty?

    user = @network.ztlp_users.find_or_initialize_by(name: name)
    user.email ||= params[:new_email].to_s.strip.presence
    user.role  ||= "user"
    user.status ||= "active"
    user.save!
    user
  rescue ActiveRecord::RecordInvalid
    nil
  end

  def parse_duration(str)
    case str
    when /\A(\d+)h\z/ then $1.to_i.hours
    when /\A(\d+)d\z/ then $1.to_i.days
    when /\A(\d+)m\z/ then $1.to_i.minutes
    else 24.hours
    end
  end
end
