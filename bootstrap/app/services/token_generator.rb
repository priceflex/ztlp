# frozen_string_literal: true

require "rqrcode"

# Generates ZTLP enrollment tokens and QR codes.
# Wraps the ztlp CLI binary for token generation when available,
# falls back to pure Ruby implementation.
class TokenGenerator
  class TokenError < StandardError; end

  ZTLP_CLI = ENV.fetch("ZTLP_CLI_PATH", "ztlp")

  def initialize(network)
    @network = network
  end

  # Generate a new enrollment token.
  #
  # Kwargs:
  #
  #   expires_in:    Lifetime (ActiveSupport::Duration). Defaults to 24h.
  #   max_uses:      Single-use (1) by default; can be bumped for kiosk
  #                  flows.
  #   roles:         Comma-joined into `allowed_roles` for legacy callers
  #                  (Steve's RBAC scaffolding pre-dates this method's
  #                  birth).
  #   notes:         Free-form. Used as the human-readable label in the
  #                  dashboard's token index.
  #   ztlp_user_id:  Sets the FK on the token directly (legacy / API
  #                  callers).
  #
  # Phase A additions (2026-05-25):
  #
  #   target_kind:   "device" | "user" — binds the token to a principal.
  #                  Both columns are NULLABLE; legacy callers that
  #                  don't pass either keep working unchanged.
  #   target_label:  Either the computer_name (when target_kind="device")
  #                  or the username (when target_kind="user"). The
  #                  username is denormalized from `ztlp_user.name`
  #                  so the label survives a ZtlpUser rename.
  #   ztlp_user:     Convenience kwarg — when present, ALSO sets the FK
  #                  (`ztlp_user_id`) from the AR object. Mutually
  #                  exclusive with `ztlp_user_id:` (caller picks one).
  #
  # Model-level validation enforces the paired-presence invariant
  # (you can't have a target_label without a target_kind), and
  # `ActiveRecord::RecordInvalid` propagates up if the caller hands us
  # an inconsistent pair.
  def generate!(expires_in: 24.hours, max_uses: 1, roles: nil, notes: nil,
                ztlp_user_id: nil, ztlp_user: nil,
                target_kind: nil, target_label: nil)
    ns_machine = @network.ns_machines.first
    relay_machine = @network.relay_machines.first

    raise TokenError, "Network must have at least one NS machine" unless ns_machine

    token_id = SecureRandom.hex(8)
    expires_at = Time.current + expires_in

    # Build the enrollment URI
    ns_addr = "#{ns_machine.ip_address}:#{SshProvisioner::ZTLP_PORTS['ns'][:udp]}"
    relay_addr = relay_machine ? "#{relay_machine.ip_address}:#{SshProvisioner::ZTLP_PORTS['relay'][:udp]}" : nil

    # Build callback URL for CLI to confirm enrollment usage
    bootstrap_url = ENV.fetch("BOOTSTRAP_URL", nil)
    callback_url = bootstrap_url ? "#{bootstrap_url}/api/enrollment/confirm" : nil

    params = {
      zone: @network.zone,
      ns: ns_addr,
      relay: relay_addr,
      token: token_id,
      expires: expires_at.to_i,
      callback: callback_url
    }.compact

    token_uri = "ztlp://enroll/?" + params.map { |k, v| "#{k}=#{v}" }.join("&")

    # Generate QR code
    qr = RQRCode::QRCode.new(token_uri)
    qr_svg = qr.as_svg(
      color: "000",
      shape_rendering: "crispEdges",
      module_size: 4,
      standalone: true,
      use_path: true
    )

    # Resolve the FK. `ztlp_user:` (AR object) takes precedence over
    # the bare `ztlp_user_id:` integer for ergonomic Phase-A callers,
    # but if both are nil we leave the column untouched (legacy API
    # callers).
    resolved_user_id = ztlp_user&.id || ztlp_user_id

    enrollment_token = @network.enrollment_tokens.create!(
      token_id: token_id,
      token_uri: token_uri,
      qr_svg: qr_svg,
      max_uses: max_uses,
      expires_at: expires_at,
      ztlp_user_id: resolved_user_id,
      allowed_roles: Array(roles).join(","),
      notes: notes,
      target_kind: target_kind,
      target_label: target_label
    )

    AuditLog.record(
      action: "token_generate",
      target: enrollment_token,
      details: {
        network: @network.name,
        zone: @network.zone,
        max_uses: max_uses,
        expires_at: expires_at.iso8601,
        target_kind: target_kind,
        target_label: target_label
      }.compact
    )

    enrollment_token
  end

  # Try to use the ztlp CLI binary for token generation (more authentic)
  def generate_via_cli!(expires_in: "24h", max_uses: 1)
    unless cli_available?
      raise TokenError, "ztlp CLI not found at #{ZTLP_CLI}. Using built-in generator instead."
    end

    ns_machine = @network.ns_machines.first
    raise TokenError, "Network must have at least one NS machine" unless ns_machine

    cmd = [
      ZTLP_CLI, "admin", "enroll",
      "--zone", @network.zone,
      "--ns-server", "#{ns_machine.ip_address}:#{SshProvisioner::ZTLP_PORTS['ns'][:udp]}",
      "--expires", expires_in,
      "--max-uses", max_uses.to_s,
      "--json"
    ]

    output = `#{cmd.shelljoin} 2>&1`
    raise TokenError, "CLI failed: #{output}" unless $?.success?

    JSON.parse(output)
  end

  def cli_available?
    system("which #{ZTLP_CLI} > /dev/null 2>&1")
  end
end
