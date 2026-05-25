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
  # @param expires_in   [ActiveSupport::Duration] how long the token is valid
  # @param max_uses     [Integer] how many times the token can be redeemed
  # @param roles        [Array<String>, String, nil] roles to attach
  # @param notes        [String, nil] free-form operator notes
  # @param ztlp_user_id [Integer, nil] owner user id (for IdP-bulk enrollment)
  # @param bootstrap_url [String, nil] the publicly-reachable URL of THIS
  #   bootstrap instance, used to build the `callback=` query parameter of
  #   the minted `ztlp://enroll/?...` URI. The CLI reads `callback=` and
  #   POSTs to `<callback>/api/enrollment/confirm` after a successful
  #   enrollment, which is what flips the token from `active` to
  #   `exhausted` and creates the corresponding `ZtlpDevice` row.
  #
  #   Resolution order (Phase B fix):
  #     1. `bootstrap_url:` keyword arg (controller passes `request.base_url`)
  #     2. `ENV["BOOTSTRAP_URL"]` (legacy env fallback, also used by jobs)
  #     3. nil — `callback=` is omitted entirely; the operator will need
  #        to mark the token exhausted manually or wait for TokenReconciler.
  #
  #   A trailing `/` on the URL is stripped so we never emit `...//api/...`.
  def generate!(expires_in: 24.hours, max_uses: 1, roles: nil, notes: nil,
                ztlp_user_id: nil, bootstrap_url: nil)
    ns_machine = @network.ns_machines.first
    relay_machine = @network.relay_machines.first

    raise TokenError, "Network must have at least one NS machine" unless ns_machine

    token_id = SecureRandom.hex(8)
    expires_at = Time.current + expires_in

    # Build the enrollment URI
    ns_addr = "#{ns_machine.ip_address}:#{SshProvisioner::ZTLP_PORTS['ns'][:udp]}"
    relay_addr = relay_machine ? "#{relay_machine.ip_address}:#{SshProvisioner::ZTLP_PORTS['relay'][:udp]}" : nil

    # ── Phase B redemption fix ────────────────────────────────────────────
    # Resolve the callback URL the CLI will POST to after enrollment.
    # Prefer the per-request value (correct for any deployment topology),
    # fall back to the legacy `BOOTSTRAP_URL` env (which Launch never set
    # for tenants, which is exactly the bug Phase B addresses). All other
    # query-param values are URL-encoded too, so the callback value must
    # be encoded to survive the simple `"#{k}=#{v}"` join below.
    raw_base = bootstrap_url.presence || ENV["BOOTSTRAP_URL"].presence
    callback_url =
      if raw_base
        normalised = raw_base.sub(%r{/+\z}, "")  # strip any trailing slashes
        ERB::Util.url_encode("#{normalised}/api/enrollment/confirm")
      end
    # ──────────────────────────────────────────────────────────────────────

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

    enrollment_token = @network.enrollment_tokens.create!(
      token_id: token_id,
      token_uri: token_uri,
      qr_svg: qr_svg,
      max_uses: max_uses,
      expires_at: expires_at,
      ztlp_user_id: ztlp_user_id,
      allowed_roles: Array(roles).join(","),
      notes: notes
    )

    AuditLog.record(
      action: "token_generate",
      target: enrollment_token,
      details: {
        network: @network.name,
        zone: @network.zone,
        max_uses: max_uses,
        expires_at: expires_at.iso8601
      }
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
