# frozen_string_literal: true

# Mint a v1 enrollment token (shared by EnrollmentsController#create and UsersController#create
# "Enroll a device now"). Stores the URI encrypted at rest (token_uri_ct), audits WITHOUT the token,
# and arms the one-time reveal the show-once result page consumes. Raises
# Ztlp::TokenMinter::EnrollmentSecretMissing when the zone enrollment secret is not set.
#
# Expiry: 1h default, 24h hard max (spec F8 / Slice 10). `expiry_hours` is user-supplied: clamp it,
# and a blank value falls back to the 1h default.
module EnrollmentMinting
  extend ActiveSupport::Concern

  ENROLLMENT_SECRET_MISSING =
    "The zone enrollment secret is not set. Run `rails zone:set_secret enrollment` (stdin) first."

  private

  def clamp_expiry_hours(raw)
    hours = raw.to_s.strip
    hours = hours.empty? ? 1 : hours.to_i
    hours.clamp(1, Ztlp::TokenMinter::MAX_EXPIRY_SECONDS / 3600)
  end

  class InvalidDeviceName < StandardError; end

  DEVICE_NAME_HELP = "Device name must be the computer's short name, like heidys-macbook-air " \
                     "(lowercase letters, digits and dashes; no dots or spaces)."

  def mint_enrollment!(kind:, user:, device_name:, expiry_hours:, embed_relay_secret:)
    # The device name goes into the setup command (`--name`) and is how the panel finds the enrolled
    # device on the name server afterwards (KEY "<name>.<zone>", Ztlp::DevicePickup).
    # A missing zone secret is the bigger problem: report it before any form-field complaint.
    if @zone.enrollment_secret_ct.blank?
      audit!("enrollment.mint", status: "error", details: { error: "no_zone_enrollment_secret" })
      raise Ztlp::TokenMinter::EnrollmentSecretMissing, "zone #{@zone.name} has no enrollment secret"
    end

    device_name = device_name.to_s.strip.presence
    if kind == "user_device" && device_name.nil?
      raise InvalidDeviceName, "A user+device token needs the device name: the panel finds the enrolled device by it."
    end
    raise InvalidDeviceName, DEVICE_NAME_HELP if device_name && !(device_name.length <= 63 && device_name.match?(Admin::USERNAME))

    # embed_relay_secret is a NOT NULL boolean column (default false). Forms post "1" when checked
    # and nothing when unchecked: cast to a real boolean (nil would 500 on the NOT NULL column).
    embed_relay = %w[1 true on yes].include?(embed_relay_secret.to_s.strip.downcase)

    enrollment = @zone.enrollments.build(
      kind: kind,
      user: user,
      device_name: device_name,
      embed_relay_secret: embed_relay,
      max_uses: 1,
      status: "pending",
      expires_at: clamp_expiry_hours(expiry_hours).hours.from_now,
      created_by_admin: current_admin
    )
    enrollment.token_id = Enrollment.generate_token_id

    # The callback_url points the CLI (ztlp-cli.rs confirm_enrollment) at the panel's OWN
    # unauthenticated legacy endpoint. The panel's public URL comes from ZTLP_PANEL_PUBLIC_URL;
    # when unset (or malformed: no http(s) scheme) fall back to request.host_with_port.
    raw_public_url = ENV.fetch("ZTLP_PANEL_PUBLIC_URL", "").to_s.strip
    base = raw_public_url.match?(%r{\Ahttps?://}) ? raw_public_url : "http://#{request.host_with_port}"
    callback_url = "#{base.chomp('/')}/api/enrollment/confirm"

    begin
      uri = Ztlp::TokenMinter.to_uri(
        Ztlp::TokenMinter.mint(@zone, expires_at: enrollment.expires_at.to_i, callback_url: callback_url,
                                      relay_secret: (embed_relay ? @zone.token_relay_secret : nil),
                                      ns_key_hex: @zone.ns_pubkey_hex)
      )
    rescue Ztlp::TokenMinter::EnrollmentSecretMissing
      audit!("enrollment.mint", status: "error", details: { error: "no_zone_enrollment_secret" })
      raise
    end
    enrollment.token_uri_ct = uri
    enrollment.save!

    # The audit row records the HUMAN code + user, never the token URI.
    audit!("enrollment.mint", target: enrollment, status: "ok",
                              details: { code: enrollment.code, kind: enrollment.kind,
                                         user: user&.username, device: enrollment.device_name,
                                         embed_relay_secret: enrollment.embed_relay_secret,
                                         relay_secret_in_token: embed_relay && @zone.token_relay_secret.present?,
                                         ns_key_in_token: @zone.ns_pubkey_hex.present? })
    # One-time reveal: the result page renders the URI once, then clears this.
    session[:enrollment_reveal] = { enrollment_id: enrollment.id, nonce: SecureRandom.hex(16) }
    enrollment
  end
end
