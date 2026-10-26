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

  def mint_enrollment!(kind:, user:, device_name:, expiry_hours:, embed_relay_secret:)
    # embed_relay_secret is a NOT NULL boolean column (default false). Forms post "1" when checked
    # and nothing when unchecked: cast to a real boolean (nil would 500 on the NOT NULL column).
    embed_relay = %w[1 true on yes].include?(embed_relay_secret.to_s.strip.downcase)

    enrollment = @zone.enrollments.build(
      kind: kind,
      user: user,
      device_name: device_name.to_s.strip.presence,
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
        Ztlp::TokenMinter.mint(@zone, expires_at: enrollment.expires_at.to_i, callback_url: callback_url)
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
                                         user: user&.username, embed_relay_secret: enrollment.embed_relay_secret })
    # One-time reveal: the result page renders the URI once, then clears this.
    session[:enrollment_reveal] = { enrollment_id: enrollment.id, nonce: SecureRandom.hex(16) }
    enrollment
  end
end
