# frozen_string_literal: true

# Slice 10b sub-slice 4: the LEGACY confirm endpoint (spec §7.4 "Legacy
# clients"). Older clients still call the token's legacy `callback_url`
# shape — `POST /api/enrollment/confirm` with a FORM body, UNAUTHENTICATED,
# carrying NO signed identity.
#
# It therefore may NOT enroll. It only:
#   - marks the enrollment `redeemed_unverified` (the token has been used by
#     a client whose identity the panel has NOT verified — deliberately a
#     different status from `redeemed`, which the signed path owns),
#   - creates the DEVICE row as `pending` (an administrator adopts it later;
#     a pending device is NOT published to the NS — the NS stays authoritative
#     over identity, so a pending device must not exist there),
#   - does NOT publish anything, does NOT activate the user, does NOT set a
#     signing key (none was signed), and NEVER leaks the token URI.
#
# Machine-to-machine posture: extends ActionController::Base directly (no
# admin session, no tunnel gate) and skips CSRF (a form body with no browser
# token). Rate-limited by rack-attack's `api/ip` throttle (10/min/IP).
class Api::EnrollmentLegacyController < ActionController::Base
  skip_forgery_protection

  class NameConflict < StandardError; end

  # The legacy form identifies the token by the human CODE (the token_id is
  # inside the token itself; the code is the human-facing half of it).
  def confirm
    # Spec F10 legacy callback body: token_id=&node_id=&name=&pubkey_hex=. The secret token_id is the
    # capability (the 8-char human code is shown to admins and in the audit log, so it never is).
    token_id = params[:token_id].to_s.strip
    return render_unprocessable("Missing token_id.") if token_id.empty?

    token = Enrollment.find_by(token_id: token_id)
    return render_404 if token.nil?

    # "name" is the device NS name ("old-pc.<zone>") or the bare label. node_id/pubkey_hex are
    # unverified here (no signature), so they are NOT stored: the device stays pending for adoption.
    device_name = params[:name].to_s.strip.downcase.delete_suffix(".#{token.zone.name}")
    return render_unprocessable("Missing name.") if device_name.empty?
    return render_unprocessable("Device name is not a valid label.") unless device_name.match?(Admin::USERNAME)
    if token.device_name.present? && device_name != token.device_name.to_s.downcase
      return render_unprocessable("Device name does not match this enrollment.")
    end

    return render_unprocessable("Enrollment is expired.") if token.expired?
    return render_unprocessable("Enrollment is revoked.") if token.revoked?
    return render_unprocessable("Enrollment is already used.") unless token.pending?
    return render_unprocessable("Enrollment uses are exhausted.") if token.uses >= token.max_uses.to_i

    owner = token.user
    Device.transaction do
      # Row lock + re-check: two concurrent confirms of a one-use token cannot both pass.
      token.lock!
      raise NameConflict, "enrollment is no longer redeemable" unless token.pending?

      existing = token.zone.devices.find_by(name: device_name)
      if existing && !(existing.status == "pending" && existing.node_id_hex.blank? &&
                       [ nil, token.id ].include?(existing.enrollment_id))
        raise NameConflict, "device name #{device_name} is already taken"
      end

      device = existing || token.zone.devices.build(name: device_name)
      # A PENDING device: no identity fields were signed by any client, so no
      # node_id / keys / enrollment timestamps. Owner is linked (the
      # enrollment's user) so the administrator can see WHO this is for, but
      # the device stays `pending` — adoption (Slice 11/adopt action) is what
      # turns it `enrolled` and publishes it to the NS.
      device.update!(status: "pending", user: owner, enrollment: token,
                     key_source: "unknown", assurance: 1)
      token.update_columns(uses: token.uses + 1, status: "redeemed_unverified",
                           redeemed_at: Time.current, redeemed_device_id: device.id)
      @reply = { "status" => "pending_adoption", "device" => device.ns_name,
                 "owner" => (owner && owner.ns_name) }
    end

    AuditLog.record!("enrollment.confirm", ip: request.remote_ip, status: "ok",
                     details: { code: token.code, device: device_name,
                                user: (owner && owner.username) })
    render json: @reply
  rescue NameConflict => e
    AuditLog.record!("enrollment.confirm", ip: request.remote_ip, status: "denied",
                     details: { code: token&.code, device: params[:name].to_s,
                                reason: e.message })
    render json: { "status" => "error", "error" => e.message }, status: :conflict
  rescue ActiveRecord::RecordNotSaved, ActiveRecord::RecordInvalid
    render json: { "status" => "error", "error" => "device could not be saved" },
           status: :unprocessable_entity
  end

  private

  def render_404
    render json: { "error" => "not found" }, status: :not_found
  end

  def render_unprocessable(message)
    render json: { "error" => message }, status: :unprocessable_entity
  end
end
