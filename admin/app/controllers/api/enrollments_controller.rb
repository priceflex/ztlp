# frozen_string_literal: true

# Slice 10b sub-slice 3: the SIGNED redeem endpoint (spec §7.4).
#
# POST /api/v1/enrollments/:token_id/redeem
#
# A newly-enrolled device POSTs its identity, signed with its fresh Ed25519
# key: {node_id, name, noise_pubkey_hex, signing_pubkey_hex, platform,
# agent_version, timestamp, signature} where
#   signature = Ed25519(sha256(canonical JSON of the body WITHOUT signature)).
#
# This is machine-to-machine (the client's agent, over the ZTLP tunnel), NOT a
# browser, so it does NOT inherit the tunnel-identity gate or the admin
# session from ApplicationController — it extends ActionController::Base
# directly. It is rate-limited by rack-attack's `api/ip` throttle (10/min/IP).
#
# Fail-closed (permanent security action, spec §7.4 / operator decision): the
# panel's OWN revocation of a token is enforced HERE — the NS has no
# per-token revocation, so the redeem path is where a panel-revoked token is
# refused. If the NS publish fails the whole transaction rolls back and the
# device is NOT shown as enrolled.
class Api::EnrollmentsController < ActionController::Base
  # Timestamp tolerance (spec §7.4): ±300 s.
  MAX_TIMESTAMP_DRIFT = 300
  # Fields the canonical-JSON signature covers (spec §7.4 body).
  BODY_FIELDS = %w[node_id name noise_pubkey_hex signing_pubkey_hex platform
                   agent_version timestamp].freeze

  def redeem
    token = Enrollment.find_by(token_id: params[:token_id])
    return render_404 if token.nil?

    body = redeem_body
    return render_unprocessable("Body must be a JSON object with the enrollment fields.") if body.nil?

    # Signature verification FIRST (before any token-state checks that could be
    # timing-observable), then the token's own state.
    sig = body["signature"].to_s
    return render_unprocessable("Missing signature.") if sig.empty?

    signable = signable_body(body)
    return render_unprocessable("Signature does not verify.") unless
      Ztlp::Ed25519.verify(pubkey_hex: body["signing_pubkey_hex"].to_s,
                           message: Ztlp::Ed25519.claim_message(signable),
                           signature_hex: sig)

    return render_unprocessable("Token is expired.") if token.expired?
    return render_unprocessable("Token uses are exhausted.") if token.uses >= token.max_uses.to_i
    return render_unprocessable("Token is revoked.") unless token.pending?
    return render_unprocessable("Timestamp is stale (outside ±300 s).") if
      (Time.current.to_i - body["timestamp"].to_i).abs > MAX_TIMESTAMP_DRIFT

    owner = token.user
    # Spec §7.4: ONE transaction. The device upsert, the token flip, the user
    # activation AND the NS publish are atomic with each other: a failure
    # anywhere (NS publish included) rolls back the WHOLE change, so a failed
    # enroll leaves the panel DB exactly as it was (fail-closed). The NS write
    # is the authority — if it refuses, nothing in the panel is committed.
    Device.transaction do
      device = upsert_device(token, body, owner)
      token.update_columns(uses: token.uses + 1, status: "redeemed",
                           redeemed_at: Time.current, redeemed_device_id: device.id)
      Ztlp::Publisher.publish_device!(device)
      Ztlp::Publisher.publish_user!(owner) if owner
      @redeem_reply = { "status" => "redeemed", "device" => device.ns_name,
                        "owner" => (owner && owner.ns_name) }
    end

    AuditLog.record!("enrollment.redeem", ip: request.remote_ip, status: "ok",
                     details: { code: token.code, device: token.device_name || @redeem_reply["device"],
                                user: (owner && owner.username) })
    render json: @redeem_reply
  rescue ActiveRecord::RecordNotSaved, ActiveRecord::RecordInvalid
    render json: { "status" => "error", "error" => "device could not be saved" },
           status: :unprocessable_entity
  rescue Ztlp::NsClient::NsError, Ztlp::Records::Error => e
    # Fail-closed: the transaction above rolled back — nothing changed in the
    # panel DB. A real 500 (not a silent 200). Rendered JSON, not re-raised,
    # so the error is honest and the middleware stack does not leak the
    # internal exception (rails-development-pitfalls §27h: publishing must not
    # 500 with a stack trace).
    AuditLog.record!("enrollment.redeem", ip: request.remote_ip, status: "failed",
                     details: { code: token.code, device: body["name"].to_s,
                                result: format("0x%02X %s", e.code, e.reason) })
    render json: { "status" => "error",
                   "error" => "Name server refused the enrollment (0x%02X %s). Nothing was saved; try again." % [ e.code, e.reason ] },
           status: :internal_server_error
  end

  private

  # The body hash restricted to the fields the signature covers. `deep_sort`
  # mirrors Ztlp::Ed25519.canonical_json so the signature covers exactly the
  # signed shape (keys sorted as strings, no whitespace).
  def signable_body(body)
    BODY_FIELDS.index_with { |f| body[f] }
  end

  # The wire form exactly as it arrived (request.raw_post). The test harness
  # serializes a Hash `params:` to clean JSON, and a real client's JSON body
  # round-trips to the same canonical shape Ztlp::Ed25519.deep_sort expects.
  def redeem_body
    raw = request.raw_post.to_s
    data = JSON.parse(raw)
    data.is_a?(Hash) ? data : nil
  rescue JSON::ParserError
    nil
  end

  # Create-or-upsert the DEVICE row. Upserting by (zone, name) makes a second
  # token for the same device idempotent (one row, re-enrolled) rather than a
  # uniqueness 500. The device's identity fields come from the signed body.
  def upsert_device(token, body, owner)
    name = body["name"].to_s.strip.downcase
    existing = token.zone.devices.find_by(name: name)
    device = existing || token.zone.devices.build(name: name)
    device.update!(
      node_id_hex: body["node_id"].to_s.strip,
      noise_pubkey_hex: body["noise_pubkey_hex"].to_s.strip,
      signing_pubkey_hex: body["signing_pubkey_hex"].to_s.strip,
      platform: body["platform"].to_s.strip.presence,
      agent_version: body["agent_version"].to_s.strip.presence,
      key_source: "unknown",
      assurance: 1,
      status: "enrolled",
      user: owner,
      enrollment: token,
      enrolled_at: Time.current,
      last_seen_at: Time.current
    )
    # user invited → active; set the user's signing pubkey if null.
    if owner
      owner.update!(status: "active") unless owner.active?
      owner.update_columns(signing_pubkey_hex: body["signing_pubkey_hex"].to_s.strip) if owner.signing_pubkey_hex.blank?
    end
    device
  end

  def render_404
    render json: { "error" => "not found" }, status: :not_found
  end

  def render_unprocessable(message)
    render json: { "error" => message }, status: :unprocessable_entity
  end
end
