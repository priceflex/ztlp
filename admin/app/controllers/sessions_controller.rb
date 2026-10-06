# frozen_string_literal: true

# Ed25519 challenge-response login (spec §4.2). HTML + JSON.
class SessionsController < ApplicationController
  skip_before_action :require_sign_in
  skip_before_action :verify_authenticity_token, only: %i[challenge verify], if: -> { request.format.json? }

  # GET /login
  def new
    redirect_to root_path if signed_in?
  end

  # POST /auth/challenge {pubkey_hex}
  def challenge
    pub = params[:pubkey_hex].to_s.strip.downcase
    admin = Admin.active.find_by(pubkey_hex: pub)
    # Do not reveal whether the key is known: always return a nonce-shaped answer.
    nonce = admin ? LoginChallenge.issue!(admin).nonce : SecureRandom.hex(32)
    payload = { nonce: nonce, expires_in: LoginChallenge::TTL.to_i, host: request.host,
                message: Ztlp::Ed25519.login_message(request.host, nonce) }
    respond_to do |f|
      f.json { render json: payload }
      f.html do
        @challenge = payload
        @pubkey_hex = pub
        render :new
      end
    end
  end

  # POST /auth/verify {pubkey_hex, nonce, signature}
  def verify
    pub = params[:pubkey_hex].to_s.strip.downcase
    admin = Admin.active.find_by(pubkey_hex: pub)
    ch = admin && LoginChallenge.live.find_by(admin: admin, nonce: params[:nonce].to_s)
    ok = ch && Ztlp::Ed25519.verify(pubkey_hex: pub, message: Ztlp::Ed25519.login_message(request.host, ch.nonce),
                                    signature_hex: params[:signature].to_s.strip.downcase)
    unless ok
      AuditLog.record!("auth.login_failed", ip: request.remote_ip, status: "error", details: { pubkey_hex: pub })
      respond_to do |f|
        f.json { render json: { error: "signature does not verify" }, status: :unauthorized }
        f.html { redirect_to login_path, alert: "Signature does not verify. Request a new challenge." }
      end
      return
    end
    ch.consume!
    raw = SessionToken.issue!(admin)
    AuditLog.record!("auth.login", admin: admin, ip: request.remote_ip)
    url = auth_session_url(raw)
    respond_to do |f|
      f.json { render json: { login_url: url } }
      f.html { redirect_to url }
    end
  end

  # GET /auth/session/:token  -> cookie session
  def exchange
    admin = SessionToken.redeem!(params[:token])
    return redirect_to(login_path, alert: "Login link expired or already used.") unless admin

    sign_in!(admin)
    redirect_to root_path, notice: "Signed in as #{admin.display_name}."
  end

  def destroy
    audit!("auth.logout") if signed_in?
    reset_session
    redirect_to login_path, notice: "Signed out."
  end
end
