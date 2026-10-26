# frozen_string_literal: true

# First-administrator claim (spec §4.1).
class Claim
  KEY_DIGEST = "claim_code_digest"
  KEY_EXPIRES = "claim_code_expires_at"
  # Set ONLY by `admin:reset_claim` (issue!(force: true)). Server-side state is the sole source of
  # "force": a request can never ask for it.
  KEY_FORCED = "claim_code_forced"
  TTL = 24.hours
  SKEW = 300

  Error = Class.new(StandardError)

  class << self
    def needed? = !Admin.exists_any?

    # /claim is open when nobody has claimed yet, or a break-glass code is pending and unexpired.
    def open? = needed? || forced_pending?

    def forced_pending?
      SystemSetting[KEY_FORCED] == "1" && SystemSetting[KEY_DIGEST].present? &&
        Time.zone.parse(SystemSetting[KEY_EXPIRES].to_s)&.future? == true
    end

    # Idempotent: ensures a live claim code exists when no admin exists.
    # Returns the plaintext code ONLY when a new one was generated.
    def ensure_code!
      return nil unless needed?
      return nil if SystemSetting[KEY_DIGEST].present? && Time.zone.parse(SystemSetting[KEY_EXPIRES].to_s)&.future?

      issue!
    end

    def issue!(force: false)
      raw = SecureRandom.random_bytes(20)
      code = Base32ish.encode(raw).scan(/.{1,4}/).join("-")
      SystemSetting[KEY_DIGEST] = Digest::SHA256.hexdigest(normalize(code))
      SystemSetting[KEY_EXPIRES] = TTL.from_now.iso8601
      if force
        SystemSetting[KEY_FORCED] = "1"
      else
        SystemSetting.delete_key(KEY_FORCED)
      end
      if force
        Rails.logger.warn("ZTLP ADMIN: forced claim reissue (break-glass). Claim code: #{code} (valid 24h)")
        $stdout.puts("ZTLP ADMIN: forced claim reissue (break-glass). Claim code: #{code} (valid 24h)")
      else
        Rails.logger.warn("ZTLP ADMIN: no administrator yet. Claim code: #{code} (valid 24h)")
        $stdout.puts("ZTLP ADMIN: no administrator yet. Claim code: #{code} (valid 24h)")
      end
      code
    end

    def code_valid?(code)
      digest = SystemSetting[KEY_DIGEST]
      exp = SystemSetting[KEY_EXPIRES]
      return false if digest.blank? || exp.blank? || Time.zone.parse(exp) <= Time.current

      ActiveSupport::SecurityUtils.secure_compare(digest, Digest::SHA256.hexdigest(normalize(code.to_s)))
    end

    # params: claim_code, username, display_name, email, pubkey_hex, timestamp, signature (optional)
    # force: true = break-glass (spec §4.1 step 6): when admins already exist, the claim creates an
    # ADDITIONAL super_admin instead of failing. Only reachable from admin:reset_claim.
    def perform!(params, ip: nil, force: false)
      raise Error, "An administrator already exists." if !force && !needed?
      raise Error, "Invalid or expired claim code." unless code_valid?(params[:claim_code])

      pub = params[:pubkey_hex].to_s.strip.downcase
      raise Error, "Public key must be 64 hex characters." unless Ztlp::Ed25519.valid_pubkey_hex?(pub)

      if params[:signature].present?
        ts = params[:timestamp].to_i
        raise Error, "Timestamp outside the allowed window." unless (Time.current.to_i - ts).abs <= SKEW

        body = {
          "claim_code" => params[:claim_code].to_s, "username" => params[:username].to_s,
          "display_name" => params[:display_name].to_s, "email" => params[:email].to_s,
          "pubkey_hex" => pub, "timestamp" => ts
        }
        ok = Ztlp::Ed25519.verify(pubkey_hex: pub, message: Ztlp::Ed25519.claim_message(body),
                                  signature_hex: params[:signature].to_s.strip.downcase)
        raise Error, "Signature does not verify against the public key." unless ok
      end

      admin = nil
      Admin.transaction do
        raise Error, "An administrator already exists." if Admin.exists_any? && !force

        admin = Admin.create!(username: params[:username], display_name: params[:display_name],
                              email: params[:email].presence, pubkey_hex: pub, role: "super_admin")
        zone = Zone.default
        user = zone.users.create!(username: params[:username], display_name: params[:display_name],
                                  kind: "person", role: "admin", status: "active")
        admin.update!(user_id: user.id)
        admins_group = zone.groups.find_or_create_by!(name: "admins")
        zone.groups.find_or_create_by!(name: "staff")
        admins_group.group_memberships.create!(user: user, added_by_admin: admin)
        SystemSetting.delete_key(KEY_DIGEST)
        SystemSetting.delete_key(KEY_EXPIRES)
        SystemSetting.delete_key(KEY_FORCED)
        break_glass = force && Admin.count > 1
        AuditLog.record!(break_glass ? "system.reset_claim" : "system.claimed",
                                           admin: admin, target: admin, ip: ip,
                                           details: { signed: params[:signature].present? })
      end
      admin
    end

    def normalize(code) = code.to_s.upcase.delete("- ")
  end

  # RFC4648 base32 alphabet without padding; good enough for a human-typed code.
  module Base32ish
    ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    def self.encode(bytes)
      bits = bytes.unpack1("B*")
      bits += "0" * ((5 - bits.size % 5) % 5)
      bits.scan(/.{5}/).map { |b| ALPHA[b.to_i(2)] }.join
    end
  end
end
