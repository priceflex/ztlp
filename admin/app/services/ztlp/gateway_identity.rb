# frozen_string_literal: true

module Ztlp
  # Verifies the signed X-ZTLP-* identity headers the Rust gateway
  # (`ztlp listen --http-inject-headers`) stamps on every request that
  # arrived through an authenticated ZTLP tunnel. The gateway strips any
  # client-supplied X-ZTLP-* headers before injecting, so a verified
  # bundle means "this request came through MY gateway, from THIS peer".
  #
  # Canonical string (proto/src/http_injector.rs): the eight signed fields,
  # lowercased names, "name:value" joined by "\n", sorted by name, no
  # trailing newline. HMAC-SHA256 with the raw bytes of --header-hmac-secret.
  class GatewayIdentity
    SIGNED = %w[authenticated admin-email device-name zone group assurance audience timestamp].freeze
    MAX_AGE = 30 # seconds, mirrors the PoC verifier

    Result = Struct.new(:ok, :subject, :device_name, :zone, :fingerprint, :error, keyword_init: true)

    def self.secret = ENV["ZTLP_GATEWAY_HEADER_SECRET"].to_s
    def self.audience = ENV.fetch("ZTLP_GATEWAY_AUDIENCE", "admin")
    def self.enabled? = secret.present?

    # headers: anything responding to #[] with "X-ZTLP-Foo" keys (Rack env is
    # also accepted via the HTTP_X_ZTLP_FOO form).
    def self.verify(headers, now: Time.now.utc)
      return Result.new(ok: false, error: "disabled") unless enabled?

      get = lambda do |f|
        headers["X-ZTLP-#{f.split("-").map(&:capitalize).join("-")}"] ||
          headers["HTTP_X_ZTLP_#{f.upcase.tr("-", "_")}"]
      end
      sig = get.call("signature").to_s.downcase
      return Result.new(ok: false, error: "no signature") if sig.empty?

      fields = SIGNED.to_h { |f| [ f, get.call(f).to_s ] }
      return Result.new(ok: false, error: "not authenticated") unless fields["authenticated"] == "1"
      return Result.new(ok: false, error: "audience mismatch") unless fields["audience"] == audience

      ts = Time.iso8601(fields["timestamp"]) rescue nil
      return Result.new(ok: false, error: "bad timestamp") unless ts
      return Result.new(ok: false, error: "stale") if (now - ts).abs > MAX_AGE

      canonical = fields.map { |k, v| "x-ztlp-#{k}:#{v}" }.sort.join("\n")
      expected = OpenSSL::HMAC.hexdigest("SHA256", secret, canonical)
      return Result.new(ok: false, error: "bad signature") unless ActiveSupport::SecurityUtils.secure_compare(expected, sig)

      Result.new(ok: true, subject: fields["admin-email"], device_name: fields["device-name"], zone: fields["zone"])
    end
  end
end
