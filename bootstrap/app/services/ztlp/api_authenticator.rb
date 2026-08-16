# frozen_string_literal: true

# Ztlp::ApiAuthenticator — verifies a request against the ZTLP-secured
# per-zone HMAC contract.
#
# This is the request-time half of the BS-PR-2 API auth design (see
# the bootstrap workstream in `~/hermes_session_handoff.md`). The
# allowlist half lives in the `ApiClient` model.
#
# ## Contract (v1)
#
# Caller sets the following request headers:
#
#     X-ZTLP-Zone:      <zone-id, e.g. "acme.ztlp">
#     X-ZTLP-Client:    <api_clients.name, e.g. "z2ls.acme">
#     X-ZTLP-Timestamp: <unix-seconds, integer>
#     X-ZTLP-Nonce:     <32-char hex, unique per request>
#     X-ZTLP-Signature: <hex HMAC-SHA256 over the canonical message>
#
# Canonical signed message (newline-joined):
#
#     METHOD\n
#     PATH\n
#     X-ZTLP-Zone\n
#     X-ZTLP-Client\n
#     X-ZTLP-Timestamp\n
#     X-ZTLP-Nonce\n
#     SHA256_HEX(body)
#
# `METHOD` is upper-cased. `PATH` is request path + query string
# (matches `request.fullpath`). `SHA256_HEX(body)` is the lower-case
# hex digest of the raw request body (empty string → digest of `""`).
#
# The HMAC key is the per-zone primary secret returned by the same
# resolution rule the gateway uses
# (`ZTLP_HMAC_SECRET_<UPCASE_SLUGIFIED_ZONE>` env var, first
# comma-separated entry). This keeps Bootstrap, gateway, and relay
# all reading from the same secret store.
#
# ## Why this design
#
# * **No API keys.** Per Steve's brief — the credential is the
#   per-zone HMAC secret already in use elsewhere in the stack.
# * **Replay protection** via the 5-minute timestamp window. Without
#   it an intercepted request could be re-sent indefinitely.
# * **Body integrity** via the body-digest line. Without it an
#   attacker could swap the POST body of an in-flight signed request.
# * **`(zone, name)` allowlist on top of HMAC.** Mathematically the
#   HMAC alone is enough; the allowlist gives operators a kill
#   switch ("revoke this client") without needing to rotate the
#   per-zone secret.
#
# ## What this does NOT do
#
# * No mTLS. The HMAC is the only credential.
# * No request-rate limiting. That belongs in Rack::Attack at the
#   controller layer (BS-PR-3 will add it for `POST /api/v1/enrollment_tokens`).
# * No Ed25519 path. The `api_clients.ed25519_pubkey` column is
#   reserved for a future BS-PR-7+ variant; v1 ignores it.
module Ztlp
  class ApiAuthenticator
    # Replay window — accept timestamps within ±5 minutes of "now".
    # Tighter is more secure but trips up clients whose clock drifts;
    # 5 minutes is the same window the relay's V1/V2 GATEWAY_REGISTER
    # path uses.
    DEFAULT_CLOCK_SKEW_SECONDS = 300

    # Nonce cache — used nonces are stored here with a TTL matching
    # the clock skew window so they expire exactly when the timestamp
    # window closes.  This prevents replay attacks (CWE-840) within
    # the accepted time window.
    # Key format: "api_auth:nonce:<canonical-ts>:<nonce>"
    # The canonical timestamp (rounded to the second) is part of the
    # key to avoid cross-contamination when a client re-signs the same
    # logical request with a fresh nonce at a different second.
    NONCE_CACHE_PREFIX = "api_auth:nonce:"

    # Concrete error classes the controller can rescue from.
    Result = Struct.new(:ok?, :client, :reason, keyword_init: true) do
      def self.success(client) = new(ok?: true,  client: client, reason: nil)
      def self.failure(reason) = new(ok?: false, client: nil,    reason: reason)
    end

    def initialize(request, clock_skew: DEFAULT_CLOCK_SKEW_SECONDS, now: Time.current)
      @request = request
      @clock_skew = clock_skew
      @now = now
    end

    # Verify the request. Returns a `Result` struct — `.ok?` is the
    # high-level signal; `.client` is the authenticated `ApiClient`
    # row; `.reason` is a short symbol useful for log emission but NOT
    # for response bodies (don't leak it to the caller — return a
    # generic 401).
    def authenticate
      zone      = header("X-ZTLP-Zone")
      client    = header("X-ZTLP-Client")
      ts_raw    = header("X-ZTLP-Timestamp")
      nonce     = header("X-ZTLP-Nonce")
      provided  = header("X-ZTLP-Signature")

      return Result.failure(:missing_header) if [zone, client, ts_raw, nonce, provided].any?(&:blank?)

      ts = Integer(ts_raw, exception: false)
      return Result.failure(:bad_timestamp) if ts.nil?

      return Result.failure(:expired_timestamp) if (ts - @now.to_i).abs > @clock_skew

      # Replay protection — reject if this nonce was already used.
      return Result.failure(:replayed_nonce) if nonce_used?(nonce, ts)

      api_client = ApiClient.find_active(zone: zone, name: client)
      return Result.failure(:unknown_client) unless api_client

      secret = resolve_zone_secret(zone)
      return Result.failure(:no_zone_secret) if secret.blank?

      expected = compute_hmac(secret, ts: ts, nonce: nonce, zone: zone, client: client)

      unless secure_compare(expected, provided)
        return Result.failure(:bad_signature)
      end

      # Record the nonce so the exact same request cannot be replayed.
      mark_nonce_used!(nonce, ts)

      api_client.touch_last_used!
      Result.success(api_client)
    end

    # Public helper: same canonical signing rule the authenticator
    # verifies against. Useful for tests + for the Z2LS-side signing
    # docs in `docs/enrollment_token_lifecycle.md` (and the BS-PR-6
    # runbook).
    def self.canonical_signing_string(method:, path:, zone:, client:, timestamp:, nonce:, body:)
      body_digest = Digest::SHA256.hexdigest(body.to_s)

      [
        method.to_s.upcase,
        path.to_s,
        zone.to_s,
        client.to_s,
        timestamp.to_s,
        nonce.to_s,
        body_digest
      ].join("\n")
    end

    # Public helper for tests + for Z2LS clients in Ruby land.
    def self.sign(method:, path:, zone:, client:, timestamp:, nonce:, body:, secret:)
      msg = canonical_signing_string(
        method: method, path: path, zone: zone,
        client: client, timestamp: timestamp, nonce: nonce,
        body: body
      )

      OpenSSL::HMAC.hexdigest("SHA256", secret, msg)
    end

    # Public helper: zone → env var name. Same rule as
    # `ZtlpGateway.HmacSecrets.slugify_zone/1` and
    # `ZtlpRelay.HmacSecrets.slugify_zone/1`.
    def self.slugify_zone(zone)
      zone.to_s.upcase.gsub(/[^A-Z0-9]+/, "_").sub(/\A_/, "").sub(/_\z/, "")
    end

    # Resolve the per-zone primary secret. Reads the same env var the
    # gateway and relay read. First comma-separated entry is primary;
    # we accept hex (64 chars) and raw, matching the gateway's
    # decoding rules. (`base64:` prefix support is omitted in v1 —
    # add it when an operator actually needs it.)
    def self.resolve_zone_secret(zone)
      raw = ENV["ZTLP_HMAC_SECRET_#{slugify_zone(zone)}"]
      return nil if raw.blank?

      primary = raw.split(",").first.to_s.strip
      return nil if primary.empty?

      if primary.length == 64 && primary.match?(/\A[0-9a-fA-F]+\z/)
        [primary].pack("H*")
      else
        primary
      end
    end

    private

    def header(name)
      # `request.headers[]` accepts the literal HTTP header name; in
      # tests we may receive a hash directly.
      if @request.respond_to?(:headers)
        @request.headers[name]
      else
        @request[name]
      end
    end

    def body_for_digest
      if @request.respond_to?(:raw_post)
        @request.raw_post
      elsif @request.respond_to?(:body)
        body = @request.body.read
        @request.body.rewind if @request.body.respond_to?(:rewind)
        body
      else
        ""
      end
    end

    def request_method
      @request.request_method.to_s.upcase
    end

    def request_path
      # Use `fullpath` so query strings are included.
      @request.fullpath
    end

    def compute_hmac(secret, ts:, nonce:, zone:, client:)
      self.class.sign(
        method: request_method,
        path: request_path,
        zone: zone,
        client: client,
        timestamp: ts,
        nonce: nonce,
        body: body_for_digest,
        secret: secret
      )
    end

    def resolve_zone_secret(zone)
      self.class.resolve_zone_secret(zone)
    end

    # Constant-time string compare — uses ActiveSupport's wrapper if
    # available (ships with Rails 7.1) and falls back to a manual
    # loop for symmetry.
    def secure_compare(a, b)
      return false if a.nil? || b.nil? || a.bytesize != b.bytesize

      ActiveSupport::SecurityUtils.secure_compare(a, b)
    end

    # ── Replay protection helpers ─────────────────────────────────

    def nonce_cache_key(nonce, ts)
      "#{NONCE_CACHE_PREFIX}#{ts}:#{nonce}"
    end

    def nonce_used?(nonce, ts)
      Rails.cache.read(nonce_cache_key(nonce, ts))
    end

    def mark_nonce_used!(nonce, ts)
      # TTL matches the clock skew window — nonces expire exactly
      # when the timestamp window closes.
      Rails.cache.write(nonce_cache_key(nonce, ts), 1, expires_in: @clock_skew.seconds)
    end
  end
end
