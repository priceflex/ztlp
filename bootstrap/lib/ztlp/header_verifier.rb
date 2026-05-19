# frozen_string_literal: true

require "openssl"
require "time"

module Ztlp
  # HMAC-SHA256 verification of ZTLP gateway identity headers.
  #
  # This is a Ruby port of ZtlpGateway.HeaderVerifier (Elixir). It MUST stay
  # byte-compatible with the gateway implementation living at
  # ztlp/gateway/lib/ztlp_gateway/header_verifier.ex and header_signer.ex.
  #
  # Canonicalization rules (matching the Elixir reference):
  #   1. Collect every X-ZTLP-* header except X-ZTLP-Signature.
  #   2. Sort by the lowercased header name.
  #   3. Build a canonical string of "name:value" pairs, where `name` is the
  #      lowercased header name and `value` is the raw (case-preserved) value,
  #      joined by "\n".
  #   4. HMAC-SHA256 the canonical string with the shared secret.
  #   5. Hex-encode the digest lowercase.
  #   6. Constant-time compare against the X-ZTLP-Signature header.
  #   7. Reject if X-ZTLP-Timestamp is missing or older than max_age_seconds.
  module HeaderVerifier
    module_function

    # Verify a request's X-ZTLP-* headers.
    #
    # Parameters:
    #   headers_hash    — any object yielding (name, value) pairs via `each`.
    #                     Works with ActionDispatch::Http::Headers, a plain
    #                     Hash, or an Array of [name, value] tuples.
    #   secret:         — (required) shared HMAC secret. String.
    #   max_age_seconds — reject signatures older than this many seconds
    #                     (default: 60).
    #
    # Returns:
    #   [:ok, identity]      — Hash mapping the stripped, lowercased header
    #                          suffix (e.g. "admin-email", "authenticated")
    #                          to the raw header value.
    #   [:error, reason]     — reason is one of:
    #                            :missing_signature
    #                            :invalid_signature
    #                            :missing_timestamp
    #                            :expired
    def verify_request(headers_hash, secret:, max_age_seconds: 60)
      ztlp_headers = extract_ztlp_headers(headers_hash)

      signature = find_header(ztlp_headers, "x-ztlp-signature")
      return [:error, :missing_signature] if signature.nil? || signature.empty?

      signing_headers = ztlp_headers.reject { |name, _| name.downcase == "x-ztlp-signature" }

      expected = hmac_hex(canonical_string(signing_headers), secret)
      return [:error, :invalid_signature] unless secure_compare(expected, signature)

      timestamp = find_header(signing_headers, "x-ztlp-timestamp")
      return [:error, :missing_timestamp] if timestamp.nil? || timestamp.empty?

      begin
        ts = Time.iso8601(timestamp)
      rescue ArgumentError
        return [:error, :missing_timestamp]
      end

      age = Time.now.utc.to_i - ts.utc.to_i
      return [:error, :expired] if age > max_age_seconds || age < 0

      [:ok, build_identity(signing_headers)]
    end

    # Build the canonical string used as HMAC input. Public so callers (and
    # tests) can sanity-check the canonicalization.
    def canonical_string(headers)
      headers
        .map { |name, value| [name.downcase, value] }
        .sort_by { |name, _| name }
        .map { |name, value| "#{name}:#{value}" }
        .join("\n")
    end

    # Compute the lowercase hex HMAC-SHA256 of the canonical string with the
    # given secret. Public so signers/tools can produce matching signatures.
    def hmac_hex(canonical, secret)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("sha256"), secret.to_s, canonical)
    end

    # -- internals -----------------------------------------------------------

    # Normalize a Rack/ActionDispatch header name (e.g. "HTTP_X_ZTLP_FOO") to
    # the canonical wire form ("X-ZTLP-Foo"). Already-canonical names pass
    # through unchanged.
    def normalize_name(raw_name)
      name = raw_name.to_s
      name = name.sub(/\AHTTP_/, "") if name.start_with?("HTTP_")
      # If the name still contains underscores and no dashes, it's the
      # rack env style. Convert underscores to dashes.
      if name.include?("_") && !name.include?("-")
        name = name.tr("_", "-")
      end
      name
    end

    def extract_ztlp_headers(headers_hash)
      result = []
      headers_hash.each do |name, value|
        next if name.nil? || value.nil?
        normalized = normalize_name(name)
        next unless normalized.downcase.start_with?("x-ztlp-")
        result << [normalized, value.to_s]
      end
      result
    end

    def find_header(headers, lowercase_name)
      pair = headers.find { |name, _| name.downcase == lowercase_name }
      pair && pair[1]
    end

    def build_identity(headers)
      headers.each_with_object({}) do |(name, value), acc|
        key = name.downcase.sub(/\Ax-ztlp-/, "")
        acc[key] = value
      end
    end

    # Constant-time string comparison. Returns false on length mismatch.
    def secure_compare(a, b)
      return false if a.nil? || b.nil?
      return false if a.bytesize != b.bytesize

      l = a.unpack("C*")
      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res.zero?
    end
  end
end
