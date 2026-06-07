# frozen_string_literal: true

require "net/http"
require "openssl"
require "digest"
require "json"
require "uri"

# Ztlp::NsAdminClient — Bootstrap → NS admin-API HTTP client.
#
# Wraps `GET /admin/records` on the NS metrics server (port 9103 by
# default). Signs every request with HMAC-SHA256 using the canonical
# 4-line message shared with `ZtlpNs.AdminApi.verify_request/5`:
#
#     METHOD\n
#     PATH (incl. query string)\n
#     UNIX_TIMESTAMP\n
#     SHA256_HEX(body)
#
# The HMAC key is the per-deploy `ZTLP_NS_ADMIN_API_SECRET` (32 raw
# bytes, supplied as 64-char hex). Falls through to env vars when the
# call site doesn't pass `base_url:` / `secret:` — that's the
# expected production path; the keyword args exist for the tests.
#
# Failure modes are deliberately split into typed errors so the
# reconciler (T7) can decide whether to retry, alert, or bail without
# string-matching exception messages.
module Ztlp
  class NsAdminClient
    class Error < StandardError; end

    # Misconfiguration — base_url or secret missing/malformed. Boot-
    # time and CLI callers should treat this as fatal; reconcilers
    # should NOT retry.
    class ConfigurationError < Error; end

    # NS rejected our signature with HTTP 401. Usually means
    # `ZTLP_NS_ADMIN_API_SECRET` is out of sync between bootstrap and
    # NS. Don't retry — it'll just fail the same way next minute.
    class AuthenticationError < Error; end

    # NS returned a 5xx. Transient — reconcilers may retry on the
    # next tick.
    class ServerError < Error; end

    # Couldn't reach NS at all — DNS failure, connection refused,
    # timeout. Transient — same retry rules as ServerError.
    class TransportError < Error; end

    PATH = "/admin/records"
    DEFAULT_TIMEOUT = 10

    # GET /admin/records, optionally filtered by zone and/or type.
    # Returns the parsed JSON body as a Hash with string keys
    # ("records", "count", "generated_at").
    def self.list_records(zone: nil, type: nil, base_url: nil, secret: nil, timeout: DEFAULT_TIMEOUT)
      base_url ||= ENV["ZTLP_NS_ADMIN_BASE_URL"]
      secret   ||= ENV["ZTLP_NS_ADMIN_API_SECRET"]
      raise ConfigurationError, "base_url missing (set ZTLP_NS_ADMIN_BASE_URL)" if base_url.to_s.strip.empty?
      raise ConfigurationError, "secret missing (set ZTLP_NS_ADMIN_API_SECRET)" if secret.to_s.strip.empty?

      # Build the query string in sorted order so the canonical path
      # is deterministic. NS sees the path verbatim in `req.path`
      # and signs over the same string — any divergence (re-ordering,
      # extra encoding) blows the signature.
      query = {}
      query[:type] = type if type
      query[:zone] = zone if zone
      qs   = query.empty? ? "" : "?" + query.sort.map { |k, v| "#{k}=#{v}" }.join("&")
      path = PATH + qs

      ts            = Time.now.to_i
      body          = ""
      canonical     = "GET\n#{path}\n#{ts}\n#{Digest::SHA256.hexdigest(body)}"
      secret_bytes  = decode_secret(secret)
      signature     = OpenSSL::HMAC.hexdigest("sha256", secret_bytes, canonical)

      uri = URI.parse(base_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.open_timeout = timeout
      http.read_timeout = timeout

      req = Net::HTTP::Get.new(path)
      req["X-NS-Timestamp"] = ts.to_s
      req["X-NS-Signature"] = signature

      resp =
        begin
          http.request(req)
        rescue StandardError => e
          # Net::HTTP raises a grab-bag of low-level errors (Errno::*,
          # Net::OpenTimeout, SocketError, ...) — collapse them all
          # into TransportError so callers have one symbol to rescue.
          raise TransportError, "#{e.class}: #{e.message}"
        end

      case resp.code.to_i
      when 200      then JSON.parse(resp.body)
      when 401      then raise AuthenticationError, "NS rejected admin signature (HTTP 401)"
      when 500..599 then raise ServerError, "NS returned HTTP #{resp.code}"
      else               raise Error, "NS returned unexpected HTTP #{resp.code}"
      end
    end

    # Accept either a 64-char hex string (the canonical form, matches
    # what NS expects in `ZTLP_NS_ADMIN_API_SECRET`) or already-raw
    # 32 bytes. Anything else is a config error — fail loudly rather
    # than silently signing with the wrong key.
    def self.decode_secret(secret)
      packed = [secret].pack("H*")
      return packed if packed.bytesize == 32
      return secret if secret.bytesize == 32
      raise ConfigurationError, "secret must be 32 raw bytes or 64-char hex"
    end
    private_class_method :decode_secret
  end
end
