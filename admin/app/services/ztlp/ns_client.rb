# frozen_string_literal: true

require "socket"
require "net/http"
require "openssl"
require "digest"
require "json"

module Ztlp
  # Thin client for the ZTLP name server (Elixir OTP, ns/lib/ztlp_ns).
  #
  # Wire formats are pinned to the NS sources:
  #   register v2 (server.ex:51):
  #     <<0x09, name_len::16, name, type::8, data_len::16, data,
  #       sig_len::16, sig, pubkey_len::16, pubkey>>
  #   canonical form signed (registration_auth.ex build_canonical):
  #     <<type::8, name_len::16, name, data_bin>>
  #   query (server.ex:171): <<0x01, name_len::16, name, type::8>>
  #     padded to 600 bytes (NS ignores trailing padding)
  #   query reply 0x02 (record.ex serialize):
  #     <<0x02, type::8, name_len::16, name, data_len::32, data,
  #       created_at::64, ttl::32, serial::64>>
  #   replies: 0x06 ack, 0x03 not found, 0x04 revoked,
  #            0xFF + reason code (registration_error.ex)
  #
  # Record list (spec F6): GET /admin/records on the NS metrics port with
  # x-ns-timestamp + x-ns-signature headers. The signature is HMAC-SHA256
  # over "GET\n<path>\n<ts>\n<sha256hex(body)>" (ns/lib/ztlp_ns/admin_api.ex).
  class NsClient
    # NS registration rejection codes (registration_error.ex reason_to_code).
    # 0x0C timeout and 0x0D refused are panel-invented (no NS code for them).
    REASON_CODES = {
      0x00 => "unspecified", 0x01 => "unknown_type", 0x02 => "missing_pubkey",
      0x03 => "invalid_name", 0x04 => "invalid_signature", 0x05 => "unauthorized",
      0x06 => "key_overwrite", 0x07 => "revoked_pubkey", 0x08 => "revoked_name",
      0x09 => "rate_limited", 0x0A => "invalid_data", 0x0B => "storage_error",
      0x0C => "timeout", 0x0D => "refused"
    }.freeze

    TYPE_BYTES = {
      "key" => 0x01, "svc" => 0x02, "relay" => 0x03, "policy" => 0x04,
      "revoke" => 0x05, "device" => 0x10, "user" => 0x11, "group" => 0x12
    }.freeze

    QUERY_PAD_SIZE = 600
    MAX_REPLY = 65_535

    # Raised for every NS rejection and transport failure. `code` is a
    # REASON_CODES key; `reason` is its string name.
    class NsError < StandardError
      attr_reader :code, :reason

      def initialize(code, reason)
        @code = code
        @reason = reason
        super("NS rejected (#{code.to_s(16)} #{reason})")
      end
    end

    # ── public API ─────────────────────────────────────────────────

    # Register a record signed by `seed` (64-hex Ed25519 seed). Returns :ok
    # on a 0x06 ack; raises NsError on 0xFF+code, timeout or connection
    # refusal. Retries once on timeout (spec: 5 s timeout, 1 retry).
    def self.register(ns_addr, timeout, name:, type:, data:, seed:, socket: nil)
      type_byte = require_type(type)
      data_bin = Cbor.encode(data)
      sig_hex = Ed25519.sign(seed_hex: seed, message: canonical(type_byte, name, data_bin))
      pubkey = raw_pubkey(seed) # 32 raw bytes, not hex
      packet = [ 0x09, name.bytesize, name.b, type_byte, data_bin.bytesize, data_bin,
                 64, [ sig_hex ].pack("H*"), pubkey.bytesize, pubkey ]
                .pack("C n a* C n a* n a* n a*")

      send_one(ns_addr, timeout, packet, socket: socket).then do |reply|
        first = reply.getbyte(0)
        if first == 0x06
          :ok
        elsif first == 0xFF
          code = reply.getbyte(1) || 0x00
          raise NsError.new(code, REASON_CODES[code] || "unspecified")
        else
          raise NsError.new(0x00, "bad_reply")
        end
      end
    end

    # Query a record by name+type. Returns :not_found / :revoked, or
    # { name:, type:, data:, created_at:, ttl:, serial: } on a 0x02 reply.
    def self.query(ns_addr, timeout, name:, type:, socket: nil)
      type_byte = require_type(type)
      request = [ 0x01, name.bytesize, name.b, type_byte ].pack("C n a* C")
      request = request + "\x00".b * (QUERY_PAD_SIZE - request.bytesize)

      reply = send_one(ns_addr, timeout, request, socket: socket)
      first = reply.getbyte(0)
      case first
      when 0x02 then parse_record(reply)
      when 0x03 then :not_found
      when 0x04 then :revoked
      when 0xFF
        code = reply.getbyte(1) || 0x00
        raise NsError.new(code, REASON_CODES[code] || "unspecified")
      else
        raise NsError.new(0x00, "bad_reply")
      end
    end

    # List records via the NS admin HTTP API (spec F6). `ns_admin_api_port`
    # is the metrics port (9103 by default, ZTLP_NS_METRICS_PORT);
    # `ns_admin_api_secret` is the 64-hex (or 32-raw) secret behind
    # /admin/records. Test seams: `http:`, `ts:`, `headers:`.
    def self.list(ns_admin_api_port, ns_admin_api_secret, type: nil, zone: nil, http: nil, ts: nil, headers: nil)
      ts ||= Time.now.to_i
      headers ||= admin_headers(ns_admin_api_secret, ts, path_for(type: type, zone: zone))
      http ||= Net::HTTP.new("127.0.0.1", ns_admin_api_port)
      # Test seams (mocha doubles) reject setter invocations; real
      # sockets get a 5 s read + open budget.
      http.read_timeout = 5 if http.is_a?(Net::HTTP)
      http.open_timeout = 5 if http.is_a?(Net::HTTP)
      resp = http.get(path_for(type: type, zone: zone), headers)
      unless resp.code == "200"
        code = resp.code == "401" ? 0x05 : 0x00
        raise NsError.new(code, REASON_CODES[code])
      end

      parsed = JSON.parse(resp.body)
      Array(parsed["records"]).map { |r| symbolize_record(r) }
    end

    # ── wire helpers (public for tests) ────────────────────────────

    # The canonical form the registrant signs (registration_auth.ex).
    def self.canonical(type_byte, name, data_bin)
      [ type_byte, name.bytesize, name.b, data_bin.b ].pack("C n a* a*")
    end

    def self.path_for(type: nil, zone: nil)
      params = {}
      params[:type] = type if type
      params[:zone] = zone if zone
      query = params.map { |k, v| "#{k}=#{v}" }.join("&")
      "/admin/records#{query.empty? ? "" : "?#{query}"}"
    end

    # HMAC headers for /admin/records (admin_api.ex verify_request). The
    # NS (config.ex) loads the secret as 32 raw bytes (used as-is) or 64-char
    # hex (decoded to 32 bytes); the HMAC key is the DECODED 32 raw bytes.
    # Mirror that: a 64-hex secret is decoded before keying the HMAC; any
    # other length is used verbatim (backwards-compat for raw/short secrets).
    def self.admin_headers(secret, ts, path)
      key = admin_secret_key(secret)
      canonical_str = "GET\n#{path}\n#{ts}\n" + Digest::SHA256.hexdigest("")
      sig = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("sha256"), key, canonical_str)
      { "x-ns-timestamp" => ts.to_s, "x-ns-signature" => sig }
    end

    # The HMAC key the NS actually uses for /admin/records: a 64-char hex
    # secret is decoded to its 32 raw bytes (ns/lib/ztlp_ns/config.ex loads
    # ZTLP_NS_ADMIN_API_SECRET exactly this way); other lengths pass through.
    def self.admin_secret_key(secret)
      secret.match?(/\A[0-9a-fA-F]{64}\z/) ? [ secret ].pack("H*") : secret
    end
    private_class_method :admin_secret_key

    # ── internals ──────────────────────────────────────────────────

    def self.require_type(type)
      TYPE_BYTES.fetch(type.to_s) { raise NsError.new(0x01, REASON_CODES[0x01]) }
    end

    def self.raw_pubkey(seed_hex)
      OpenSSL::PKey.new_raw_private_key("ED25519", [ seed_hex ].pack("H*")).raw_public_key
    end

    def self.send_one(ns_addr, timeout, packet, socket: nil)
      attempts = 0
      loop do
        attempts += 1
        sock = socket || open_socket(ns_addr, timeout)
        begin
          sock.send(packet, 0)
          return sock.recvfrom(MAX_REPLY).first
        rescue Errno::ECONNREFUSED
          sock.close if sock != socket
          raise NsError.new(0x0D, REASON_CODES[0x0D])
        rescue IO::TimeoutError, SocketError, SystemCallError
          # IO::TimeoutError (IO#timeout=, Ruby 3.2) is an IOError, not a SystemCallError.
          sock.close if sock != socket
          raise NsError.new(0x0C, REASON_CODES[0x0C]) if attempts >= 2
        end
      end
    end
    private_class_method :send_one

    def self.open_socket(ns_addr, timeout)
      host, port = ns_addr.split(":")
      UDPSocket.new.tap { |s| s.connect(host, port.to_i) }.tap { |s| s.timeout = timeout }
    rescue
      raise NsError.new(0x0D, REASON_CODES[0x0D])
    end
    private_class_method :open_socket

    # Parse a 0x02 reply: <<0x02, Record.encode>> (server.ex:185, record.ex:196) =
    # <<0x02, type::8, name_len::16, name, data_len::32, data, created_at::64,
    #   ttl::32, serial::64, sig_len::16, sig, pub_len::16, pub>>, all big-endian.
    def self.parse_record(reply)
      type_byte, name_len = reply.unpack("x C n")
      off = 4
      name = reply.byteslice(off, name_len)
      off += name_len
      data_len = reply.byteslice(off, 4).unpack1("N")
      off += 4
      data_bin = reply.byteslice(off, data_len)
      off += data_len
      tail = reply.byteslice(off, 20)
      raise ArgumentError, "truncated" if name.bytesize != name_len || data_bin.bytesize != data_len ||
                                          tail.nil? || tail.bytesize != 20

      created_at, ttl, serial = tail.unpack("Q> N Q>")
      { name: name.force_encoding(Encoding::UTF_8), type: TYPE_BYTES.key(type_byte).to_s,
        data: Cbor.decode(data_bin), created_at: created_at, ttl: ttl, serial: serial }
    rescue ArgumentError, NoMethodError, TypeError
      raise NsError.new(0x0A, REASON_CODES[0x0A])
    end
    private_class_method :parse_record

    def self.symbolize_record(hash)
      {
        name: hash["name"],
        type: hash["type"].to_s,
        data: hash.fetch("data", {}),
        created_at: hash["created_at"],
        ttl: hash["ttl"],
        serial: hash["serial"],
        pubkey_hex: hash["pubkey_hex"]
      }.compact
    end
    private_class_method :symbolize_record
  end
end
