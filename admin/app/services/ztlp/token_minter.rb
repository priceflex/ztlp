# frozen_string_literal: true

module Ztlp
  # Mints v1 binary enrollment tokens, byte-for-byte what proto/src/enrollment.rs
  # `serialize_without_mac` produces and ns/lib/ztlp_ns/enrollment.ex `parse_token` reads.
  # Held to the shared vector proto/tests/fixtures/enrollment_token_all_flags.hex.
  #
  #   version::8 (0x01)
  #   flags::8   0x01 gateway, 0x02 callback, 0x08 relay secret, 0x10 home NS public key
  #   zone_len::16 zone
  #   ns_len::16 ns_addr
  #   relay_count::8 [relay_len::16 relay] * relay_count
  #   [gw_len::16 gateway]          if flags & 0x01
  #   [cb_len::16 callback_url]     if flags & 0x02
  #   [rs_len::16 relay_secret]     if flags & 0x08  (ZT-01: `ztlp setup` writes it to agent.toml)
  #   [ns_key::32 raw]              if flags & 0x10  (NS-anchored trust: the device verifies NS answers
  #                                                   with it and takes the gateway cert pin from the
  #                                                   signed SVC record, so no first-use pins)
  #   max_uses::16
  #   expires_at::64 (unix seconds, big-endian)
  #   nonce::16
  #   mac::32 HMAC-BLAKE2s-256 over everything above, keyed with the
  #           32-byte zone enrollment secret (NS ZTLP_ENROLLMENT_SECRET).
  class TokenMinter
    class EnrollmentSecretMissing < StandardError; end
    class InvalidField < ArgumentError; end

    VERSION = 0x01
    FLAG_HAS_GATEWAY = 0x01
    FLAG_HAS_CALLBACK = 0x02
    FLAG_HAS_RELAY_SECRET = 0x08
    FLAG_HAS_NS_KEY = 0x10
    KNOWN_FLAGS = FLAG_HAS_GATEWAY | FLAG_HAS_CALLBACK | FLAG_HAS_RELAY_SECRET | FLAG_HAS_NS_KEY
    MAX_RELAY_SECRET_LEN = 256 # proto enrollment::MAX_RELAY_SECRET_LEN: longer tokens are rejected
    MAX_EXPIRY_SECONDS = 24 * 3600 # spec F8 / Slice 10: expiry at most 24h

    # Mint the binary token for `zone`.
    #
    # gateway_addr / callback_url are optional (flag bits 0x01 / 0x02);
    # relay addresses come from zone.relay_addrs (the NS relay set).
    # max_uses defaults to 1: today's tokens are single-use capabilities.
    # expires_at must be at most 24h out (enforcement is in 10b).
    def self.mint(zone, expires_at:, nonce: nil, max_uses: 1, gateway_addr: nil, callback_url: nil,
                  relay_secret: nil, ns_key_hex: nil)
      secret = [ zone.enrollment_secret_ct ].pack("H*")
      raise EnrollmentSecretMissing, "zone #{zone.name} has no enrollment secret" if secret.bytesize != 32

      nonce = SecureRandom.random_bytes(16) if nonce.nil?
      relay_secret = relay_secret.to_s.strip.presence
      if relay_secret && relay_secret.bytesize > MAX_RELAY_SECRET_LEN
        raise InvalidField, "relay secret is longer than #{MAX_RELAY_SECRET_LEN} bytes"
      end
      ns_key = ns_key_hex.to_s.strip.presence
      raise InvalidField, "NS key must be 64 hex characters" if ns_key && !ns_key.match?(/\A\h{64}\z/)

      flags = 0
      flags |= FLAG_HAS_GATEWAY if gateway_addr
      flags |= FLAG_HAS_CALLBACK if callback_url
      flags |= FLAG_HAS_RELAY_SECRET if relay_secret
      flags |= FLAG_HAS_NS_KEY if ns_key

      buf = +"".b
      buf << [ VERSION ].pack("C")
      buf << [ flags ].pack("C")
      write_len_prefixed(buf, zone.name)
      write_len_prefixed(buf, zone.ns_addr)
      relays = Array(zone.relay_addrs)
      buf << [ relays.length ].pack("C")
      relays.each { |r| write_len_prefixed(buf, r) }
      write_len_prefixed(buf, gateway_addr) if gateway_addr
      write_len_prefixed(buf, callback_url) if callback_url
      write_len_prefixed(buf, relay_secret) if relay_secret
      buf << [ ns_key ].pack("H*") if ns_key
      buf << [ max_uses.to_i.clamp(0, 65_535) ].pack("n")
      buf << [ expires_at.to_i ].pack("Q>")
      buf << nonce

      mac = Blake2sHmac.mac(secret, buf)
      buf << mac
      buf
    end

    # The `ztlp://enroll/<base64url>` URI form (Rust `to_uri`, base64url
    # no padding — `ztlp setup --token` accepts it directly).
    def self.to_uri(binary)
      "ztlp://enroll/#{Base64.urlsafe_encode64(binary, padding: false)}"
    end

    # Reverse of to_uri: accept a bare base64url string or the full URI.
    # .strip is Unicode-aware here to match the Rust consumer, which
    # std::str::trim's the input before decoding (Rust chars, not ASCII).
    # Padding is normalized manually: base64 gem 0.3's urlsafe_decode64
    # rejects unpadded input, but the Rust consumer accepts both padded and
    # unpadded, so the panel side must too.
    def self.from_uri(uri)
      b64 = uri.to_s.delete_prefix("ztlp://enroll/").strip
      b64 += "=" * (-b64.length % 4)
      Base64.urlsafe_decode64(b64)
    end

    # Read a binary token back (tests, and the operator's own checks). Raises InvalidField on a
    # truncated token or a flag this panel does not know. Does NOT check the MAC: see valid_mac?.
    def self.parse(bin)
      bin = bin.b
      pos = 0
      take = lambda do |n|
        raise InvalidField, "truncated token" if pos + n > bin.bytesize

        v = bin.byteslice(pos, n)
        pos += n
        v
      end
      str = -> { take.call(take.call(2).unpack1("n")).force_encoding(Encoding::UTF_8) }

      version, flags = take.call(2).unpack("CC")
      raise InvalidField, "unknown token flags 0x#{format('%02x', flags & ~KNOWN_FLAGS)}" if flags & ~KNOWN_FLAGS != 0

      t = { version: version, flags: flags, zone: str.call, ns_addr: str.call }
      t[:relay_addrs] = Array.new(take.call(1).unpack1("C")) { str.call }
      t[:gateway_addr] = flags & FLAG_HAS_GATEWAY != 0 ? str.call : nil
      t[:callback_url] = flags & FLAG_HAS_CALLBACK != 0 ? str.call : nil
      t[:relay_secret] = flags & FLAG_HAS_RELAY_SECRET != 0 ? str.call : nil
      t[:ns_key_hex] = flags & FLAG_HAS_NS_KEY != 0 ? take.call(32).unpack1("H*") : nil
      t[:max_uses] = take.call(2).unpack1("n")
      t[:expires_at] = take.call(8).unpack1("Q>")
      t[:nonce_hex] = take.call(16).unpack1("H*")
      take.call(32)
      raise InvalidField, "trailing bytes after the MAC" if pos != bin.bytesize

      t
    end

    def self.valid_mac?(bin, secret)
      bin = bin.b
      return false if bin.bytesize < 33

      data = bin.byteslice(0, bin.bytesize - 32)
      ActiveSupport::SecurityUtils.secure_compare(Blake2sHmac.mac(secret, data), bin.byteslice(-32, 32))
    end

    def self.write_len_prefixed(buf, value)
      bytes = value.to_s.b
      buf << [ bytes.bytesize ].pack("n") << bytes
    end
    private_class_method :write_len_prefixed
  end
end
