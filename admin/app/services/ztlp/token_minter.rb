# frozen_string_literal: true

module Ztlp
  # Mints v1 binary enrollment tokens (spec F8, current format — no identity
  # flag yet; the identity-carrying 0x08 flag is a later ZTLP release).
  #
  # Wire layout, byte-for-byte from proto/src/enrollment.rs
  # `serialize_without_mac` and ns/lib/ztlp_ns/enrollment.ex `parse_token`
  # (read from /home/trs/ztlp HEAD; do not re-research):
  #
  #   version::8 (0x01)
  #   flags::8   (bit 0 = has gateway, bit 1 = has callback)
  #   zone_len::16 zone
  #   ns_len::16 ns_addr
  #   relay_count::8 [relay_len::16 relay] * relay_count
  #   [gw_len::16 gateway]         if flags & 0x01
  #   [cb_len::16 callback_url]    if flags & 0x02
  #   max_uses::16
  #   expires_at::64 (unix seconds, big-endian)
  #   nonce::16
  #   mac::32 HMAC-BLAKE2s-256 over everything above, keyed with the
  #           32-byte zone enrollment secret (NS ZTLP_ENROLLMENT_SECRET).
  class TokenMinter
    class EnrollmentSecretMissing < StandardError; end

    VERSION = 0x01
    FLAG_HAS_GATEWAY = 0x01
    FLAG_HAS_CALLBACK = 0x02
    MAX_EXPIRY_SECONDS = 24 * 3600 # spec F8 / Slice 10: expiry at most 24h

    # Mint the binary token for `zone`.
    #
    # gateway_addr / callback_url are optional (flag bits 0x01 / 0x02);
    # relay addresses come from zone.relay_addrs (the NS relay set).
    # max_uses defaults to 1: today's tokens are single-use capabilities.
    # expires_at must be at most 24h out (enforcement is in 10b).
    def self.mint(zone, expires_at:, nonce: nil, max_uses: 1, gateway_addr: nil, callback_url: nil)
      secret = [ zone.enrollment_secret_ct ].pack("H*")
      raise EnrollmentSecretMissing, "zone #{zone.name} has no enrollment secret" if secret.bytesize != 32

      nonce = SecureRandom.random_bytes(16) if nonce.nil?

      flags = 0
      flags |= FLAG_HAS_GATEWAY if gateway_addr
      flags |= FLAG_HAS_CALLBACK if callback_url

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

    def self.write_len_prefixed(buf, value)
      bytes = value.to_s.b
      buf << [ bytes.bytesize ].pack("n") << bytes
    end
    private_class_method :write_len_prefixed
  end
end
