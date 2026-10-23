# frozen_string_literal: true

module Ztlp
  # HMAC-BLAKE2s-256 for enrollment tokens (spec F8).
  #
  # Cross-checked live 2026-10-23 against the NS implementation (a running
  # ztlp-ns:v0.35.20 container evaluated hmac_blake2s/2 from
  # ns/lib/ztlp_ns/enrollment.ex — manual ipad/opad over the key zero-padded
  # to 64 bytes — on key = 32 x 0x42, data = "hello world"):
  #
  #   0128d0eb05c551a625495a3a946b57329aea31a6fc8845e1e54768dd3526e8c0
  #
  # identical to Ruby's OpenSSL::HMAC on the same vector, so this delegates.
  # The Rust CLI side (proto/src/admission.rs hmac_blake2s) is the same
  # construction (zero-pad to 64, then ipad/opad). OpenSSL::HMAC pads the
  # key to the digest's block size (64 for BLAKE2s) with zeros itself.
  class Blake2sHmac
    DIGEST = "BLAKE2s256"

    def self.mac(key, data)
      OpenSSL::HMAC.digest(OpenSSL::Digest.new(DIGEST), key, data)
    end
  end
end
