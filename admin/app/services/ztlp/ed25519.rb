# frozen_string_literal: true

require "openssl"
require "json"
require "digest"

module Ztlp
  # Ed25519 helpers for the claim and login flows (spec §4).
  #
  # Claim:  signature = Ed25519(sha256(canonical_json(body_without_signature)))
  # Login:  signature = Ed25519("ztlp-admin-login\n<host>\n<nonce>")
  module Ed25519
    HEX32 = /\A[0-9a-f]{64}\z/
    HEX64 = /\A[0-9a-f]{128}\z/

    module_function

    def valid_pubkey_hex?(hex)
      hex.is_a?(String) && hex.match?(HEX32)
    end

    def valid_signature_hex?(hex)
      hex.is_a?(String) && hex.match?(HEX64)
    end

    # Deterministic JSON: keys sorted, no whitespace. Values are not re-encoded
    # beyond what JSON.generate does, so integers stay integers.
    def canonical_json(hash)
      JSON.generate(deep_sort(hash))
    end

    def claim_message(body)
      Digest::SHA256.digest(canonical_json(body))
    end

    def login_message(host, nonce)
      "ztlp-admin-login\n#{host}\n#{nonce}"
    end

    # Returns true only if the signature verifies. Never raises on bad input.
    def verify(pubkey_hex:, message:, signature_hex:)
      return false unless valid_pubkey_hex?(pubkey_hex) && valid_signature_hex?(signature_hex)

      key = OpenSSL::PKey.new_raw_public_key("ED25519", [ pubkey_hex ].pack("H*"))
      key.verify(nil, [ signature_hex ].pack("H*"), message)
    rescue OpenSSL::PKey::PKeyError, ArgumentError
      false
    end

    # Test/dev helper. Returns [seed_hex(64), pubkey_hex(64)].
    def generate
      key = OpenSSL::PKey.generate_key("ED25519")
      [ key.raw_private_key.unpack1("H*"), key.raw_public_key.unpack1("H*") ]
    end

    def sign(seed_hex:, message:)
      key = OpenSSL::PKey.new_raw_private_key("ED25519", [ seed_hex ].pack("H*"))
      key.sign(nil, message).unpack1("H*")
    end

    def deep_sort(obj)
      case obj
      when Hash then obj.sort_by { |k, _| k.to_s }.to_h { |k, v| [ k.to_s, deep_sort(v) ] }
      when Array then obj.map { |v| deep_sort(v) }
      else obj
      end
    end
    private_class_method :deep_sort
  end
end
