# frozen_string_literal: true

module Ztlp
  # Device-identity assurance levels (spec §5, ztlp-cli.rs cbor_extract_string
  # "assurance"). Ordered floor for the mandatory gateway gate
  # (ZTLP_MIN_ASSURANCE) and the device list.
  class Assurance
    LEVELS = { "unknown" => 1, "software" => 2, "device-bound" => 3, "device_bound" => 3, "hardware" => 4 }.freeze
    MAX_LEVEL = 4

    # 4 = "hardware" but until attestation is verified (ATTESTATION_VERIFIED=1)
    # it is presented as unverified.
    def self.label(level)
      case level.to_i
      when 1 then "unknown"
      when 2 then "software"
      when 3 then "device-bound"
      when 4 then attested? ? "hardware" : "hardware (unverified)"
      else "unknown"
      end
    end

    def self.level(value)
      LEVELS.fetch(value.to_s, 1)
    end

    def self.attested? = ENV["ATTESTATION_VERIFIED"] == "1"

    # Device records carry one of these (spec §2.2 devices.key_source).
    KEY_SOURCES = %w[yubikey tpm secure-enclave strongbox file unknown].freeze
  end
end
