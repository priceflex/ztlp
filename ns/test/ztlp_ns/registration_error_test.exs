defmodule ZtlpNs.RegistrationErrorTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.RegistrationError

  describe "encode/1" do
    test "encodes :unspecified to <<0xFF, 0x00>>" do
      assert RegistrationError.encode(:unspecified) == <<0xFF, 0x00>>
    end

    test "encodes :unknown_type to <<0xFF, 0x01>>" do
      assert RegistrationError.encode(:unknown_type) == <<0xFF, 0x01>>
    end

    test "encodes :missing_pubkey to <<0xFF, 0x02>>" do
      assert RegistrationError.encode(:missing_pubkey) == <<0xFF, 0x02>>
    end

    test "encodes :invalid_name to <<0xFF, 0x03>>" do
      assert RegistrationError.encode(:invalid_name) == <<0xFF, 0x03>>
    end

    test "encodes :invalid_signature to <<0xFF, 0x04>>" do
      assert RegistrationError.encode(:invalid_signature) == <<0xFF, 0x04>>
    end

    test "encodes :unauthorized to <<0xFF, 0x05>>" do
      assert RegistrationError.encode(:unauthorized) == <<0xFF, 0x05>>
    end

    test "encodes :key_overwrite to <<0xFF, 0x06>>" do
      assert RegistrationError.encode(:key_overwrite) == <<0xFF, 0x06>>
    end

    test "encodes :revoked_pubkey to <<0xFF, 0x07>>" do
      assert RegistrationError.encode(:revoked_pubkey) == <<0xFF, 0x07>>
    end

    test "encodes :revoked_name to <<0xFF, 0x08>>" do
      assert RegistrationError.encode(:revoked_name) == <<0xFF, 0x08>>
    end

    test "encodes :rate_limited to <<0xFF, 0x09>>" do
      assert RegistrationError.encode(:rate_limited) == <<0xFF, 0x09>>
    end

    test "encodes :invalid_data to <<0xFF, 0x0A>>" do
      assert RegistrationError.encode(:invalid_data) == <<0xFF, 0x0A>>
    end

    test "encodes :storage_error to <<0xFF, 0x0B>>" do
      assert RegistrationError.encode(:storage_error) == <<0xFF, 0x0B>>
    end

    test "unknown atoms fall back to :unspecified" do
      assert RegistrationError.encode(:something_new) == <<0xFF, 0x00>>
      assert RegistrationError.encode(:_unknown_reason_) == <<0xFF, 0x00>>
    end
  end

  describe "code_to_reason/1 / reason_to_code/1 round-trip" do
    test "all known reasons round-trip cleanly" do
      reasons = [
        :unspecified,
        :unknown_type,
        :missing_pubkey,
        :invalid_name,
        :invalid_signature,
        :unauthorized,
        :key_overwrite,
        :revoked_pubkey,
        :revoked_name,
        :rate_limited,
        :invalid_data,
        :storage_error
      ]

      for reason <- reasons do
        code = RegistrationError.reason_to_code(reason)
        assert RegistrationError.code_to_reason(code) == reason,
               "round-trip failed for #{inspect(reason)} (code 0x#{Integer.to_string(code, 16)})"
      end
    end

    test "unknown codes decode to :unspecified" do
      assert RegistrationError.code_to_reason(0xFE) == :unspecified
      assert RegistrationError.code_to_reason(0x42) == :unspecified
    end
  end

  describe "from_internal/1 maps NS-internal reasons to wire codes" do
    test "name-validation reasons → :invalid_name" do
      assert RegistrationError.from_internal(:invalid_name) == :invalid_name
      assert RegistrationError.from_internal(:invalid_suffix) == :invalid_name
      assert RegistrationError.from_internal(:name_too_long) == :invalid_name
      assert RegistrationError.from_internal(:invalid_characters) == :invalid_name
    end

    test "signature reasons → :invalid_signature" do
      assert RegistrationError.from_internal(:bad_signature) == :invalid_signature
      assert RegistrationError.from_internal(:signature_verification_failed) == :invalid_signature
    end

    test "authorization reasons → :unauthorized" do
      assert RegistrationError.from_internal(:not_in_zone) == :unauthorized
      assert RegistrationError.from_internal(:zone_not_allowed) == :unauthorized
      assert RegistrationError.from_internal(:wrong_zone) == :unauthorized
    end

    test "key-overwrite reasons → :key_overwrite" do
      assert RegistrationError.from_internal(:key_overwrite_rejected) == :key_overwrite
      assert RegistrationError.from_internal(:name_taken) == :key_overwrite
      assert RegistrationError.from_internal(:owned_by_different_key) == :key_overwrite
    end

    test "revocation reasons → :revoked_pubkey or :revoked_name" do
      assert RegistrationError.from_internal(:pubkey_revoked) == :revoked_pubkey
      assert RegistrationError.from_internal(:nodeid_revoked) == :revoked_pubkey
      assert RegistrationError.from_internal(:name_revoked) == :revoked_name
    end

    test "rate-limit reasons → :rate_limited" do
      assert RegistrationError.from_internal(:rate_limited) == :rate_limited
      assert RegistrationError.from_internal(:too_many_registrations) == :rate_limited
    end

    test "data-validation reasons → :invalid_data" do
      assert RegistrationError.from_internal(:cbor_decode_failed) == :invalid_data
      assert RegistrationError.from_internal(:missing_required_field) == :invalid_data
    end

    test "storage reasons → :storage_error" do
      assert RegistrationError.from_internal(:stale_serial) == :storage_error
      assert RegistrationError.from_internal(:mnesia_aborted) == :storage_error
    end

    test "unmapped reasons fall back to :unspecified" do
      assert RegistrationError.from_internal(:totally_made_up) == :unspecified
      assert RegistrationError.from_internal(:_) == :unspecified
    end
  end

  describe "wire compatibility" do
    test "encoded byte 0 is always 0xFF (backward compat with old clients)" do
      for reason <- [:unspecified, :rate_limited, :key_overwrite, :invalid_signature] do
        <<first_byte, _rest>> = RegistrationError.encode(reason)
        assert first_byte == 0xFF,
               "byte 0 must be 0xFF for #{inspect(reason)} to keep old clients happy"
      end
    end

    test "encoded response is exactly 2 bytes" do
      for reason <- [:unspecified, :rate_limited, :key_overwrite] do
        encoded = RegistrationError.encode(reason)
        assert byte_size(encoded) == 2,
               "encoded response must be 2 bytes for #{inspect(reason)}"
      end
    end
  end
end
