defmodule ZtlpNs.RegistrationError do
  @moduledoc """
  Reason codes returned in the second byte of registration error responses.

  Wire format: `<<0xFF, reason_code::8>>`

  ## Backward compatibility

  Pre-v0.34 clients only inspect the first byte (`0xFF`) and ignore the
  rest. They continue to receive an opaque "rejected" signal exactly as
  before. New clients that parse the second byte get a granular reason
  they can use to drive backoff / retry / give-up logic.

  ## Reason codes

  | Code | Symbol              | Meaning                                                          |
  |------|---------------------|------------------------------------------------------------------|
  | 0x00 | `:unspecified`      | Catch-all when no specific code applies                          |
  | 0x01 | `:unknown_type`     | Record type byte not in the known type enum                      |
  | 0x02 | `:missing_pubkey`   | Used v1 (0x09) registration in prod where v2 (0x0A) is required  |
  | 0x03 | `:invalid_name`     | Name validation failed (suffix mismatch, format invalid)         |
  | 0x04 | `:invalid_signature`| Ed25519 signature verification failed                            |
  | 0x05 | `:unauthorized`     | Pubkey not allowed to register this name/type (zone auth)        |
  | 0x06 | `:key_overwrite`    | Another pubkey already owns this name (DEVICE/USER protection)   |
  | 0x07 | `:revoked_pubkey`   | The pubkey or its NodeID has been revoked                        |
  | 0x08 | `:revoked_name`     | The name itself has been revoked                                 |
  | 0x09 | `:rate_limited`     | Hit the per-name registration rate limit                         |
  | 0x0A | `:invalid_data`     | CBOR decode failed or type-specific field validation failed      |
  | 0x0B | `:storage_error`    | Mnesia / Store.insert failed (stale_serial retry exhausted)      |

  Reserve `0xFC..0xFF` for future use. New codes must be appended (never
  renumbered) to preserve wire compatibility across mixed-version fleets.
  """

  @type reason ::
          :unspecified
          | :unknown_type
          | :missing_pubkey
          | :invalid_name
          | :invalid_signature
          | :unauthorized
          | :key_overwrite
          | :revoked_pubkey
          | :revoked_name
          | :rate_limited
          | :invalid_data
          | :storage_error

  @doc """
  Encode a registration error reason as a 2-byte response (`<<0xFF, code>>`).

  Atoms not in the known set fall back to `:unspecified` (0x00).
  """
  @spec encode(reason() | atom()) :: binary()
  def encode(reason) do
    <<0xFF, reason_to_code(reason)::8>>
  end

  @doc """
  Map a reason atom to its numeric code.
  """
  @spec reason_to_code(reason() | atom()) :: byte()
  def reason_to_code(:unspecified), do: 0x00
  def reason_to_code(:unknown_type), do: 0x01
  def reason_to_code(:missing_pubkey), do: 0x02
  def reason_to_code(:invalid_name), do: 0x03
  def reason_to_code(:invalid_signature), do: 0x04
  def reason_to_code(:unauthorized), do: 0x05
  def reason_to_code(:key_overwrite), do: 0x06
  def reason_to_code(:revoked_pubkey), do: 0x07
  def reason_to_code(:revoked_name), do: 0x08
  def reason_to_code(:rate_limited), do: 0x09
  def reason_to_code(:invalid_data), do: 0x0A
  def reason_to_code(:storage_error), do: 0x0B

  # Unknown reasons → unspecified. Keeps the wire path safe even if a
  # rejection path picks up a new atom we haven't enumerated here.
  def reason_to_code(_other), do: 0x00

  @doc """
  Map a numeric code back to its reason atom. Used by tests and the
  Rust CLI parser via interop testing.
  """
  @spec code_to_reason(byte()) :: reason()
  def code_to_reason(0x00), do: :unspecified
  def code_to_reason(0x01), do: :unknown_type
  def code_to_reason(0x02), do: :missing_pubkey
  def code_to_reason(0x03), do: :invalid_name
  def code_to_reason(0x04), do: :invalid_signature
  def code_to_reason(0x05), do: :unauthorized
  def code_to_reason(0x06), do: :key_overwrite
  def code_to_reason(0x07), do: :revoked_pubkey
  def code_to_reason(0x08), do: :revoked_name
  def code_to_reason(0x09), do: :rate_limited
  def code_to_reason(0x0A), do: :invalid_data
  def code_to_reason(0x0B), do: :storage_error
  def code_to_reason(_), do: :unspecified

  @doc """
  Map an internal error atom (as produced by RegistrationAuth, Store, etc.)
  to its corresponding registration error reason.

  This is the bridge between internal error vocabulary and the wire-level
  reason codes. New internal errors should be added here so they get
  encoded correctly rather than falling back to `:unspecified`.
  """
  @spec from_internal(atom()) :: reason()
  def from_internal(:unknown_type), do: :unknown_type
  def from_internal(:missing_pubkey), do: :missing_pubkey

  # NameValidator failures
  def from_internal(:invalid_name), do: :invalid_name
  def from_internal(:invalid_suffix), do: :invalid_name
  def from_internal(:name_too_long), do: :invalid_name
  def from_internal(:name_too_short), do: :invalid_name
  def from_internal(:invalid_characters), do: :invalid_name

  # RegistrationAuth signature failures
  def from_internal(:bad_signature), do: :invalid_signature
  def from_internal(:invalid_signature), do: :invalid_signature
  def from_internal(:signature_verification_failed), do: :invalid_signature

  # Authorization failures
  def from_internal(:unauthorized), do: :unauthorized
  def from_internal(:not_in_zone), do: :unauthorized
  def from_internal(:zone_not_allowed), do: :unauthorized
  def from_internal(:wrong_zone), do: :unauthorized

  # Key overwrite protection
  def from_internal(:key_overwrite_rejected), do: :key_overwrite
  def from_internal(:name_taken), do: :key_overwrite
  def from_internal(:owned_by_different_key), do: :key_overwrite

  # Revocation
  def from_internal(:pubkey_revoked), do: :revoked_pubkey
  def from_internal(:nodeid_revoked), do: :revoked_pubkey
  def from_internal(:revoked), do: :revoked_pubkey
  def from_internal(:name_revoked), do: :revoked_name

  # Rate limit
  def from_internal(:rate_limited), do: :rate_limited
  def from_internal(:too_many_registrations), do: :rate_limited

  # Data validation
  def from_internal(:invalid_data), do: :invalid_data
  def from_internal(:cbor_decode_failed), do: :invalid_data
  def from_internal(:invalid_record_data), do: :invalid_data
  def from_internal(:missing_required_field), do: :invalid_data

  # Storage
  def from_internal(:stale_serial), do: :storage_error
  def from_internal(:mnesia_aborted), do: :storage_error
  def from_internal(:storage_error), do: :storage_error

  def from_internal(_other), do: :unspecified
end
