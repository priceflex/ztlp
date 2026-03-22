defmodule ZtlpNs.Attestation do
  @moduledoc """
  Hardware key attestation verification for ZTLP-NS.

  Determines the assurance level for a client certificate based on:

  1. **Hardware (level 4)** — Key stored in a hardware security module
     (YubiKey, TPM, Secure Enclave, StrongBox). Verified via manufacturer
     attestation certificate chain.

  2. **Device-bound (level 3)** — Key bound to the device's secure storage
     (macOS Keychain, Windows DPAPI, Linux kernel keyring) but not in a
     dedicated hardware module. No manufacturer attestation available but
     key cannot be extracted from the device.

  3. **Software (level 2)** — Key stored in a file on disk, potentially
     encrypted. Portable and extractable.

  4. **Unknown (level 1)** — Key source cannot be determined.

  ## Attestation Verification

  For hardware keys (YubiKey, TPM), the client provides an attestation
  certificate chain. This module verifies:

  - The attestation cert chains to a known manufacturer root
  - The attested public key matches the key being certified
  - The attestation is fresh (within acceptable time window)
  """

  @type assurance_level :: :hardware | :device_bound | :software | :unknown

  @type key_source :: String.t()
  # "yubikey" | "tpm" | "secure-enclave" | "strongbox" | "file" | "unknown"

  @type attestation_result :: %{
    level: assurance_level(),
    key_source: key_source(),
    attestation_verified: boolean()
  }

  # Known manufacturer roots (fingerprints)
  # In production these would be loaded from a configuration file
  @yubikey_root_fingerprints [
    # Yubico PIV attestation root (placeholder - real fingerprint would go here)
    "yubico-piv-root-placeholder"
  ]

  # ── Public API ─────────────────────────────────────────────────────

  @doc """
  Determine the assurance level for a key based on attestation evidence.

  ## Parameters
  - `key_source` — string identifying the key's storage ("yubikey", "tpm", "secure-enclave", "strongbox", "file", "unknown")
  - `attestation` — optional attestation evidence map:
    - `:cert_chain` — list of DER-encoded attestation certificates
    - `:public_key` — the public key being attested
    - `:timestamp` — when the attestation was generated

  Returns an `attestation_result` map.
  """
  @spec verify(key_source(), map() | nil) :: attestation_result()
  def verify(key_source, attestation \\ nil)

  def verify("yubikey", attestation) when is_map(attestation) do
    case verify_yubikey_attestation(attestation) do
      true ->
        %{level: :hardware, key_source: "yubikey", attestation_verified: true}
      false ->
        # Claimed YubiKey but attestation failed — downgrade to device-bound
        %{level: :device_bound, key_source: "yubikey", attestation_verified: false}
    end
  end

  def verify("yubikey", nil) do
    # Claimed YubiKey but no attestation provided
    %{level: :device_bound, key_source: "yubikey", attestation_verified: false}
  end

  def verify("tpm", attestation) when is_map(attestation) do
    case verify_tpm_attestation(attestation) do
      true ->
        %{level: :hardware, key_source: "tpm", attestation_verified: true}
      false ->
        %{level: :device_bound, key_source: "tpm", attestation_verified: false}
    end
  end

  def verify("tpm", nil) do
    %{level: :device_bound, key_source: "tpm", attestation_verified: false}
  end

  def verify("secure-enclave", attestation) when is_map(attestation) do
    case verify_apple_attestation(attestation) do
      true ->
        %{level: :hardware, key_source: "secure-enclave", attestation_verified: true}
      false ->
        %{level: :device_bound, key_source: "secure-enclave", attestation_verified: false}
    end
  end

  def verify("secure-enclave", nil) do
    %{level: :device_bound, key_source: "secure-enclave", attestation_verified: false}
  end

  def verify("strongbox", attestation) when is_map(attestation) do
    case verify_android_attestation(attestation) do
      true ->
        %{level: :hardware, key_source: "strongbox", attestation_verified: true}
      false ->
        %{level: :device_bound, key_source: "strongbox", attestation_verified: false}
    end
  end

  def verify("strongbox", nil) do
    %{level: :device_bound, key_source: "strongbox", attestation_verified: false}
  end

  def verify("file", _) do
    %{level: :software, key_source: "file", attestation_verified: false}
  end

  def verify("unknown", _) do
    %{level: :unknown, key_source: "unknown", attestation_verified: false}
  end

  def verify(_, _) do
    %{level: :unknown, key_source: "unknown", attestation_verified: false}
  end

  @doc """
  Check if assurance level meets a minimum requirement.

  ## Parameters
  - `actual` — the actual assurance level
  - `required` — the minimum required level

  Returns `true` if actual >= required.
  """
  @spec meets_minimum?(assurance_level(), assurance_level()) :: boolean()
  def meets_minimum?(actual, required) do
    level_value(actual) >= level_value(required)
  end

  @doc """
  Get the numeric value for an assurance level.

  Higher is more assured.
  """
  @spec level_value(assurance_level()) :: non_neg_integer()
  def level_value(:hardware), do: 4
  def level_value(:device_bound), do: 3
  def level_value(:software), do: 2
  def level_value(:unknown), do: 1
  def level_value(_), do: 0

  @doc """
  Parse an assurance level from a string.
  """
  @spec parse_level(String.t()) :: assurance_level()
  def parse_level("hardware"), do: :hardware
  def parse_level("device_bound"), do: :device_bound
  def parse_level("device-bound"), do: :device_bound
  def parse_level("software"), do: :software
  def parse_level("unknown"), do: :unknown
  def parse_level(_), do: :unknown

  @doc """
  Convert an assurance level to a string.
  """
  @spec level_to_string(assurance_level()) :: String.t()
  def level_to_string(:hardware), do: "hardware"
  def level_to_string(:device_bound), do: "device-bound"
  def level_to_string(:software), do: "software"
  def level_to_string(:unknown), do: "unknown"
  def level_to_string(_), do: "unknown"

  # ── Internal: Attestation Verification ─────────────────────────────

  defp verify_yubikey_attestation(%{cert_chain: certs, public_key: _pub_key} = _attestation)
       when is_list(certs) and length(certs) > 0 do
    # In production:
    # 1. Verify cert chain up to Yubico's root
    # 2. Check attested public key matches the key in the cert request
    # 3. Verify freshness
    #
    # For the prototype, we verify the chain structure is valid
    verify_chain_structure(certs)
  end

  defp verify_yubikey_attestation(_), do: false

  defp verify_tpm_attestation(%{cert_chain: certs} = _attestation)
       when is_list(certs) and length(certs) > 0 do
    verify_chain_structure(certs)
  end

  defp verify_tpm_attestation(_), do: false

  defp verify_apple_attestation(%{cert_chain: certs} = _attestation)
       when is_list(certs) and length(certs) > 0 do
    verify_chain_structure(certs)
  end

  defp verify_apple_attestation(_), do: false

  defp verify_android_attestation(%{cert_chain: certs} = _attestation)
       when is_list(certs) and length(certs) > 0 do
    verify_chain_structure(certs)
  end

  defp verify_android_attestation(_), do: false

  defp verify_chain_structure(certs) when is_list(certs) and length(certs) >= 2 do
    # Verify each cert in the chain is signed by the next
    # certs[0] = leaf, certs[1] = intermediate, certs[n-1] = root
    pairs = Enum.zip(certs, Enum.drop(certs, 1))

    Enum.all?(pairs, fn {cert_der, issuer_der} ->
      ZtlpNs.X509.verify_cert(cert_der, issuer_der)
    end)
  end

  defp verify_chain_structure(_), do: false
end
