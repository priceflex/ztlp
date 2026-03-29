defmodule ZtlpGateway.Attestation do
  @moduledoc """
  Device attestation verification for ZTLP enrollment.

  Supports:
  - Apple App Attest (iOS 14+, macOS 14+)
  - Android Key Attestation (StrongBox/TEE)
  - YubiKey attestation certificates
  - Software attestation (fallback, lower trust)

  Each attestation type produces a trust level:
  - :hardware — Key stored in Secure Enclave/StrongBox/YubiKey
  - :tee — Key in TEE (Trusted Execution Environment)
  - :software — Key in software keystore
  - :none — No attestation provided
  """

  require Logger

  @type trust_level :: :hardware | :tee | :software | :none
  @type attestation_result ::
          {:ok,
           %{
             trust_level: trust_level(),
             device_type: String.t(),
             key_id: binary(),
             details: map()
           }}
          | {:error, term()}

  @doc """
  Verify an attestation statement.

  ## Parameters
  - `type` — :apple | :android | :yubikey | :software
  - `attestation_data` — binary attestation statement
  - `challenge` — the challenge nonce that was sent to the device
  - `opts` — verification options
  """
  @spec verify(atom(), binary(), binary(), keyword()) :: attestation_result()
  def verify(type, attestation_data, challenge, opts \\ [])

  def verify(:apple, attestation_data, challenge, opts) do
    verify_apple_attestation(attestation_data, challenge, opts)
  end

  def verify(:android, attestation_data, challenge, opts) do
    verify_android_attestation(attestation_data, challenge, opts)
  end

  def verify(:yubikey, attestation_data, challenge, opts) do
    verify_yubikey_attestation(attestation_data, challenge, opts)
  end

  def verify(:software, attestation_data, challenge, _opts) do
    verify_software_attestation(attestation_data, challenge)
  end

  def verify(unknown, _data, _challenge, _opts) do
    {:error, {:unknown_attestation_type, unknown}}
  end

  @doc """
  Generate a random challenge nonce for attestation.
  """
  @spec generate_challenge() :: binary()
  def generate_challenge do
    :crypto.strong_rand_bytes(32)
  end

  @doc """
  Get minimum trust level from config.
  Returns :none by default (accept all devices).
  """
  @spec minimum_trust_level() :: trust_level()
  def minimum_trust_level do
    case System.get_env("ZTLP_MIN_ATTESTATION_LEVEL") do
      "hardware" -> :hardware
      "tee" -> :tee
      "software" -> :software
      _ -> :none
    end
  end

  @doc """
  Check if a trust level meets the minimum requirement.
  """
  @spec meets_minimum?(trust_level()) :: boolean()
  def meets_minimum?(level) do
    trust_order = %{hardware: 3, tee: 2, software: 1, none: 0}
    min_level = minimum_trust_level()
    Map.get(trust_order, level, 0) >= Map.get(trust_order, min_level, 0)
  end

  ## Apple App Attest

  defp verify_apple_attestation(attestation_data, challenge, opts) do
    # Apple App Attest uses CBOR-encoded attestation objects
    # containing x5c certificate chain and authenticator data
    #
    # Verification steps:
    # 1. Parse CBOR attestation object
    # 2. Extract certificate chain (x5c)
    # 3. Verify chain roots to Apple App Attest CA
    # 4. Verify authenticator data contains SHA256(challenge)
    # 5. Extract key ID from credential certificate

    with {:ok, parsed} <- parse_cbor_attestation(attestation_data),
         {:ok, cert_chain} <- extract_x5c_chain(parsed),
         :ok <- verify_apple_cert_chain(cert_chain, opts),
         {:ok, auth_data} <- extract_auth_data(parsed),
         :ok <- verify_challenge_hash(auth_data, challenge),
         {:ok, key_id} <- extract_apple_key_id(cert_chain) do
      prefix = key_id |> Base.encode16(case: :lower) |> binary_part(0, 16)
      Logger.info("[Attestation] Apple attestation verified, key_id=#{prefix}...")

      {:ok,
       %{
         trust_level: :hardware,
         device_type: "apple",
         key_id: key_id,
         details: %{
           format: "apple-appattest",
           cert_count: length(cert_chain)
         }
       }}
    else
      {:error, reason} = err ->
        Logger.warning("[Attestation] Apple attestation failed: #{inspect(reason)}")
        err
    end
  end

  ## Android Key Attestation

  defp verify_android_attestation(attestation_data, challenge, _opts) do
    # Android Key Attestation uses X.509 certificate chain
    # with attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
    #
    # Verification steps:
    # 1. Parse X.509 certificate chain
    # 2. Verify chain roots to Google root CA
    # 3. Parse attestation extension
    # 4. Verify challenge matches
    # 5. Determine security level (StrongBox > TEE > Software)

    with {:ok, certs} <- parse_x509_chain(attestation_data),
         {:ok, attestation_ext} <- extract_android_attestation_ext(certs),
         :ok <- verify_android_challenge(attestation_ext, challenge),
         {:ok, security_level} <- extract_android_security_level(attestation_ext) do
      key_id = :crypto.hash(:sha256, attestation_data)

      trust =
        case security_level do
          :strong_box -> :hardware
          :tee -> :tee
          _ -> :software
        end

      Logger.info("[Attestation] Android attestation verified, level=#{security_level}")

      {:ok,
       %{
         trust_level: trust,
         device_type: "android",
         key_id: key_id,
         details: %{
           format: "android-key",
           security_level: security_level
         }
       }}
    else
      {:error, reason} = err ->
        Logger.warning("[Attestation] Android attestation failed: #{inspect(reason)}")
        err
    end
  end

  ## YubiKey Attestation

  defp verify_yubikey_attestation(attestation_data, challenge, _opts) do
    # YubiKey attestation provides a certificate chain
    # proving the key was generated on a YubiKey
    #
    # Verification:
    # 1. Parse attestation cert + intermediate
    # 2. Verify chain to Yubico root CA
    # 3. Extract serial number and firmware version
    # 4. Verify challenge binding

    with {:ok, certs} <- parse_x509_chain(attestation_data),
         :ok <- verify_yubikey_chain(certs),
         {:ok, serial} <- extract_yubikey_serial(certs),
         :ok <- verify_yubikey_challenge(certs, challenge) do
      key_id = :crypto.hash(:sha256, attestation_data)

      Logger.info("[Attestation] YubiKey attestation verified, serial=#{serial}")

      {:ok,
       %{
         trust_level: :hardware,
         device_type: "yubikey",
         key_id: key_id,
         details: %{
           format: "yubikey",
           serial: serial
         }
       }}
    else
      {:error, reason} = err ->
        Logger.warning("[Attestation] YubiKey attestation failed: #{inspect(reason)}")
        err
    end
  end

  ## Software Attestation (Fallback)

  defp verify_software_attestation(attestation_data, challenge) do
    # Software attestation: client signs the challenge with its key
    # No hardware guarantees, but proves key possession
    #
    # Expected format: <<public_key::binary-32, signature::binary-64>>
    case attestation_data do
      <<public_key::binary-32, signature::binary-64>> ->
        case :crypto.verify(:eddsa, :none, challenge, signature, [public_key, :ed25519]) do
          true ->
            key_id = :crypto.hash(:sha256, public_key)

            {:ok,
             %{
               trust_level: :software,
               device_type: "software",
               key_id: key_id,
               details: %{format: "ed25519-software"}
             }}

          false ->
            {:error, :invalid_signature}
        end

      _ ->
        {:error, :invalid_attestation_format}
    end
  end

  ## Parsers (stubs — full implementations need ASN.1/CBOR libraries)
  ## These provide the structure; actual platform-specific parsing
  ## would be implemented when integrating with real devices.

  defp parse_cbor_attestation(_data) do
    {:error, :cbor_not_implemented}
  end

  defp extract_x5c_chain(_parsed) do
    {:error, :not_implemented}
  end

  defp verify_apple_cert_chain(_chain, _opts) do
    {:error, :not_implemented}
  end

  defp extract_auth_data(_parsed) do
    {:error, :not_implemented}
  end

  defp verify_challenge_hash(_auth_data, _challenge) do
    {:error, :not_implemented}
  end

  defp extract_apple_key_id(_chain) do
    {:error, :not_implemented}
  end

  defp parse_x509_chain(_data) do
    {:error, :x509_not_implemented}
  end

  defp extract_android_attestation_ext(_certs) do
    {:error, :not_implemented}
  end

  defp verify_android_challenge(_ext, _challenge) do
    {:error, :not_implemented}
  end

  defp extract_android_security_level(_ext) do
    {:error, :not_implemented}
  end

  defp verify_yubikey_chain(_certs) do
    {:error, :not_implemented}
  end

  defp extract_yubikey_serial(_certs) do
    {:error, :not_implemented}
  end

  defp verify_yubikey_challenge(_certs, _challenge) do
    {:error, :not_implemented}
  end
end
