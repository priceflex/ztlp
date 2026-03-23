defmodule ZtlpGateway.HeaderSigner do
  @moduledoc """
  HMAC-SHA256 header signing for ZTLP identity headers.

  Backend services can verify the authenticity of identity headers
  by checking the HMAC signature. The signing key is a shared secret
  between the gateway and backend services.

  ## Signed Headers

  The signature covers all X-ZTLP-* headers in a canonical format:
  - Headers sorted alphabetically by name
  - Each header as "name:value"
  - Joined with newlines
  - HMAC-SHA256 of the resulting string

  The signature is placed in the `X-ZTLP-Signature` header.
  """

  require Logger

  @doc """
  Sign identity headers with HMAC-SHA256.

  Returns the signature as a hex string.
  """
  @spec sign(list({String.t(), String.t()}), binary()) :: String.t()
  def sign(headers, secret) when is_binary(secret) do
    canonical = canonical_string(headers)

    # HMAC-SHA256
    :crypto.mac(:hmac, :sha256, secret, canonical)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Build the canonical string for signing from a list of headers.

  Collects all X-ZTLP-* headers (excluding X-ZTLP-Signature),
  sorts them alphabetically by lowercase name, and joins as
  "name:value" pairs separated by newlines.
  """
  @spec canonical_string(list({String.t(), String.t()})) :: String.t()
  def canonical_string(headers) do
    headers
    |> Enum.filter(fn {name, _} ->
      String.starts_with?(String.downcase(name), "x-ztlp-") and
        String.downcase(name) != "x-ztlp-signature"
    end)
    |> Enum.sort_by(fn {name, _} -> String.downcase(name) end)
    |> Enum.map(fn {name, value} -> "#{String.downcase(name)}:#{value}" end)
    |> Enum.join("\n")
  end

  @doc """
  Verify a header signature.

  Returns `true` if the signature matches.
  """
  @spec verify(list({String.t(), String.t()}), String.t(), binary()) :: boolean()
  def verify(headers, signature, secret) do
    expected = sign(headers, secret)
    # Constant-time comparison
    safe_compare(expected, signature)
  end

  @doc """
  Verify a header signature with timestamp expiry check.

  Extracts the `X-ZTLP-Timestamp` header, verifies the HMAC signature,
  and checks that the timestamp is within `max_age_seconds` of the current time.

  Returns:
  - `{:ok, :valid}` if signature matches and timestamp is fresh
  - `{:error, :invalid_signature}` if HMAC doesn't match
  - `{:error, :expired}` if timestamp is older than `max_age_seconds`
  - `{:error, :missing_timestamp}` if no timestamp header is found
  """
  @spec verify_with_timestamp(
          list({String.t(), String.t()}),
          String.t(),
          binary(),
          non_neg_integer()
        ) :: {:ok, :valid} | {:error, :invalid_signature | :expired | :missing_timestamp}
  def verify_with_timestamp(headers, signature, secret, max_age_seconds) do
    # First verify signature
    if verify(headers, signature, secret) do
      # Then check timestamp
      timestamp_value =
        Enum.find_value(headers, fn {name, value} ->
          if String.downcase(name) == "x-ztlp-timestamp", do: value
        end)

      case timestamp_value do
        nil ->
          {:error, :missing_timestamp}

        ts_string ->
          case DateTime.from_iso8601(ts_string) do
            {:ok, ts_dt, _offset} ->
              now = DateTime.utc_now()
              age_seconds = DateTime.diff(now, ts_dt, :second)

              if age_seconds <= max_age_seconds and age_seconds >= 0 do
                {:ok, :valid}
              else
                {:error, :expired}
              end

            {:error, _} ->
              {:error, :missing_timestamp}
          end
      end
    else
      {:error, :invalid_signature}
    end
  end

  @doc """
  Get the default signing secret from config.

  Returns the configured secret, or `nil` if no secret is configured.
  Tests that don't configure a secret will get `nil`, causing signing
  to be skipped (passthrough mode).
  """
  @spec default_secret() :: binary() | nil
  def default_secret do
    ZtlpGateway.Config.get(:header_signing_secret)
  end

  @doc """
  Validate that a real signing secret is configured.

  Called at startup. When header signing is enabled but no real secret
  is configured (or the secret equals the old default), logs a critical
  warning. Does NOT crash the application.
  """
  @spec validate_secret!() :: :ok
  def validate_secret! do
    signing_enabled = ZtlpGateway.Config.get(:header_signing_enabled)
    secret = ZtlpGateway.Config.get(:header_signing_secret)

    if signing_enabled do
      cond do
        is_nil(secret) ->
          Logger.critical(
            "[HeaderSigner] SECURITY WARNING: Header signing is enabled but no signing secret is configured. " <>
              "Set ZTLP_HEADER_HMAC_SECRET or :header_signing_secret in config. " <>
              "Headers will NOT be signed until a secret is configured."
          )

        secret == "ztlp-default-signing-secret" ->
          Logger.critical(
            "[HeaderSigner] SECURITY WARNING: Header signing is enabled but using the default " <>
              "signing secret. This is insecure — any attacker who reads the source code can " <>
              "forge signatures. Set a strong random secret via ZTLP_HEADER_HMAC_SECRET."
          )

        true ->
          Logger.info("[HeaderSigner] Header signing enabled with configured secret.")
      end
    else
      Logger.debug("[HeaderSigner] Header signing is disabled (passthrough mode).")
    end

    :ok
  end

  @doc """
  Check a nonce against the replay cache.

  Returns `:ok` if the nonce hasn't been seen, `{:error, :replayed}` if it has.
  Delegates to the NonceCache GenServer.
  """
  @spec check_nonce(String.t()) :: :ok | {:error, :replayed}
  def check_nonce(nonce) do
    ZtlpGateway.HeaderSigner.NonceCache.check_nonce(nonce)
  end

  # Constant-time string comparison to prevent timing attacks
  defp safe_compare(a, b) when byte_size(a) != byte_size(b), do: false

  defp safe_compare(a, b) do
    # XOR each byte and accumulate; result is 0 iff all bytes match
    a_bytes = :binary.bin_to_list(a)
    b_bytes = :binary.bin_to_list(b)

    result =
      Enum.zip(a_bytes, b_bytes)
      |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)

    result == 0
  end
end
