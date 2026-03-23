defmodule ZtlpGateway.HeaderVerifier do
  @moduledoc """
  Self-contained verification module for ZTLP identity headers.

  Backend services (Rails, Go, Python, etc.) can use this module as a
  reference implementation for verifying ZTLP headers injected by the
  gateway.

  ## Usage

      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Node-Name", "node1.corp.ztlp"},
        {"X-ZTLP-Authenticated", "true"},
        {"X-ZTLP-Timestamp", "2025-01-01T00:00:00Z"},
        {"X-ZTLP-Nonce", "deadbeef01234567deadbeef01234567"},
        {"X-ZTLP-Request-ID", "550e8400-e29b-41d4-a716-446655440000"},
        {"X-ZTLP-Signature", "abc123..."}
      ]

      case ZtlpGateway.HeaderVerifier.verify_request(headers, secret: "my-secret") do
        {:ok, identity} ->
          # identity is a map of all X-ZTLP-* header values
          IO.inspect(identity)

        {:error, reason} ->
          # reason: :invalid_signature, :expired, :missing_timestamp,
          #         :missing_signature, :replayed
          IO.inspect(reason)
      end

  ## Porting Guide

  To port this to another language:

  1. Collect all `X-ZTLP-*` headers except `X-ZTLP-Signature`
  2. Sort by lowercase header name
  3. Build canonical string: `"name:value"` joined by `"\\n"`
  4. HMAC-SHA256 with the shared secret
  5. Hex-encode (lowercase) and compare to `X-ZTLP-Signature`
  6. Optionally check timestamp expiry and nonce replay
  """

  @doc """
  Verify a set of HTTP headers from the gateway.

  ## Parameters
  - `headers` — list of `{name, value}` tuples (raw HTTP headers)
  - `opts` — keyword list:
    - `:secret` — (required) the shared HMAC signing secret
    - `:max_age_seconds` — (optional) reject headers older than this (default: 60)
    - `:check_nonce` — (optional) check nonce replay (default: false)

  ## Returns
  - `{:ok, identity_map}` — verification passed; identity_map contains
    all X-ZTLP-* header values as a map
  - `{:error, reason}` — verification failed
    - `:missing_signature` — no X-ZTLP-Signature header found
    - `:invalid_signature` — HMAC doesn't match
    - `:missing_timestamp` — no X-ZTLP-Timestamp header found
    - `:expired` — timestamp is older than `max_age_seconds`
    - `:replayed` — nonce has been seen before
  """
  @spec verify_request(list({String.t(), String.t()}), keyword()) ::
          {:ok, map()} | {:error, atom()}
  def verify_request(headers, opts) do
    secret = Keyword.fetch!(opts, :secret)
    max_age = Keyword.get(opts, :max_age_seconds, 60)
    check_nonce? = Keyword.get(opts, :check_nonce, false)

    # Extract all X-ZTLP-* headers
    ztlp_headers =
      Enum.filter(headers, fn {name, _} ->
        String.starts_with?(String.downcase(name), "x-ztlp-")
      end)

    # Extract the signature
    signature =
      Enum.find_value(ztlp_headers, fn {name, value} ->
        if String.downcase(name) == "x-ztlp-signature", do: value
      end)

    if is_nil(signature) do
      {:error, :missing_signature}
    else
      # Headers for signing (everything except signature)
      signing_headers =
        Enum.reject(ztlp_headers, fn {name, _} ->
          String.downcase(name) == "x-ztlp-signature"
        end)

      # Verify HMAC
      with {:ok, :valid} <- verify_hmac(signing_headers, signature, secret),
           :ok <- verify_timestamp(signing_headers, max_age),
           :ok <- verify_nonce(signing_headers, check_nonce?) do
        # Build identity map from headers
        identity =
          ztlp_headers
          |> Enum.reject(fn {name, _} -> String.downcase(name) == "x-ztlp-signature" end)
          |> Enum.map(fn {name, value} ->
            # Strip "X-ZTLP-" prefix and normalize
            key =
              name
              |> String.replace_leading("X-ZTLP-", "")
              |> String.replace_leading("x-ztlp-", "")
              |> String.downcase()
              |> String.replace("-", "_")

            {key, value}
          end)
          |> Map.new()

        {:ok, identity}
      end
    end
  end

  # Verify HMAC-SHA256 signature
  defp verify_hmac(headers, signature, secret) do
    expected = ZtlpGateway.HeaderSigner.sign(headers, secret)

    if safe_compare(expected, signature) do
      {:ok, :valid}
    else
      {:error, :invalid_signature}
    end
  end

  # Check timestamp expiry
  defp verify_timestamp(headers, max_age) do
    timestamp =
      Enum.find_value(headers, fn {name, value} ->
        if String.downcase(name) == "x-ztlp-timestamp", do: value
      end)

    case timestamp do
      nil ->
        {:error, :missing_timestamp}

      ts_string ->
        case DateTime.from_iso8601(ts_string) do
          {:ok, ts_dt, _offset} ->
            now = DateTime.utc_now()
            age = DateTime.diff(now, ts_dt, :second)

            if age <= max_age and age >= 0 do
              :ok
            else
              {:error, :expired}
            end

          {:error, _} ->
            {:error, :missing_timestamp}
        end
    end
  end

  # Check nonce replay (if enabled)
  defp verify_nonce(_headers, false), do: :ok

  defp verify_nonce(headers, true) do
    nonce =
      Enum.find_value(headers, fn {name, value} ->
        if String.downcase(name) == "x-ztlp-nonce", do: value
      end)

    case nonce do
      nil ->
        # No nonce header — skip check (backwards compatibility)
        :ok

      nonce_value ->
        ZtlpGateway.HeaderSigner.check_nonce(nonce_value)
    end
  end

  # Constant-time string comparison to prevent timing attacks
  defp safe_compare(a, b) when byte_size(a) != byte_size(b), do: false

  defp safe_compare(a, b) do
    a_bytes = :binary.bin_to_list(a)
    b_bytes = :binary.bin_to_list(b)

    result =
      Enum.zip(a_bytes, b_bytes)
      |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)

    result == 0
  end
end
