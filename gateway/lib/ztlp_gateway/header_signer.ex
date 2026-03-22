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

  @doc """
  Sign identity headers with HMAC-SHA256.

  Returns the signature as a hex string.
  """
  @spec sign(list({String.t(), String.t()}), binary()) :: String.t()
  def sign(headers, secret) when is_binary(secret) do
    # Collect and sort ZTLP headers
    ztlp_headers = headers
      |> Enum.filter(fn {name, _} ->
        String.starts_with?(String.downcase(name), "x-ztlp-") and
        String.downcase(name) != "x-ztlp-signature"
      end)
      |> Enum.sort_by(fn {name, _} -> String.downcase(name) end)

    # Build canonical string
    canonical = ztlp_headers
      |> Enum.map(fn {name, value} -> "#{String.downcase(name)}:#{value}" end)
      |> Enum.join("\n")

    # HMAC-SHA256
    :crypto.mac(:hmac, :sha256, secret, canonical)
    |> Base.encode16(case: :lower)
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
  Get the default signing secret from config.
  """
  @spec default_secret() :: binary()
  def default_secret do
    Application.get_env(:ztlp_gateway, :header_signing_secret, "ztlp-default-signing-secret")
  end

  # Constant-time string comparison to prevent timing attacks
  defp safe_compare(a, b) when byte_size(a) != byte_size(b), do: false
  defp safe_compare(a, b) do
    # XOR each byte and accumulate; result is 0 iff all bytes match
    a_bytes = :binary.bin_to_list(a)
    b_bytes = :binary.bin_to_list(b)
    result = Enum.zip(a_bytes, b_bytes)
      |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)
    result == 0
  end
end
