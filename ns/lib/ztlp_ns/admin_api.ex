defmodule ZtlpNs.AdminApi do
  @moduledoc """
  Authenticated read-only admin HTTP API for NS. Verifies HMAC-SHA256
  signatures over a canonical 4-line signing string and gates access by
  a ±300 second clock skew window.

  Canonical signing string:

      <METHOD>\\n<PATH_WITH_QUERY>\\n<TIMESTAMP>\\n<SHA256_HEX(body)>

  Header names (lowercased map keys at this layer): `x-ns-timestamp`,
  `x-ns-signature` (hex-encoded HMAC-SHA256).
  """

  import Bitwise

  @skew_seconds 300

  @spec verify_request(String.t(), String.t(), binary(), map(), keyword()) ::
          :ok
          | {:error,
             :no_secret | :missing_header | :stale_timestamp | :bad_signature | :bad_request}
  def verify_request(method, path, body, headers, opts)
      when is_binary(method) and is_binary(path) and is_binary(body) and is_map(headers) and
             is_list(opts) do
    secret = Keyword.get(opts, :secret)

    cond do
      is_nil(secret) ->
        {:error, :no_secret}

      not Map.has_key?(headers, "x-ns-timestamp") ->
        {:error, :missing_header}

      not Map.has_key?(headers, "x-ns-signature") ->
        {:error, :missing_header}

      true ->
        verify(method, path, body, headers, secret)
    end
  end

  defp verify(method, path, body, headers, secret) do
    ts_str = Map.fetch!(headers, "x-ns-timestamp")
    sig_hex = Map.fetch!(headers, "x-ns-signature")

    case Integer.parse(ts_str) do
      {ts_int, ""} ->
        if abs(System.system_time(:second) - ts_int) > @skew_seconds do
          {:error, :stale_timestamp}
        else
          body_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)
          canonical = "#{method}\n#{path}\n#{ts_int}\n#{body_hash}"

          expected =
            :crypto.mac(:hmac, :sha256, secret, canonical) |> Base.encode16(case: :lower)

          if secure_compare(expected, sig_hex), do: :ok, else: {:error, :bad_signature}
        end

      _ ->
        {:error, :bad_request}
    end
  end

  # Constant-time string comparison. Stdlib-only (no Plug.Crypto dep).
  defp secure_compare(a, b) when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b) do
    a
    |> :binary.bin_to_list()
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.reduce(0, fn {x, y}, acc -> bor(acc, bxor(x, y)) end)
    |> Kernel.==(0)
  end

  defp secure_compare(_, _), do: false
end
