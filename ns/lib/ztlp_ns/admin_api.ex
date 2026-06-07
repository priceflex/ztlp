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

  @doc """
  Constant-time string comparison. Stdlib-only (no Plug.Crypto dep).

  Returns `false` immediately on length mismatch (length is not secret
  for our HMAC hex strings — they're always 64 chars). For equal-length
  inputs, every byte is XORed before the result is returned, so timing
  does not leak which byte differed.

  Public because `ZtlpNs.AdminApi.TenantRegistry.identify_tenant/3`
  shares this primitive when comparing per-tenant HMAC signatures.
  """
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(a, b) when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b) do
    a
    |> :binary.bin_to_list()
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.reduce(0, fn {x, y}, acc -> bor(acc, bxor(x, y)) end)
    |> Kernel.==(0)
  end

  def secure_compare(_, _), do: false

  # ── list_records/1 ─────────────────────────────────────────────────
  #
  # JSON-safe projection of `ZtlpNs.Store.list_filtered/1`. The output
  # NEVER includes raw signature bytes or any non-pubkey key material.
  # `type` is rendered as a string so JSON consumers don't have to
  # re-atomize, and pubkeys (when present as raw binaries under
  # `data.pubkey`) are rendered as lowercase hex under `pubkey_hex`.

  @type list_opts :: [type: atom() | nil, zone: String.t() | nil]

  @doc """
  Return a JSON-safe projection of all non-expired records matching
  the given filter options.

  ## Options
  - `:type` — atom record type filter (e.g. `:key`, `:svc`)
  - `:zone` — string zone suffix filter (e.g. `"trs.ztlp"`)

  ## Shape
      %{
        records: [
          %{name: ..., type: "key", data: %{...}, created_at: ...,
            ttl: ..., serial: ..., pubkey_hex: "abcd..."}
        ],
        count: non_neg_integer(),
        generated_at: non_neg_integer()  # unix seconds
      }
  """
  @spec list_records(list_opts()) :: %{
          records: [map()],
          count: non_neg_integer(),
          generated_at: non_neg_integer()
        }
  def list_records(opts \\ []) do
    records =
      opts
      |> ZtlpNs.Store.list_filtered()
      |> Enum.map(&project/1)

    %{
      records: records,
      count: length(records),
      generated_at: System.system_time(:second)
    }
  end

  defp project({name, type, %ZtlpNs.Record{} = r}) do
    {data, pubkey_bin} = extract_pubkey(r.data)

    base = %{
      name: name,
      type: Atom.to_string(type),
      data: data,
      created_at: r.created_at,
      ttl: r.ttl,
      serial: r.serial
    }

    case pubkey_bin do
      bin when is_binary(bin) -> Map.put(base, :pubkey_hex, Base.encode16(bin, case: :lower))
      _ -> base
    end
  end

  # Pull the raw-binary `:pubkey` (or `"pubkey"`) out of the record's
  # `data` map. If present and binary, the raw bytes are stripped from
  # `data` (they'd break JSON encoding) and returned so the caller can
  # render them under the top-level `:pubkey_hex` field. If the value
  # is already a string (e.g. hex), it's left in place and no separate
  # `pubkey_hex` is produced.
  defp extract_pubkey(%{pubkey: bin} = data) when is_binary(bin) do
    if String.valid?(bin),
      do: {data, nil},
      else: {Map.delete(data, :pubkey), bin}
  end

  defp extract_pubkey(%{"pubkey" => bin} = data) when is_binary(bin) do
    if String.valid?(bin),
      do: {data, nil},
      else: {Map.delete(data, "pubkey"), bin}
  end

  defp extract_pubkey(data), do: {data, nil}
end
