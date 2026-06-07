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

  @type identity ::
          {:tenant, ZtlpNs.AdminApi.TenantRegistry.t()}
          | :legacy

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
  Tenant-aware HMAC verification with backwards-compat global fallback.

  Resolution order (security-critical — do not reorder):

    1. Header presence checks (`x-ns-timestamp`, `x-ns-signature`).
    2. Timestamp parse + ±#{@skew_seconds}s skew window. Stale → short-circuit.
    3. Try EVERY tenant's secret. First HMAC match wins → `{:ok, {:tenant, t}}`.
    4. If no tenant matched AND `global_secret` is a binary, try global.
       Match → `{:ok, :legacy}`. No match → `{:error, :bad_signature}`.
    5. If no tenant matched AND no `global_secret` AND no tenants are
       configured → `{:error, :no_secret}` (operator hasn't set any
       credentials at all — distinct from "signed with the wrong key").
    6. If no tenant matched AND no `global_secret` AND tenants ARE
       configured → `{:error, :bad_signature}`.

  Tenant ALWAYS wins over global when both could match. This matters
  during the migration window when operators run with both per-tenant
  secrets AND the legacy `ZTLP_NS_ADMIN_API_SECRET` set — a leaked
  global secret would NOT be allowed to impersonate a tenant.

  The legacy `verify_request/5` is preserved unchanged for callers that
  only need single-secret mode.
  """
  @spec verify_request_with_registry(
          String.t(),
          String.t(),
          binary(),
          map(),
          %{String.t() => ZtlpNs.AdminApi.TenantRegistry.t()},
          binary() | nil
        ) ::
          {:ok, identity()}
          | {:error,
             :no_secret | :missing_header | :stale_timestamp | :bad_signature | :bad_request}
  def verify_request_with_registry(method, path, body, headers, registry, global_secret)
      when is_binary(method) and is_binary(path) and is_binary(body) and is_map(headers) and
             is_map(registry) and (is_binary(global_secret) or is_nil(global_secret)) do
    with :ok <- check_header_presence(headers),
         {:ok, ts_int} <- parse_timestamp(headers),
         :ok <- check_skew(ts_int) do
      body_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)
      canonical = "#{method}\n#{path}\n#{ts_int}\n#{body_hash}"
      sig_hex = Map.fetch!(headers, "x-ns-signature")

      case ZtlpNs.AdminApi.TenantRegistry.identify_tenant(canonical, sig_hex, registry) do
        {:ok, tenant} ->
          {:ok, {:tenant, tenant}}

        :no_match ->
          fallback_to_global(canonical, sig_hex, registry, global_secret)
      end
    end
  end

  defp fallback_to_global(canonical, sig_hex, registry, global_secret) do
    cond do
      is_binary(global_secret) ->
        expected =
          :crypto.mac(:hmac, :sha256, global_secret, canonical)
          |> Base.encode16(case: :lower)

        if secure_compare(expected, sig_hex),
          do: {:ok, :legacy},
          else: {:error, :bad_signature}

      map_size(registry) == 0 ->
        # No tenants configured AND no global — operator has set up
        # NOTHING. Distinguish from "wrong key" so callers can log a
        # more useful audit reason.
        {:error, :no_secret}

      true ->
        {:error, :bad_signature}
    end
  end

  defp check_header_presence(headers) do
    cond do
      not Map.has_key?(headers, "x-ns-timestamp") -> {:error, :missing_header}
      not Map.has_key?(headers, "x-ns-signature") -> {:error, :missing_header}
      true -> :ok
    end
  end

  defp parse_timestamp(headers) do
    case Integer.parse(Map.fetch!(headers, "x-ns-timestamp")) do
      {n, ""} -> {:ok, n}
      _ -> {:error, :bad_request}
    end
  end

  defp check_skew(ts_int) do
    if abs(System.system_time(:second) - ts_int) > @skew_seconds,
      do: {:error, :stale_timestamp},
      else: :ok
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

  # ── Trust-authority extension hook (T7, stub for Phase 3+) ─────────

  @type request_context :: %{
          peer_ip: :inet.ip4_address(),
          method: String.t(),
          path: String.t(),
          query: String.t(),
          identity: identity()
        }

  @doc """
  Trust-authority verification hook. Phase 3+ will plug CA-signed
  authorization here. For now returns `:ok` unconditionally; the call
  site in `ZtlpNs.MetricsServer.handle_admin_records/5` is pinned so
  future implementations don't need to restructure the auth chain.

  Future contract (NOT YET ENFORCED):

    - Takes the authenticated `identity` plus a `request_context` map.
    - Returns `:ok` if a valid trust authority has issued the tenant a
      capability for this operation, OR if no trust authority is
      configured (open mode).
    - Returns `{:error, :authority_denied}` if a trust authority is
      configured AND has explicitly denied this operation.

  The hook fires AFTER tenant identification (T4) and BEFORE zone-glob
  filtering (T5). A `:authority_denied` result short-circuits to 403
  with audit severity `:critical`.

  See `docs/operations/ns-admin-tenant-isolation.md` § Trust Authority
  Forward Path for the design discussion.
  """
  @spec verify_authority(identity(), request_context() | map()) ::
          :ok | {:error, :authority_denied}
  def verify_authority(_identity, _context), do: :ok

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
