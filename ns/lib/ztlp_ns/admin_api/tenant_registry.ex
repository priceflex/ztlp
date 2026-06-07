defmodule ZtlpNs.AdminApi.TenantRegistry do
  @moduledoc """
  Loads per-tenant admin-API configuration from environment variables.

  Convention (deployment contract):

      ZTLP_NS_ADMIN_API_TENANT_<SLUG>_SECRET     — 64-char hex OR 32 raw bytes
      ZTLP_NS_ADMIN_API_TENANT_<SLUG>_ZONE_GLOB  — e.g. "*.trs.ztlp" or "trs.ztlp"
      ZTLP_NS_ADMIN_API_TENANT_<SLUG>_CIDRS      — comma-separated IPv4 CIDRs

  Slug is uppercase alphanumeric + underscore. Lowercase env vars are
  ignored (forces explicit deployment contract — no silent uppercasing).

  ## Zone glob semantics

    * `"*.trs.ztlp"` matches `"host.trs.ztlp"` and `"host.sub.trs.ztlp"`
      but NOT `"trs.ztlp"` (bare zone) or `"nottrs.ztlp"`.
    * `"trs.ztlp"` (no leading `*.`) matches only `"trs.ztlp"` exactly.
    * Middle wildcards (e.g. `"*.foo.*"`) are rejected at boot —
      operators must enumerate.

  Multi-CIDR per tenant is supported (comma-separated). Useful when a
  tenant Bootstrap reaches NS over both a primary docker bridge and a
  backup network.

  Misconfiguration raises at boot — missing SECRET / ZONE_GLOB / CIDRS,
  invalid hex secret, malformed CIDR, middle-wildcard glob all fail
  loudly rather than silently allowing requests through.

  Pure data: no GenServer, no application state. Used by the admin-API
  IP gate and per-tenant secret resolution.
  """

  alias ZtlpNs.Cidr

  defstruct [:slug, :secret, :zone_glob, :cidrs]

  @type t :: %__MODULE__{
          slug: String.t(),
          secret: binary(),
          zone_glob: String.t(),
          cidrs: [Cidr.t()]
        }

  @env_prefix "ZTLP_NS_ADMIN_API_TENANT_"
  @slug_re ~r/^[A-Z][A-Z0-9_]*$/

  @doc "Scan `System.get_env/0` and build the registry. Raises on misconfiguration."
  @spec load_all() :: %{String.t() => t()}
  def load_all do
    System.get_env() |> load_from_env()
  end

  @doc "Load from an explicit env map. Test seam and used by `load_all/0`."
  @spec load_from_env(map()) :: %{String.t() => t()}
  def load_from_env(env_map) when is_map(env_map) do
    env_map
    |> group_by_slug()
    |> Enum.map(&build_tenant!/1)
    |> Map.new()
  end

  defp group_by_slug(env_map) do
    Enum.reduce(env_map, %{}, fn {key, val}, acc ->
      case parse_key(key) do
        {:ok, slug, field} ->
          Map.update(acc, slug, %{field => val}, &Map.put(&1, field, val))

        :ignore ->
          acc
      end
    end)
  end

  defp parse_key(key) when is_binary(key) do
    if String.starts_with?(key, @env_prefix) do
      rest = String.replace_prefix(key, @env_prefix, "")
      classify_rest(rest)
    else
      :ignore
    end
  end

  defp parse_key(_), do: :ignore

  defp classify_rest(rest) do
    cond do
      String.ends_with?(rest, "_SECRET") ->
        maybe_field(String.replace_suffix(rest, "_SECRET", ""), :secret)

      String.ends_with?(rest, "_ZONE_GLOB") ->
        maybe_field(String.replace_suffix(rest, "_ZONE_GLOB", ""), :zone_glob)

      String.ends_with?(rest, "_CIDRS") ->
        maybe_field(String.replace_suffix(rest, "_CIDRS", ""), :cidrs)

      true ->
        :ignore
    end
  end

  defp maybe_field(slug, field) do
    if Regex.match?(@slug_re, slug), do: {:ok, slug, field}, else: :ignore
  end

  defp build_tenant!({slug, fields}) do
    secret_str = Map.get(fields, :secret) || raise "tenant #{slug} missing SECRET"
    zone_glob = Map.get(fields, :zone_glob) || raise "tenant #{slug} missing ZONE_GLOB"
    cidrs_str = Map.get(fields, :cidrs) || raise "tenant #{slug} missing CIDRS"

    secret = decode_secret!(slug, secret_str)
    :ok = validate_zone_glob!(slug, zone_glob)
    cidrs = parse_cidrs!(slug, cidrs_str)

    {slug,
     %__MODULE__{
       slug: slug,
       secret: secret,
       zone_glob: zone_glob,
       cidrs: cidrs
     }}
  end

  defp decode_secret!(slug, str) when is_binary(str) do
    cond do
      byte_size(str) == 64 and Regex.match?(~r/^[0-9a-fA-F]+$/, str) ->
        Base.decode16!(str, case: :mixed)

      byte_size(str) == 32 ->
        str

      true ->
        raise "tenant #{slug} secret must be 32 raw bytes or 64-char hex " <>
                "(got #{byte_size(str)} bytes)"
    end
  end

  defp validate_zone_glob!(slug, glob) when is_binary(glob) do
    cond do
      glob == "" ->
        raise "tenant #{slug} ZONE_GLOB empty"

      String.starts_with?(glob, "*.") ->
        # Strip the leading "*." and ensure no other "*" remains.
        rest = binary_part(glob, 2, byte_size(glob) - 2)

        if String.contains?(rest, "*") do
          raise "tenant #{slug} ZONE_GLOB has middle/trailing wildcard " <>
                  "(only leading '*.' or exact match allowed): #{glob}"
        else
          :ok
        end

      String.contains?(glob, "*") ->
        raise "tenant #{slug} ZONE_GLOB has wildcard but not in leading position: #{glob}"

      true ->
        :ok
    end
  end

  defp parse_cidrs!(slug, str) when is_binary(str) do
    str
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> case do
      [] ->
        raise "tenant #{slug} CIDRS empty"

      list ->
        Enum.map(list, fn s ->
          case Cidr.parse(s) do
            {:ok, cidr} ->
              cidr

            {:error, reason} ->
              raise "tenant #{slug} CIDR #{inspect(s)} invalid: #{reason}"
          end
        end)
    end
  end

  # ── Public predicates ──────────────────────────────────────────────

  @doc "True iff `ip` is inside any of `tenant`'s CIDRs."
  @spec ip_in_cidrs?(t(), :inet.ip4_address()) :: boolean()
  def ip_in_cidrs?(%__MODULE__{cidrs: cidrs}, ip) do
    Enum.any?(cidrs, &Cidr.match?(&1, ip))
  end

  @doc """
  True iff `zone_name` matches `tenant.zone_glob`.

  See moduledoc for the exact semantics of leading-`*.` vs exact globs.
  """
  @spec zone_matches?(t(), String.t()) :: boolean()
  def zone_matches?(%__MODULE__{zone_glob: glob}, name) when is_binary(name) do
    do_zone_match(glob, name)
  end

  defp do_zone_match("*." <> suffix, name) do
    # Leading-`*.` glob: name must end with `.<suffix>` (so at least one
    # prefix segment exists). The bare `suffix` itself is NOT a match.
    String.ends_with?(name, "." <> suffix) and name != suffix
  end

  defp do_zone_match(exact, name), do: exact == name

  # ── Tenant identification by HMAC signature ─────────────────────────

  @doc """
  Try each tenant's secret against the given canonical signing string
  and signature. Returns `{:ok, tenant}` on the first match, `:no_match`
  otherwise.

  Constant-time comparison via `ZtlpNs.AdminApi.secure_compare/2`. Note
  that this still iterates linearly over the registry — for very small
  tenant counts (expected: O(10)) this is fine. The comparison itself
  is constant-time per tenant.
  """
  @spec identify_tenant(canonical :: String.t(), sig_hex :: String.t(), %{String.t() => t()}) ::
          {:ok, t()} | :no_match
  def identify_tenant(canonical, sig_hex, registry)
      when is_binary(canonical) and is_binary(sig_hex) and is_map(registry) do
    Enum.find_value(registry, :no_match, fn {_slug, tenant} ->
      expected =
        :crypto.mac(:hmac, :sha256, tenant.secret, canonical)
        |> Base.encode16(case: :lower)

      if ZtlpNs.AdminApi.secure_compare(expected, sig_hex), do: {:ok, tenant}, else: false
    end)
  end
end
