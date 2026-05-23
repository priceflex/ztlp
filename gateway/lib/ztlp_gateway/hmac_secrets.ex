defmodule ZtlpGateway.HmacSecrets do
  @moduledoc """
  Gateway-side per-zone HMAC secret reader.

  This is the **signer** counterpart of `ZtlpRelay.HmacSecrets`. The
  gateway only needs to *sign* outbound `GATEWAY_REGISTER` frames, so
  this module is intentionally a smaller surface than the relay
  module — no verification, no mode policy, no legacy fallback wiring
  (the gateway still has `ZtlpGateway.Config.registration_secret/0`
  for the V1 legacy signing path).

  ## Wire compatibility

  The slugify rule, encoding rules (raw bytes / hex / `base64:`),
  comma-separated rotation list, and zone-name → env-var-suffix
  mapping are **identical to the relay's `HmacSecrets.slugify_zone/1`
  and `verifying_secrets/1`**. The relay-side verifier accepts any
  signature produced with the primary key returned here.

  ## Why a separate module instead of importing the relay's?

  The gateway and relay are independent Mix projects (no shared
  library yet). Copying the signer subset is ~50 lines and keeps the
  two services deployable independently. A future refactor can hoist
  both modules into a shared `ztlp_proto_shared` package; the
  contract above is the seam that has to stay byte-identical.

  See `docs/per_zone_hmac_design.md` § "Zone secret storage" for the
  canonical spec.
  """

  require Logger

  @type zone_id :: String.t()
  @type secret :: binary()

  @doc """
  Returns the *primary* signing secret for `zone_id`, or
  `{:error, :not_configured}` if no per-zone secret is set.

  Matches `ZtlpRelay.HmacSecrets.primary_secret/1` byte-for-byte so a
  signature produced here verifies against the same key on the relay
  side.
  """
  @spec primary_secret(zone_id()) :: {:ok, secret()} | {:error, :not_configured}
  def primary_secret(zone_id) when is_binary(zone_id) do
    case verifying_secrets(zone_id) do
      [] -> {:error, :not_configured}
      [primary | _] -> {:ok, primary}
    end
  end

  @doc """
  Returns all configured secrets for `zone_id` in priority order
  (primary first, then any grace keys), empty list if none configured.

  Only the primary is used for signing; the rest exist so an operator
  can see what the relay would also accept during rotation. Tests use
  this to assert rotation overlap behaviour.
  """
  @spec verifying_secrets(zone_id()) :: [secret()]
  def verifying_secrets(zone_id) when is_binary(zone_id) do
    case read_zone_env(zone_id) do
      nil ->
        []

      raw_value ->
        raw_value
        |> String.split(",", trim: true)
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == ""))
        |> Enum.map(&decode_secret/1)
        |> Enum.reject(&is_nil/1)
    end
  end

  @doc """
  Slugify a zone name to its env-var suffix using the same rule as
  the relay:

  1. Upper-case.
  2. Replace runs of non-alphanumerics with a single `_`.
  3. Strip leading/trailing `_`.

  ## Examples

      iex> ZtlpGateway.HmacSecrets.slugify_zone("acme.ztlp")
      "ACME_ZTLP"

      iex> ZtlpGateway.HmacSecrets.slugify_zone("tech-rockstars.ztlp")
      "TECH_ROCKSTARS_ZTLP"
  """
  @spec slugify_zone(zone_id()) :: String.t()
  def slugify_zone(zone_id) when is_binary(zone_id) do
    zone_id
    |> String.upcase()
    |> String.replace(~r/[^A-Z0-9]+/, "_")
    |> String.trim("_")
  end

  # ── Internals ──────────────────────────────────────────────────

  defp read_zone_env(zone_id) do
    System.get_env("ZTLP_HMAC_SECRET_" <> slugify_zone(zone_id))
  end

  # Decode one comma-separated entry to its raw byte form. Mirrors the
  # relay's encoding rules: `base64:` prefix → Base.decode64, 64 hex
  # chars → Base.decode16, anything else → raw bytes (with a soft warn
  # below 16 bytes).
  defp decode_secret("base64:" <> rest) do
    case Base.decode64(rest) do
      {:ok, bytes} when byte_size(bytes) >= 16 ->
        bytes

      _ ->
        Logger.warning(
          "[Gateway.HmacSecrets] Rejected base64-encoded entry " <>
            "(decoded length < 16B or invalid)."
        )

        nil
    end
  end

  defp decode_secret(value) when is_binary(value) do
    cond do
      byte_size(value) == 64 and hex?(value) ->
        case Base.decode16(value, case: :mixed) do
          {:ok, bytes} -> bytes
          _ -> value
        end

      byte_size(value) > 0 ->
        if byte_size(value) < 16 do
          Logger.info(
            "[Gateway.HmacSecrets] Secret entry length #{byte_size(value)}B " <>
              "is below the recommended 16-byte minimum. " <>
              "Consider regenerating with `openssl rand -hex 32`."
          )
        end

        value

      true ->
        nil
    end
  end

  defp hex?(s) do
    Regex.match?(~r/^[0-9a-fA-F]+$/, s)
  end
end
