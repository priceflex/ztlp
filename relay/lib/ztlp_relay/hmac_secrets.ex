defmodule ZtlpRelay.HmacSecrets do
  @moduledoc """
  Per-zone HMAC secret resolver for gateway dynamic registration and
  client routing.

  This module is the single source of truth for "is this signed
  registration frame trusted?" in the relay. It replaces the legacy
  single-secret `Config.registration_secret/0` with a per-zone key map
  while keeping that function as a backward-compat fallback.

  See `docs/per_zone_hmac_design.md` for the full design rationale,
  wire-format notes, mode semantics, and rotation procedure.

  ## Storage backend

  Secrets are read from process environment variables:

      ZTLP_HMAC_SECRET_<UPCASE_ZONE> = "<primary>[,<grace1>[,<grace2>...]]"

  The first comma-separated entry is the *primary* (signing) key.
  All entries are valid for *verification*. Each entry may be:

    * raw 32 bytes (ASCII-printable),
    * 64 hex characters (decoded to 32 bytes), or
    * `base64:<encoded>` (decoded to raw bytes).

  When no per-zone secret matches, falls back to the legacy
  `ZTLP_RELAY_REGISTRATION_SECRET`. When neither is configured, the
  mode-aware policy (`verify_with_policy/3`) decides whether the frame
  is accepted or rejected. The default mode is `:prod` (fail-closed),
  so unsigned frames are rejected unless `ZTLP_RELAY_HMAC_MODE` is
  explicitly set to `dev` or `staging`.

  This module is structured so a future swap to an external secret
  manager (Vault / AWS SM / GCP SM) only needs to change
  `read_zone_env/1` and `read_legacy_env/0` — call sites in
  `udp_listener.ex` are unaffected.
  """

  require Logger

  @type zone_id :: String.t()
  @type secret :: binary()
  @type mode :: :dev | :staging | :prod
  @type key_class :: :primary | :grace | :legacy
  @type policy_class ::
          key_class()
          | :unverified_dev
          | :unverified_staging

  @doc """
  Returns the current HMAC mode (`:dev` | `:staging` | `:prod`).

  Read from `ZTLP_RELAY_HMAC_MODE` (case-insensitive). Defaults to
  `:prod` (fail-closed) so that unauthenticated `GATEWAY_REGISTER`
  frames are rejected when no secret is configured — the previous
  default of `:dev` silently accepted any registration without HMAC
  verification, which allowed an attacker on the relay's UDP network
  to register rogue gateways (CWE-287).

  Garbage input is treated as `:prod` with a warning log — operators
  must explicitly opt into `:dev` or `:staging` to allow unsigned
  frames during development or migration.
  """
  @spec mode() :: mode()
  def mode do
    case System.get_env("ZTLP_RELAY_HMAC_MODE") do
      nil ->
        :prod

      value ->
        case String.downcase(value) do
          "dev" -> :dev
          "staging" -> :staging
          "prod" -> :prod
          other ->
            Logger.warning(
              "[HmacSecrets] Unrecognized ZTLP_RELAY_HMAC_MODE=#{inspect(other)}, " <>
                "defaulting to :prod (fail-closed). Valid values: dev, staging, prod. " <>
                "Set ZTLP_RELAY_HMAC_MODE=dev to allow unsigned registrations."
            )

            :prod
        end
    end
  end

  @doc """
  Slugifies a zone id into the env-var suffix used to look up its
  secret(s).

  Deterministic: uppercases, replaces non-alphanumeric runs with a
  single underscore, and strips leading/trailing underscores.

  ## Examples

      iex> ZtlpRelay.HmacSecrets.slugify_zone("acme.ztlp")
      "ACME_ZTLP"

      iex> ZtlpRelay.HmacSecrets.slugify_zone("tech-rockstars.ztlp")
      "TECH_ROCKSTARS_ZTLP"
  """
  @spec slugify_zone(zone_id()) :: String.t()
  def slugify_zone(zone_id) when is_binary(zone_id) do
    zone_id
    |> String.upcase()
    |> String.replace(~r/[^A-Z0-9]+/, "_")
    |> String.trim("_")
  end

  @doc """
  Returns the *primary* signing secret for `zone_id`, or
  `{:error, :not_configured}` if no per-zone secret is set.

  The primary is the first entry in the comma-separated list. It is
  used for outbound signing; for inbound verification use
  `verifying_secrets/1`.
  """
  @spec primary_secret(zone_id()) :: {:ok, secret()} | {:error, :not_configured}
  def primary_secret(zone_id) do
    case verifying_secrets(zone_id) do
      [] -> {:error, :not_configured}
      [primary | _] -> {:ok, primary}
    end
  end

  @doc """
  Returns all verifying secrets for `zone_id` in priority order
  (primary first, then grace keys). Empty list if none configured.

  Inbound verification should try each in order and return as soon as
  one matches; constant-time comparison inside the loop prevents
  timing leaks across keys.
  """
  @spec verifying_secrets(zone_id()) :: [secret()]
  def verifying_secrets(zone_id) do
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
  Returns the legacy single registration secret if configured, else
  `nil`. This is the v0.29.5-and-earlier path; new deployments should
  use per-zone secrets exclusively.
  """
  @spec legacy_secret() :: secret() | nil
  def legacy_secret do
    case read_legacy_env() do
      nil -> nil
      raw -> decode_secret(raw)
    end
  end

  @doc """
  Verifies a signed payload's HMAC against the configured secrets for
  `zone_id`. Returns which key class matched so the caller can log
  appropriately:

    * `{:ok, :primary}` — matched the current primary key (signed
      with the latest config).
    * `{:ok, :grace}`   — matched a non-primary key in this zone's
      list (rotation overlap; the sender needs to upgrade).
    * `{:ok, :legacy}`  — fell through to the global
      `ZTLP_RELAY_REGISTRATION_SECRET` because no per-zone key exists
      for this zone or none of the per-zone keys matched.
    * `{:error, :no_secret}` — neither per-zone nor legacy is set.
    * `{:error, :bad_hmac}`  — at least one secret is set but no key
      validated the provided HMAC.

  Mode-aware policy (accept/reject unsigned frames) is in
  `verify_with_policy/3`.
  """
  @spec verify(zone_id(), binary(), binary()) ::
          {:ok, key_class()} | {:error, :no_secret | :bad_hmac}
  def verify(zone_id, signed_data, provided_hmac)
      when is_binary(signed_data) and is_binary(provided_hmac) do
    zone_keys = verifying_secrets(zone_id)
    legacy = legacy_secret()

    cond do
      # ── Per-zone path ──
      zone_keys != [] ->
        case match_against(zone_keys, signed_data, provided_hmac) do
          {:match, 0} ->
            {:ok, :primary}

          {:match, _idx} ->
            {:ok, :grace}

          :no_match ->
            # No per-zone key matched. Try the legacy fallback before
            # giving up — operators rotating from legacy → per-zone
            # need both paths to coexist during the migration window.
            cond do
              legacy != nil and constant_time_equal?(
                :crypto.mac(:hmac, :sha256, legacy, signed_data),
                provided_hmac
              ) ->
                {:ok, :legacy}

              true ->
                {:error, :bad_hmac}
            end
        end

      # ── Legacy-only path (no per-zone secret configured for this zone) ──
      legacy != nil ->
        expected = :crypto.mac(:hmac, :sha256, legacy, signed_data)

        if constant_time_equal?(expected, provided_hmac) do
          {:ok, :legacy}
        else
          {:error, :bad_hmac}
        end

      # ── Nothing configured ──
      true ->
        {:error, :no_secret}
    end
  end

  @doc """
  Mode-aware wrapper around `verify/3`.

  In `:dev` and `:staging`, an unsigned frame against an
  unconfigured-secret zone is accepted (with mode-specific logging).
  In `:prod`, the same case is rejected.

  Successful verification returns the same `key_class` as `verify/3`
  unwrapped from `{:ok, _}`. Acceptance-without-signature returns
  `:unverified_dev` or `:unverified_staging` so the caller can
  distinguish in its log line.
  """
  @spec verify_with_policy(zone_id(), binary(), binary()) ::
          {:ok, policy_class()} | {:error, :bad_hmac | :no_secret_configured_prod}
  def verify_with_policy(zone_id, signed_data, provided_hmac) do
    case verify(zone_id, signed_data, provided_hmac) do
      {:ok, class} ->
        {:ok, class}

      {:error, :bad_hmac} ->
        {:error, :bad_hmac}

      {:error, :no_secret} ->
        case mode() do
          :dev -> {:ok, :unverified_dev}
          :staging -> {:ok, :unverified_staging}
          :prod -> {:error, :no_secret_configured_prod}
        end
    end
  end

  # ── Internals ──────────────────────────────────────────────────

  # Env-var IO is isolated here so that swapping to an external secret
  # manager later only touches these two helpers and the slugify rule.
  defp read_zone_env(zone_id) do
    System.get_env("ZTLP_HMAC_SECRET_" <> slugify_zone(zone_id))
  end

  defp read_legacy_env do
    # Honor both the env var (preferred for prod) and the Application
    # config (used by tests and legacy dev setups). Env var wins to
    # match the existing precedence in `ZtlpRelay.Config.registration_secret/0`.
    case System.get_env("ZTLP_RELAY_REGISTRATION_SECRET") do
      nil -> Application.get_env(:ztlp_relay, :registration_secret)
      value -> value
    end
  end

  # Decode one comma-separated entry to its raw byte form. Returns nil
  # on malformed input so the caller can skip it (we log the rejection
  # for operator visibility).
  defp decode_secret("base64:" <> rest) do
    case Base.decode64(rest) do
      {:ok, bytes} when byte_size(bytes) >= 16 ->
        bytes

      _ ->
        Logger.warning(
          "[HmacSecrets] Rejected base64-encoded entry " <>
            "(decoded length < 16B or invalid)."
        )

        nil
    end
  end

  defp decode_secret(value) when is_binary(value) do
    cond do
      # 64-char ASCII string that decodes cleanly from hex → treat as hex.
      byte_size(value) == 64 and hex?(value) ->
        case Base.decode16(value, case: :mixed) do
          {:ok, bytes} -> bytes
          _ -> value
        end

      # Otherwise: raw bytes as-is. HMAC-SHA256 accepts any non-empty
      # key; we recommend ≥16 bytes in operator docs but do NOT enforce
      # it here because the legacy single-secret path historically
      # accepted shorter values and several existing dev/test setups
      # would break on a hard floor. A soft `info` log surfaces short
      # keys for operator visibility without rejecting them.
      byte_size(value) > 0 ->
        if byte_size(value) < 16 do
          Logger.info(
            "[HmacSecrets] Secret entry length #{byte_size(value)}B " <>
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

  # Walks the verifying-key list in order, returning the index of the
  # first match (0 == primary, 1+ == grace). Each comparison is
  # constant-time on the HMAC bytes. The walk itself terminates early
  # on first match — this is acceptable because an attacker cannot
  # learn which key matched from timing without already controlling
  # the verifying-key set.
  defp match_against(keys, signed_data, provided_hmac) do
    keys
    |> Enum.with_index()
    |> Enum.reduce_while(:no_match, fn {key, idx}, _acc ->
      expected = :crypto.mac(:hmac, :sha256, key, signed_data)

      if constant_time_equal?(expected, provided_hmac) do
        {:halt, {:match, idx}}
      else
        {:cont, :no_match}
      end
    end)
  end

  # Constant-time byte comparison. Returns false immediately on length
  # mismatch — this is safe because the expected HMAC length is a
  # public constant (32 bytes for HMAC-SHA256), not a secret.
  defp constant_time_equal?(a, b)
       when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b) do
    a_bytes = :binary.bin_to_list(a)
    b_bytes = :binary.bin_to_list(b)

    Enum.zip(a_bytes, b_bytes)
    |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)
    |> Kernel.==(0)
  end

  defp constant_time_equal?(_a, _b), do: false
end
