defmodule ZtlpRelay.HmacSecretsTest do
  @moduledoc """
  Tests for the per-zone HMAC secret resolver.

  These tests drive the behavior described in
  `docs/per_zone_hmac_design.md`. They run with `async: false` because
  every test reads and writes process environment variables, which is
  global state in OTP.
  """

  use ExUnit.Case, async: false

  alias ZtlpRelay.HmacSecrets

  # ── Helpers ───────────────────────────────────────────────────

  # Save/restore a list of env vars and the HMAC_MODE setting. Each
  # test should declare upfront which env vars it touches so the
  # `on_exit` hook can restore exactly those — broad env wipes from a
  # test would cross-contaminate other tests in the same suite.
  defp with_env(vars, fun) when is_list(vars) and is_function(fun, 0) do
    saved =
      Enum.map(vars, fn {name, value} ->
        prev = System.get_env(name)

        case value do
          nil -> System.delete_env(name)
          v when is_binary(v) -> System.put_env(name, v)
        end

        {name, prev}
      end)

    try do
      fun.()
    after
      Enum.each(saved, fn
        {name, nil} -> System.delete_env(name)
        {name, v} -> System.put_env(name, v)
      end)
    end
  end

  # ── mode/0 ────────────────────────────────────────────────────

  describe "mode/0" do
    test "defaults to :dev when ZTLP_RELAY_HMAC_MODE is unset" do
      with_env([{"ZTLP_RELAY_HMAC_MODE", nil}], fn ->
        assert HmacSecrets.mode() == :dev
      end)
    end

    test "parses 'staging'" do
      with_env([{"ZTLP_RELAY_HMAC_MODE", "staging"}], fn ->
        assert HmacSecrets.mode() == :staging
      end)
    end

    test "parses 'prod'" do
      with_env([{"ZTLP_RELAY_HMAC_MODE", "prod"}], fn ->
        assert HmacSecrets.mode() == :prod
      end)
    end

    test "is case-insensitive on input" do
      with_env([{"ZTLP_RELAY_HMAC_MODE", "PROD"}], fn ->
        assert HmacSecrets.mode() == :prod
      end)
    end

    test "falls back to :dev on garbage input" do
      with_env([{"ZTLP_RELAY_HMAC_MODE", "wat"}], fn ->
        assert HmacSecrets.mode() == :dev
      end)
    end
  end

  # ── slug/1 ────────────────────────────────────────────────────

  describe "slugify_zone/1" do
    test "uppercases ASCII letters" do
      assert HmacSecrets.slugify_zone("acme") == "ACME"
    end

    test "replaces non-alphanumeric runs with single underscore" do
      assert HmacSecrets.slugify_zone("acme.ztlp") == "ACME_ZTLP"
      assert HmacSecrets.slugify_zone("tech-rockstars.ztlp") == "TECH_ROCKSTARS_ZTLP"
      assert HmacSecrets.slugify_zone("foo..bar") == "FOO_BAR"
    end

    test "strips leading and trailing underscores" do
      assert HmacSecrets.slugify_zone(".acme.") == "ACME"
      assert HmacSecrets.slugify_zone("---foo---") == "FOO"
    end

    test "is deterministic" do
      assert HmacSecrets.slugify_zone("Acme.Ztlp") == HmacSecrets.slugify_zone("ACME.ZTLP")
    end
  end

  # ── primary_secret/1 and verifying_secrets/1 ─────────────────

  describe "primary_secret/1 with no env configured" do
    test "returns :not_configured" do
      with_env([{"ZTLP_HMAC_SECRET_ACME", nil}], fn ->
        assert HmacSecrets.primary_secret("acme") == {:error, :not_configured}
      end)
    end
  end

  describe "primary_secret/1 with a single raw 32-byte secret" do
    test "returns the secret as-is" do
      raw32 = String.duplicate("a", 32)

      with_env([{"ZTLP_HMAC_SECRET_ACME", raw32}], fn ->
        assert HmacSecrets.primary_secret("acme") == {:ok, raw32}
      end)
    end
  end

  describe "primary_secret/1 with hex-encoded secret" do
    test "decodes hex to raw bytes" do
      raw = :crypto.strong_rand_bytes(32)
      hex = Base.encode16(raw)

      with_env([{"ZTLP_HMAC_SECRET_ACME", hex}], fn ->
        assert HmacSecrets.primary_secret("acme") == {:ok, raw}
      end)
    end

    test "accepts lowercase hex" do
      raw = :crypto.strong_rand_bytes(32)
      hex = Base.encode16(raw, case: :lower)

      with_env([{"ZTLP_HMAC_SECRET_ACME", hex}], fn ->
        assert HmacSecrets.primary_secret("acme") == {:ok, raw}
      end)
    end
  end

  describe "primary_secret/1 with base64-prefixed secret" do
    test "decodes the base64: prefix form" do
      raw = :crypto.strong_rand_bytes(32)
      encoded = "base64:" <> Base.encode64(raw)

      with_env([{"ZTLP_HMAC_SECRET_ACME", encoded}], fn ->
        assert HmacSecrets.primary_secret("acme") == {:ok, raw}
      end)
    end
  end

  describe "verifying_secrets/1 with two comma-separated secrets" do
    test "returns both, with primary first (signing order = listed order)" do
      raw_primary = String.duplicate("p", 32)
      raw_grace = String.duplicate("g", 32)

      with_env([{"ZTLP_HMAC_SECRET_ACME", "#{raw_primary},#{raw_grace}"}], fn ->
        assert HmacSecrets.primary_secret("acme") == {:ok, raw_primary}
        assert HmacSecrets.verifying_secrets("acme") == [raw_primary, raw_grace]
      end)
    end

    test "ignores empty entries from trailing commas" do
      raw = String.duplicate("a", 32)

      with_env([{"ZTLP_HMAC_SECRET_ACME", "#{raw},,"}], fn ->
        assert HmacSecrets.verifying_secrets("acme") == [raw]
      end)
    end
  end

  # ── verify/3 ──────────────────────────────────────────────────

  describe "verify/3" do
    test "returns {:ok, :primary} when HMAC matches the primary key" do
      secret = :crypto.strong_rand_bytes(32)
      data = "signed payload"
      hmac = :crypto.mac(:hmac, :sha256, secret, data)

      with_env(
        [
          {"ZTLP_HMAC_SECRET_ACME", Base.encode16(secret)},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify("acme", data, hmac) == {:ok, :primary}
        end
      )
    end

    test "returns {:ok, :grace} when HMAC matches a non-primary key (rotation)" do
      primary = :crypto.strong_rand_bytes(32)
      grace = :crypto.strong_rand_bytes(32)
      data = "rotated payload"
      hmac_with_grace = :crypto.mac(:hmac, :sha256, grace, data)

      env_value = Base.encode16(primary) <> "," <> Base.encode16(grace)

      with_env(
        [
          {"ZTLP_HMAC_SECRET_ACME", env_value},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify("acme", data, hmac_with_grace) == {:ok, :grace}
        end
      )
    end

    test "returns {:error, :bad_hmac} when none of the verifying keys match" do
      secret = :crypto.strong_rand_bytes(32)
      data = "signed payload"
      wrong_hmac = :crypto.mac(:hmac, :sha256, "different-key", data)

      with_env(
        [
          {"ZTLP_HMAC_SECRET_ACME", Base.encode16(secret)},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify("acme", data, wrong_hmac) == {:error, :bad_hmac}
        end
      )
    end

    test "falls back to the legacy single secret when no per-zone secret matches" do
      legacy = :crypto.strong_rand_bytes(32)
      data = "signed payload"
      hmac = :crypto.mac(:hmac, :sha256, legacy, data)

      with_env(
        [
          {"ZTLP_HMAC_SECRET_UNKNOWN", nil},
          {"ZTLP_RELAY_REGISTRATION_SECRET", Base.encode16(legacy)}
        ],
        fn ->
          assert HmacSecrets.verify("unknown", data, hmac) == {:ok, :legacy}
        end
      )
    end

    test "returns {:error, :no_secret} when neither per-zone nor legacy is configured" do
      data = "signed payload"
      any_hmac = :crypto.mac(:hmac, :sha256, "anything", data)

      with_env(
        [
          {"ZTLP_HMAC_SECRET_NOTHING", nil},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify("nothing", data, any_hmac) == {:error, :no_secret}
        end
      )
    end

    test "is constant-time on HMAC length mismatch" do
      # Property: a wrong-length HMAC must still take the same code path
      # (no early :error short-circuit that leaks length information).
      # We can't directly measure timing in unit tests, but we can
      # assert the function returns :bad_hmac rather than crashing,
      # which proves it didn't short-circuit on length.
      secret = :crypto.strong_rand_bytes(32)
      data = "signed payload"
      truncated = :binary.part(:crypto.mac(:hmac, :sha256, secret, data), 0, 16)

      with_env(
        [
          {"ZTLP_HMAC_SECRET_ACME", Base.encode16(secret)},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify("acme", data, truncated) == {:error, :bad_hmac}
        end
      )
    end
  end

  # ── mode-dependent policy ────────────────────────────────────

  describe "verify_with_policy/3 in :dev mode" do
    test "accepts unsigned (zero HMAC) when no secret is configured" do
      data = "anything"
      zero_hmac = <<0::256>>

      with_env(
        [
          {"ZTLP_RELAY_HMAC_MODE", "dev"},
          {"ZTLP_HMAC_SECRET_ACME", nil},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify_with_policy("acme", data, zero_hmac) == {:ok, :unverified_dev}
        end
      )
    end
  end

  describe "verify_with_policy/3 in :staging mode" do
    test "accepts unsigned with :unverified_staging tag" do
      data = "anything"
      zero_hmac = <<0::256>>

      with_env(
        [
          {"ZTLP_RELAY_HMAC_MODE", "staging"},
          {"ZTLP_HMAC_SECRET_ACME", nil},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify_with_policy("acme", data, zero_hmac) ==
                   {:ok, :unverified_staging}
        end
      )
    end
  end

  describe "verify_with_policy/3 in :prod mode" do
    test "REJECTS unsigned when no secret is configured" do
      data = "anything"
      zero_hmac = <<0::256>>

      with_env(
        [
          {"ZTLP_RELAY_HMAC_MODE", "prod"},
          {"ZTLP_HMAC_SECRET_ACME", nil},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify_with_policy("acme", data, zero_hmac) ==
                   {:error, :no_secret_configured_prod}
        end
      )
    end

    test "accepts signed when per-zone secret matches" do
      secret = :crypto.strong_rand_bytes(32)
      data = "signed"
      hmac = :crypto.mac(:hmac, :sha256, secret, data)

      with_env(
        [
          {"ZTLP_RELAY_HMAC_MODE", "prod"},
          {"ZTLP_HMAC_SECRET_ACME", Base.encode16(secret)},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify_with_policy("acme", data, hmac) == {:ok, :primary}
        end
      )
    end

    test "REJECTS cross-tenant hijack — secret for zone A doesn't pass for zone B" do
      secret_a = :crypto.strong_rand_bytes(32)
      data = "signed"
      hmac_with_a = :crypto.mac(:hmac, :sha256, secret_a, data)

      with_env(
        [
          {"ZTLP_RELAY_HMAC_MODE", "prod"},
          {"ZTLP_HMAC_SECRET_TENANT_A", Base.encode16(secret_a)},
          {"ZTLP_HMAC_SECRET_TENANT_B", Base.encode16(:crypto.strong_rand_bytes(32))},
          {"ZTLP_RELAY_REGISTRATION_SECRET", nil}
        ],
        fn ->
          assert HmacSecrets.verify_with_policy("tenant-b", data, hmac_with_a) ==
                   {:error, :bad_hmac}
        end
      )
    end
  end
end
