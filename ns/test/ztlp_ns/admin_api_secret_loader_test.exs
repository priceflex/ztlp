defmodule ZtlpNs.AdminApiSecretLoaderTest do
  @moduledoc """
  Tests for the boot-time admin API secret loader. Verifies the
  ZTLP_NS_ADMIN_API_SECRET env var is read, validated for length,
  and stored in Application env where AdminApi.verify_request/5 will
  later read it on every request.
  """
  use ExUnit.Case, async: false

  setup do
    prev_env_var = System.get_env("ZTLP_NS_ADMIN_API_SECRET")
    prev_app_env = Application.get_env(:ztlp_ns, :admin_api_secret)

    on_exit(fn ->
      case prev_env_var do
        nil -> System.delete_env("ZTLP_NS_ADMIN_API_SECRET")
        v -> System.put_env("ZTLP_NS_ADMIN_API_SECRET", v)
      end

      case prev_app_env do
        nil -> Application.delete_env(:ztlp_ns, :admin_api_secret)
        v -> Application.put_env(:ztlp_ns, :admin_api_secret, v)
      end
    end)

    System.delete_env("ZTLP_NS_ADMIN_API_SECRET")
    Application.delete_env(:ztlp_ns, :admin_api_secret)
    :ok
  end

  describe "ZtlpNs.Config.load_admin_api_secret_from_env/0" do
    test "decodes a 64-char hex string into 32 raw bytes" do
      hex = String.duplicate("ab", 32)
      System.put_env("ZTLP_NS_ADMIN_API_SECRET", hex)

      ZtlpNs.Config.load_admin_api_secret_from_env()

      stored = Application.get_env(:ztlp_ns, :admin_api_secret)
      assert is_binary(stored)
      assert byte_size(stored) == 32
      assert stored == :binary.copy(<<0xab>>, 32)
    end

    test "decodes uppercase hex too (case-insensitive)" do
      hex = String.duplicate("AB", 32)
      System.put_env("ZTLP_NS_ADMIN_API_SECRET", hex)

      ZtlpNs.Config.load_admin_api_secret_from_env()

      stored = Application.get_env(:ztlp_ns, :admin_api_secret)
      assert is_binary(stored)
      assert byte_size(stored) == 32
      assert stored == :binary.copy(<<0xab>>, 32)
    end

    test "leaves Application env at nil when env var is missing" do
      ZtlpNs.Config.load_admin_api_secret_from_env()
      assert Application.get_env(:ztlp_ns, :admin_api_secret) == nil
    end

    test "leaves Application env at nil when env var is empty string" do
      System.put_env("ZTLP_NS_ADMIN_API_SECRET", "")
      ZtlpNs.Config.load_admin_api_secret_from_env()
      assert Application.get_env(:ztlp_ns, :admin_api_secret) == nil
    end

    test "leaves Application env at nil for malformed hex / wrong-length input" do
      # 63 chars, odd-length hex
      System.put_env("ZTLP_NS_ADMIN_API_SECRET", String.duplicate("a", 63))
      ZtlpNs.Config.load_admin_api_secret_from_env()
      assert Application.get_env(:ztlp_ns, :admin_api_secret) == nil
    end

    test "leaves Application env at nil for 65+ char strings that aren't valid hex" do
      System.put_env("ZTLP_NS_ADMIN_API_SECRET", "not_hex_xx_zzzz")
      ZtlpNs.Config.load_admin_api_secret_from_env()
      assert Application.get_env(:ztlp_ns, :admin_api_secret) == nil
    end
  end
end
