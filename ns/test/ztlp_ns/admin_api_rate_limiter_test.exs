defmodule ZtlpNs.AdminApiRateLimiterTest do
  # async: false — mutates the global AdminApiRateLimiter ETS bucket.
  use ExUnit.Case, async: false

  alias ZtlpNs.AdminApiRateLimiter

  setup do
    Application.ensure_all_started(:ztlp_ns)
    AdminApiRateLimiter.reset()
    :ok
  end

  test "allows requests within the burst" do
    for _ <- 1..12, do: assert :ok = AdminApiRateLimiter.check({127, 0, 0, 1})
  end

  test "rejects 13th request inside the window" do
    for _ <- 1..12, do: assert :ok = AdminApiRateLimiter.check({127, 0, 0, 1})
    assert :rate_limited = AdminApiRateLimiter.check({127, 0, 0, 1})
  end

  test "different peer IPs have independent buckets" do
    for _ <- 1..12, do: assert :ok = AdminApiRateLimiter.check({127, 0, 0, 1})
    assert :ok = AdminApiRateLimiter.check({10, 0, 0, 2})
  end

  test "concurrent requests from same IP cannot bypass the burst limit (CodeRabbit #97)" do
    # Regression: before serialization through the GenServer, ETS lookup +
    # insert was non-atomic so two concurrent requests from the same IP
    # could both observe the same token value and both pass — weakening
    # the limit exactly on burst traffic.
    ip = {192, 168, 1, 1}
    n = 24  # 2x the default 12-burst limit

    parent = self()
    tasks =
      for _ <- 1..n do
        Task.async(fn ->
          result = AdminApiRateLimiter.check(ip)
          send(parent, {:result, result})
          result
        end)
      end

    results = Enum.map(tasks, &Task.await(&1, 1_000))
    oks = Enum.count(results, &(&1 == :ok))
    limited = Enum.count(results, &(&1 == :rate_limited))

    # With proper serialization, AT MOST `burst` (12) requests can pass.
    # Before the fix, this could go to 13-24 under concurrency.
    assert oks <= 12, "expected at most 12 :ok results under concurrency, got #{oks}"
    assert oks + limited == n
  end

  describe "Config.admin_api_rate_limit/0 fallback hardening (CodeRabbit #97)" do
    setup do
      prev_env = System.get_env("ZTLP_NS_ADMIN_API_RATE_LIMIT")
      prev_app = Application.get_env(:ztlp_ns, :admin_api_rate_limit)
      System.delete_env("ZTLP_NS_ADMIN_API_RATE_LIMIT")
      Application.delete_env(:ztlp_ns, :admin_api_rate_limit)

      on_exit(fn ->
        if prev_env, do: System.put_env("ZTLP_NS_ADMIN_API_RATE_LIMIT", prev_env),
                     else: System.delete_env("ZTLP_NS_ADMIN_API_RATE_LIMIT")
        if prev_app, do: Application.put_env(:ztlp_ns, :admin_api_rate_limit, prev_app),
                     else: Application.delete_env(:ztlp_ns, :admin_api_rate_limit)
      end)

      :ok
    end

    test "rejects app-config tuple with zero window (avoids div-by-zero)" do
      Application.put_env(:ztlp_ns, :admin_api_rate_limit, {12, 0})
      assert ZtlpNs.Config.admin_api_rate_limit() == {12, 60}
    end

    test "rejects app-config tuple with negative count" do
      Application.put_env(:ztlp_ns, :admin_api_rate_limit, {-5, 60})
      assert ZtlpNs.Config.admin_api_rate_limit() == {12, 60}
    end

    test "rejects non-tuple app-config (e.g. string)" do
      Application.put_env(:ztlp_ns, :admin_api_rate_limit, "12/60")
      assert ZtlpNs.Config.admin_api_rate_limit() == {12, 60}
    end

    test "accepts valid app-config tuple" do
      Application.put_env(:ztlp_ns, :admin_api_rate_limit, {6, 30})
      assert ZtlpNs.Config.admin_api_rate_limit() == {6, 30}
    end
  end
end
