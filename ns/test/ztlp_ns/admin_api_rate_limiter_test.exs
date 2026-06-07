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
end
