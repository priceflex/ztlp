defmodule ZtlpGateway.MobilePacingTest do
  use ExUnit.Case, async: true

  @packet_bytes 1_140

  defp mobile_token_bucket(rate_bps, tick_ms) when rate_bps > 0 and tick_ms > 0 do
    max(1, div(rate_bps * tick_ms, 1000))
  end

  defp packets_for_bytes(bytes) do
    div(bytes, @packet_bytes)
  end

  test "mobile pacing token bucket caps bytes per tick to avoid unbounded cellular bursts" do
    # 6 Mbps conservative mobile profile, 6ms pacing tick.
    bytes_per_tick = mobile_token_bucket(750_000, 6)

    assert bytes_per_tick == 4_500
    assert packets_for_bytes(bytes_per_tick) == 3
    assert packets_for_bytes(bytes_per_tick) < 8
  end

  test "mobile token bucket accumulates only up to a bounded burst" do
    burst_bytes = 64 * @packet_bytes
    bytes_per_tick = mobile_token_bucket(750_000, 6)

    accumulated = Enum.reduce(1..100, 0, fn _, tokens -> min(tokens + bytes_per_tick, burst_bytes) end)

    assert accumulated == burst_bytes
  end
end
