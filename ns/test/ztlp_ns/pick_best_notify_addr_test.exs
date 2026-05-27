defmodule ZtlpNs.PickBestNotifyAddrTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.Server

  @moduledoc """
  H7 — Verifies that pick_best_notify_addr/1 always prefers :learned
  endpoints over :reported when choosing the target for PUNCH_NOTIFY.

  :learned endpoints are observed via the UDP source of inbound PEER_ENDPOINTS
  / PUNCH_REPORT packets, so they reflect the NAT-mapped public endpoint NS
  actually saw. :reported endpoints come from the client's reported list and
  may be private LAN addresses unreachable from NS's vantage.
  """

  describe "pick_best_notify_addr/1" do
    test "prefers :learned when both :learned and :reported are present" do
      endpoints = [
        {:reported, {10, 0, 0, 1}, 5000},
        {:learned, {203, 0, 113, 42}, 23456}
      ]

      assert Server.pick_best_notify_addr(endpoints) == {{203, 0, 113, 42}, 23456}
    end

    test "falls back to the first :reported when no :learned exists" do
      endpoints = [
        {:reported, {10, 0, 0, 1}, 5000},
        {:reported, {192, 168, 1, 10}, 6000}
      ]

      assert Server.pick_best_notify_addr(endpoints) == {{10, 0, 0, 1}, 5000}
    end

    test "returns nil for an empty endpoint list" do
      assert Server.pick_best_notify_addr([]) == nil
    end

    test "picks the first :learned when multiple :learned exist (order-stable)" do
      endpoints = [
        {:reported, {10, 0, 0, 1}, 5000},
        {:learned, {203, 0, 113, 42}, 23456},
        {:learned, {198, 51, 100, 7}, 34567}
      ]

      assert Server.pick_best_notify_addr(endpoints) == {{203, 0, 113, 42}, 23456}
    end
  end
end
