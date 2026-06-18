defmodule ZtlpNs.ResponseEndpointsTest do
  use ExUnit.Case, async: false

  alias ZtlpNs.Server

  @moduledoc """
  Verifies Server.response_endpoints/1 — the PEER_ENDPOINTS (0x0A) serve-path
  filter that decides which EndpointStore entries we OFFER a requester as
  standalone dial candidates.

  Root cause this guards against (KELLYMANCINO-PC, 2026-06-15): a relay-routed
  NAT'd gateway emits NS keepalives from an ephemeral 0.0.0.0:0 socket, so NS
  records a :learned endpoint = the gateway's transient outbound NAT mapping.
  That mapping is NOT an inbound listener; offered as a dial candidate it only
  times out AND crowds the genuinely reachable :reported listener address (and
  the relay backstop) out of the operator's bounded parallel-dial race. The
  filter suppresses :learned whenever a :reported endpoint exists, while still
  falling back to the full set for symmetric-NAT peers that have no reported
  address.

  These tests pin the default-on behavior. The runtime flag
  (ZTLP_NS_PEER_ENDPOINTS_PREFER_REPORTED / :peer_endpoints_prefer_reported)
  is exercised explicitly in the "flag off" test.
  """

  setup do
    # Ensure a clean, known flag state per test (default = prefer reported).
    prev = Application.get_env(:ztlp_ns, :peer_endpoints_prefer_reported)
    Application.delete_env(:ztlp_ns, :peer_endpoints_prefer_reported)
    System.delete_env("ZTLP_NS_PEER_ENDPOINTS_PREFER_REPORTED")

    on_exit(fn ->
      if prev == nil do
        Application.delete_env(:ztlp_ns, :peer_endpoints_prefer_reported)
      else
        Application.put_env(:ztlp_ns, :peer_endpoints_prefer_reported, prev)
      end

      System.delete_env("ZTLP_NS_PEER_ENDPOINTS_PREFER_REPORTED")
    end)

    :ok
  end

  describe "response_endpoints/1 (default: prefer reported)" do
    test "suppresses :learned when a :reported endpoint exists (the KELLYMANCINO case)" do
      endpoints = [
        {:reported, {10, 210, 1, 164}, 23095},
        {:learned, {64, 58, 101, 162}, 59343}
      ]

      assert Server.response_endpoints(endpoints) == [
               {:reported, {10, 210, 1, 164}, 23095}
             ]
    end

    test "returns all :reported endpoints when several exist, still dropping :learned" do
      endpoints = [
        {:reported, {10, 210, 1, 164}, 23095},
        {:reported, {192, 168, 50, 9}, 23095},
        {:learned, {64, 58, 101, 162}, 59343}
      ]

      assert Server.response_endpoints(endpoints) == [
               {:reported, {10, 210, 1, 164}, 23095},
               {:reported, {192, 168, 50, 9}, 23095}
             ]
    end

    test "falls back to the FULL set when there is NO :reported endpoint (symmetric-NAT hint)" do
      endpoints = [
        {:learned, {64, 58, 101, 162}, 59343}
      ]

      assert Server.response_endpoints(endpoints) == endpoints
    end

    test "empty in, empty out" do
      assert Server.response_endpoints([]) == []
    end

    test "preserves input order of :reported entries (stable)" do
      endpoints = [
        {:reported, {10, 0, 0, 1}, 23095},
        {:learned, {203, 0, 113, 42}, 40000},
        {:reported, {10, 0, 0, 2}, 23095}
      ]

      assert Server.response_endpoints(endpoints) == [
               {:reported, {10, 0, 0, 1}, 23095},
               {:reported, {10, 0, 0, 2}, 23095}
             ]
    end
  end

  describe "response_endpoints/1 with flag OFF (legacy: return everything)" do
    test "returns the full set unchanged when prefer-reported is disabled via env" do
      System.put_env("ZTLP_NS_PEER_ENDPOINTS_PREFER_REPORTED", "false")

      endpoints = [
        {:reported, {10, 210, 1, 164}, 23095},
        {:learned, {64, 58, 101, 162}, 59343}
      ]

      assert Server.response_endpoints(endpoints) == endpoints
    end

    test "returns the full set unchanged when disabled via app env" do
      Application.put_env(:ztlp_ns, :peer_endpoints_prefer_reported, false)

      endpoints = [
        {:reported, {10, 210, 1, 164}, 23095},
        {:learned, {64, 58, 101, 162}, 59343}
      ]

      assert Server.response_endpoints(endpoints) == endpoints
    end
  end
end
