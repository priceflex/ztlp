defmodule ZtlpNs.RecordDefaultsTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.RecordDefaults

  describe "default_ttl/1" do
    # v0.33.0 — KEY and SVC records get 24h TTL. The v0.32.x enrollment
    # path was hardcoding 3600s (1h) and silently diverging from the
    # rest of the registration code which already used 86400s. Pinning
    # the contract here prevents the drift from recurring.
    test "KEY records get 24h TTL (v0.33.0 enrollment fix)" do
      assert RecordDefaults.default_ttl(:key) == 86_400
    end

    test "SVC records get 24h TTL (v0.33.0 enrollment fix)" do
      assert RecordDefaults.default_ttl(:svc) == 86_400
    end

    test "DEVICE/USER/GROUP/BOOTSTRAP records get 24h TTL" do
      assert RecordDefaults.default_ttl(:device) == 86_400
      assert RecordDefaults.default_ttl(:user) == 86_400
      assert RecordDefaults.default_ttl(:group) == 86_400
      assert RecordDefaults.default_ttl(:bootstrap) == 86_400
    end

    test "RELAY records get 1h TTL (gateways re-heartbeat anyway)" do
      assert RecordDefaults.default_ttl(:relay) == 3_600
    end

    test "POLICY records get 1h TTL" do
      assert RecordDefaults.default_ttl(:policy) == 3_600
    end

    test "REVOKE records never expire (TTL=0)" do
      assert RecordDefaults.default_ttl(:revoke) == 0
    end

    test "unknown type falls back to 1h" do
      assert RecordDefaults.default_ttl(:totally_made_up) == 3_600
    end

    # Regression guard: the rate-limit window in RegistrationAuth is 60s.
    # The TTL for client KEY records must be >> the rate-limit window
    # so a half-TTL refresh never lands inside the anti-flood cooldown.
    # If anyone tightens the rate-limit window or shortens KEY TTL,
    # this test (in spirit) catches the bad interaction.
    test "KEY TTL is at least 100x larger than rate-limit window (v0.33.0 invariant)" do
      ttl = RecordDefaults.default_ttl(:key)
      rate_limit_window = 60
      assert ttl > rate_limit_window * 100,
        "KEY TTL #{ttl}s must be far larger than rate-limit window #{rate_limit_window}s " <>
          "so half-TTL client refreshes never collide with anti-flood cooldown"
    end
  end
end
