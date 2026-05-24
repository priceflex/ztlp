require "test_helper"

# Phase C — Suppress false "shared infra unreachable" alerts.
#
# Every fresh Bootstrap container auto-seeds two `Machine` rows for the
# central, operator-unmanaged ZTLP NS + Relay (see
# `Ztlp::EnsureSharedMachines`). They are flagged via
# `ssh_user == Machine::SHARED_SSH_USER` ("unmanaged") and exist purely
# to satisfy `Network#deployable?` so that token-mint works on first
# dashboard click.
#
# `HealthChecker` doesn't know that. Its default `check_all` tries to
# SSH into every Machine row on a 30s-ish cadence. For shared rows the
# SSH attempt is guaranteed to fail (no key, by design) — which writes
# a `down` `HealthCheck` record AND an `Alert` row per component. From
# the dashboard's perspective every fresh tenant ships with two phantom
# red alerts on infrastructure the operator can't fix.
#
# This test pins the desired Phase C behaviour: a `Machine` whose
# `shared?` predicate is true MUST be a no-op for `HealthChecker` —
# no SSH attempt, no `HealthCheck` row, no `Alert` row, no mutation of
# `machine.status` / `last_health_check_at` / `ztlp_tunnel_*`. The
# operator-owned (non-shared) path must continue to behave exactly as
# before so we don't regress the actual health-monitoring feature.
class HealthCheckerSharedMachineTest < ActiveSupport::TestCase
  setup do
    @shared = machines(:shared_ns)
    @owned  = machines(:relay1)

    # Pre-condition assertions so a regression in the fixture file or in
    # `Machine#shared?` itself doesn't masquerade as a behavioural pass.
    assert @shared.shared?, "fixture :shared_ns must be Machine#shared?"
    refute @owned.shared?, "fixture :relay1 must NOT be Machine#shared?"
  end

  # --- check_all on a shared machine ----------------------------------

  test "check_all returns an empty array for shared machines" do
    # Belt + suspenders: if any code path tries to open SSH against the
    # shared machine, the test fails LOUDLY rather than silently passing
    # because `Net::SSH.start` happens to short-circuit in some way.
    Net::SSH.expects(:start).never

    results = HealthChecker.new(@shared).check_all

    assert_equal [], results, "shared machines must be a HealthChecker no-op"
  end

  test "check_all on a shared machine creates no HealthCheck rows" do
    Net::SSH.expects(:start).never

    assert_no_difference -> { HealthCheck.where(machine: @shared).count } do
      HealthChecker.new(@shared).check_all
    end
  end

  test "check_all on a shared machine creates no Alert rows" do
    Net::SSH.expects(:start).never

    # Stage the conditions that would normally produce an alert: a
    # previous "healthy" record so the next "down" would be a status
    # change. The point is the shared guard short-circuits BEFORE
    # `store_result` ever runs.
    HealthCheck.create!(
      machine: @shared, component: "ns", status: "healthy",
      checked_at: 10.minutes.ago
    )

    assert_no_difference -> { Alert.where(machine: @shared).count } do
      HealthChecker.new(@shared).check_all
    end
  end

  test "check_all on a shared machine does not mutate machine columns" do
    Net::SSH.expects(:start).never

    original_status = @shared.status
    original_last_check = @shared.last_health_check_at
    original_tunnel_reachable = @shared.ztlp_tunnel_reachable
    original_tunnel_error = @shared.ztlp_tunnel_error
    original_last_error = @shared.last_error

    HealthChecker.new(@shared).check_all
    @shared.reload

    assert_equal original_status, @shared.status,
                 "shared machine status must not be flipped by HealthChecker"
    # last_health_check_at + ztlp_tunnel_* are nil on a fresh shared row;
    # use `assert_nil` so Minitest doesn't deprecation-warn about
    # `assert_equal nil, x` vs `assert_nil x`.
    if original_last_check.nil?
      assert_nil @shared.last_health_check_at,
                 "shared machine last_health_check_at must not be touched"
    else
      assert_equal original_last_check, @shared.last_health_check_at
    end
    if original_tunnel_reachable.nil?
      assert_nil @shared.ztlp_tunnel_reachable
    else
      assert_equal original_tunnel_reachable, @shared.ztlp_tunnel_reachable
    end
    if original_tunnel_error.nil?
      assert_nil @shared.ztlp_tunnel_error
    else
      assert_equal original_tunnel_error, @shared.ztlp_tunnel_error
    end
    if original_last_error.nil?
      assert_nil @shared.last_error
    else
      assert_equal original_last_error, @shared.last_error
    end
  end

  # --- check_component on a shared machine ----------------------------

  # `check_component` is the per-component entry point hit by the
  # dashboard's "Test connection / health" buttons. A user clicking
  # those on a shared row must get a structured "skipped" answer rather
  # than a misleading "down" pill from the failed SSH attempt.
  test "check_component on a shared machine returns a skipped result without SSH" do
    Net::SSH.expects(:start).never

    result = HealthChecker.new(@shared).check_component("ns")

    assert_kind_of HealthChecker::Result, result
    assert_equal @shared, result.machine
    assert_equal "ns", result.component
    assert_equal "skipped", result.status,
                 "single-component check on shared machine must report :skipped"
  end

  # --- regression guard for operator-owned machines -------------------

  # Phase C must NOT change anything about the operator-owned path.
  # If it does, the existing health-monitoring feature is broken.
  test "check_all on an operator-owned machine still attempts SSH" do
    Net::SSH.expects(:start).at_least_once.raises(Errno::ECONNREFUSED.new("refused"))

    results = HealthChecker.new(@owned).check_all

    refute_empty results, "operator-owned machines must still be probed"
    assert results.any? { |r| r.status == "down" },
           "operator-owned SSH failure must still surface as :down"
  end

  test "check_all on an operator-owned machine still records HealthCheck rows" do
    Net::SSH.expects(:start).at_least_once.raises(Errno::ECONNREFUSED.new("refused"))

    assert_difference -> { HealthCheck.where(machine: @owned).count } do
      HealthChecker.new(@owned).check_all
    end
  end

  test "check_all on an operator-owned machine still creates alerts on transition to down" do
    Net::SSH.expects(:start).at_least_once.raises(Errno::ECONNREFUSED.new("refused"))

    # Seed a prior "healthy" so the next "down" counts as a transition.
    HealthCheck.create!(
      machine: @owned, component: "relay", status: "healthy",
      checked_at: 10.minutes.ago
    )

    assert_difference -> { Alert.where(machine: @owned).count } do
      HealthChecker.new(@owned).check_all
    end
  end
end
