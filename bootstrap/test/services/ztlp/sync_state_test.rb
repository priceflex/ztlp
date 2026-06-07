# frozen_string_literal: true

require "test_helper"
require "fileutils"

# Ztlp::SyncState — filesystem-backed sync-health state for the
# NS → Bootstrap reconciler. Pinned behaviours under test:
#
#   * Fresh state is permissive: due? is true, counters are zero.
#   * record_success! resets failure tracking.
#   * record_failure! bumps the counter and computes an exponential
#     backoff window that caps at 15 minutes.
#   * due?(now:) is a pure function of (next_retry_at, now).
#   * Corrupt or missing state files fall back to defaults — they
#     never raise into the cron loop.
#   * State round-trips through the JSON file across "process
#     boundaries" (i.e. without an in-memory cache).
class Ztlp::SyncStateTest < ActiveSupport::TestCase
  # Each test gets its own state file so the suite is safe under
  # parallelized workers — Rails forks workers above the 50-run threshold
  # and all forks would otherwise share Rails.root/tmp/ztlp_sync_state.json.
  setup do
    @tmpdir = Dir.mktmpdir("ztlp-sync-state-test")
    @state_path = Pathname.new(File.join(@tmpdir, "ztlp_sync_state.json"))
    Ztlp::SyncState.stubs(:state_file).returns(@state_path)
  end

  teardown do
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.exist?(@tmpdir)
  end

  test "fresh state is due immediately" do
    assert Ztlp::SyncState.due?
    assert_equal 0, Ztlp::SyncState.current[:consecutive_failures]
    assert_nil Ztlp::SyncState.current[:last_success_at]
  end

  test "record_success! sets timestamp and clears failure counter" do
    Ztlp::SyncState.record_failure!(error_class: "TransportError")
    Ztlp::SyncState.record_failure!(error_class: "TransportError")
    refute Ztlp::SyncState.due?  # backoff active

    now = Time.utc(2026, 6, 7, 12)
    Ztlp::SyncState.record_success!(timestamp: now)

    state = Ztlp::SyncState.current
    assert_equal now.to_i, state[:last_success_at].to_i
    assert_equal 0, state[:consecutive_failures]
    assert_nil state[:next_retry_at]
    assert_nil state[:last_error_class]
    assert Ztlp::SyncState.due?
  end

  test "record_failure! schedules exponential backoff" do
    now = Time.utc(2026, 6, 7, 12)

    Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now)
    assert_equal 1, Ztlp::SyncState.current[:consecutive_failures]
    assert_equal "TransportError", Ztlp::SyncState.current[:last_error_class]
    assert_equal (now + 60).to_i, Ztlp::SyncState.current[:next_retry_at].to_i

    Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now + 30)
    assert_equal 2, Ztlp::SyncState.current[:consecutive_failures]
    assert_equal ((now + 30) + 120).to_i, Ztlp::SyncState.current[:next_retry_at].to_i
  end

  test "backoff caps at 15 minutes" do
    now = Time.utc(2026, 6, 7, 12)
    10.times { Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now) }
    # 10 failures: would be 60 * 2^9 = 30720s without cap; capped at 900s.
    assert_equal (now + 900).to_i, Ztlp::SyncState.current[:next_retry_at].to_i
  end

  test "due? respects next_retry_at window" do
    now = Time.utc(2026, 6, 7, 12)
    Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now)
    refute Ztlp::SyncState.due?(now: now + 30)   # inside backoff
    assert Ztlp::SyncState.due?(now: now + 61)   # past backoff
  end

  test "tolerates corrupt state file (returns default state)" do
    FileUtils.mkdir_p(File.dirname(@state_path))
    File.write(@state_path, "this is not json{")
    assert Ztlp::SyncState.due?
    assert_equal 0, Ztlp::SyncState.current[:consecutive_failures]
  end

  test "persists across process boundary (round-trip)" do
    now = Time.utc(2026, 6, 7, 12)
    Ztlp::SyncState.record_failure!(error_class: "ServerError", timestamp: now)
    # No in-memory cache — current always re-reads the file.
    state = Ztlp::SyncState.current
    assert_equal "ServerError", state[:last_error_class]
    assert_equal 1, state[:consecutive_failures]
    assert_equal (now + 60).to_i, state[:next_retry_at].to_i
  end
end
