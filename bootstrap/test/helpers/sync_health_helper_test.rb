# frozen_string_literal: true

require "test_helper"

class SyncHealthHelperTest < ActionView::TestCase
  test "green when last_success_at <10min ago and no failures" do
    state = {
      last_success_at: 2.minutes.ago, consecutive_failures: 0,
      last_failure_at: nil, last_error_class: nil, next_retry_at: nil
    }
    assert_equal :green, sync_health_status(state)
    assert_match(/2 minutes ago/, sync_health_message(state))
  end

  test "yellow when last_success_at >=10min ago but <3 failures" do
    state = {
      last_success_at: 12.minutes.ago, consecutive_failures: 1,
      last_failure_at: 1.minute.ago, last_error_class: "TransportError",
      next_retry_at: 30.seconds.from_now
    }
    assert_equal :yellow, sync_health_status(state)
    assert_match(/12 minutes ago/, sync_health_message(state))
  end

  test "red when consecutive_failures >= 3" do
    state = {
      last_success_at: 1.minute.ago, consecutive_failures: 3,
      last_failure_at: 30.seconds.ago, last_error_class: "TransportError",
      next_retry_at: 8.minutes.from_now
    }
    assert_equal :red, sync_health_status(state)
    assert_match(/TransportError/, sync_health_message(state))
  end

  test "red when never synced" do
    state = {
      last_success_at: nil, consecutive_failures: 0,
      last_failure_at: nil, last_error_class: nil, next_retry_at: nil
    }
    assert_equal :red, sync_health_status(state)
    assert_match(/never/i, sync_health_message(state))
  end

  test "red when last_success_at >60 minutes ago" do
    state = {
      last_success_at: 90.minutes.ago, consecutive_failures: 1,
      last_failure_at: 1.minute.ago, last_error_class: "ServerError",
      next_retry_at: 30.seconds.from_now
    }
    assert_equal :red, sync_health_status(state)
  end

  test "sync_health_message includes elapsed time string" do
    state = {
      last_success_at: 3.minutes.ago, consecutive_failures: 0,
      last_failure_at: nil, last_error_class: nil, next_retry_at: nil
    }
    assert_match(/3 minutes ago/, sync_health_message(state))
  end
end
