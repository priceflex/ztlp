# frozen_string_literal: true

# SyncHealthHelper — view helpers for the NS sync-health banner on
# the ZtlpDevices dashboard.
#
# Pure functions over the frozen hash returned by Ztlp::SyncState.current.
#
#   sync_health_status(state)   → :green | :yellow | :red
#   sync_health_message(state)  → human-readable banner body
#
# Bands:
#   :green  — last_success_at < 10min ago AND consecutive_failures == 0
#   :yellow — last_success_at 10..60min ago OR 1..2 consecutive failures
#   :red    — consecutive_failures >= 3 OR last_success_at > 60min ago OR never synced
module SyncHealthHelper
  include ActionView::Helpers::DateHelper

  STALE_GREEN_THRESHOLD = 10.minutes
  STALE_RED_THRESHOLD   = 60.minutes
  FAILURE_RED_THRESHOLD = 3

  def sync_health_status(state)
    return :red if state[:last_success_at].nil?

    failures = state[:consecutive_failures].to_i
    age      = Time.now - state[:last_success_at]

    return :red    if failures >= FAILURE_RED_THRESHOLD
    return :red    if age > STALE_RED_THRESHOLD
    return :yellow if age >= STALE_GREEN_THRESHOLD || failures > 0
    :green
  end

  def sync_health_message(state)
    return "NS has never synced successfully." if state[:last_success_at].nil?

    parts = ["Last NS sync: #{time_ago_in_words(state[:last_success_at])} ago"]
    if (cls = state[:last_error_class]) && state[:consecutive_failures].to_i > 0
      parts << "#{state[:consecutive_failures]} consecutive failures (#{cls})"
    end
    parts.join(" — ")
  end
end
