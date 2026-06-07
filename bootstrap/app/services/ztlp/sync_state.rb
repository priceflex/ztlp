# frozen_string_literal: true

# Ztlp::SyncState — filesystem-backed sync-health state for the
# NS → Bootstrap reconciler.
#
# Tracks last-success / last-failure / backoff window so the cron
# loop (lib/tasks/ztlp_ns_sync.rake) can suppress redundant attempts
# during NS outages, and the dashboard can surface a green/yellow/red
# health banner.
#
# Persisted as JSON at Rails.root/tmp/ztlp_sync_state.json so it
# survives Rails restarts and is visible cross-process (cron tick
# vs. operator manual sync). File access guarded by flock.
#
# Public API (locked):
#   * record_success!(timestamp:)               → :ok
#   * record_failure!(error_class:, timestamp:) → :ok
#   * current                                   → frozen hash, symbol keys
#   * due?(now:)                                → Bool
#   * reset!                                    → :ok (test helper)
#   * state_file                                → Pathname (test seam)
#
# Backoff: 60s, 120s, 240s, 480s, 900s, 900s, … (cap at 15 min).
module Ztlp
  class SyncState
    STATE_FILE = Rails.root.join("tmp", "ztlp_sync_state.json").freeze
    MAX_BACKOFF_SECONDS = 15 * 60

    class << self
      # Indirection so tests can stub a per-process tmp path and avoid
      # cross-worker contention. Production always returns STATE_FILE.
      def state_file
        STATE_FILE
      end

      def current
        normalize(load_state)
      end

      def due?(now: Time.now)
        next_at = current[:next_retry_at]
        next_at.nil? || now >= next_at
      end

      def record_success!(timestamp: Time.now)
        update_state do |s|
          s["last_success_at"]      = timestamp.iso8601
          s["consecutive_failures"] = 0
          s["next_retry_at"]        = nil
          s["last_error_class"]     = nil
        end
        :ok
      end

      def record_failure!(error_class:, timestamp: Time.now)
        update_state do |s|
          failures = (s["consecutive_failures"] || 0) + 1
          backoff  = [60 * (2**(failures - 1)), MAX_BACKOFF_SECONDS].min
          s["last_failure_at"]      = timestamp.iso8601
          s["consecutive_failures"] = failures
          s["next_retry_at"]        = (timestamp + backoff).iso8601
          s["last_error_class"]     = error_class
        end
        :ok
      end

      def reset!
        FileUtils.rm_f(state_file)
        :ok
      end

      private

      def default_state
        {
          "last_success_at"      => nil,
          "last_failure_at"      => nil,
          "consecutive_failures" => 0,
          "next_retry_at"        => nil,
          "last_error_class"     => nil
        }
      end

      def load_state
        path = state_file
        return default_state unless File.exist?(path)
        raw = File.read(path)
        return default_state if raw.empty?
        JSON.parse(raw)
      rescue JSON::ParserError
        default_state
      end

      def update_state
        path = state_file
        FileUtils.mkdir_p(File.dirname(path))
        File.open(path, File::RDWR | File::CREAT, 0o644) do |f|
          f.flock(File::LOCK_EX)
          raw = f.read
          state =
            if raw.empty?
              default_state
            else
              begin
                JSON.parse(raw)
              rescue JSON::ParserError
                default_state
              end
            end
          yield(state)
          f.rewind
          f.truncate(0)
          f.write(JSON.pretty_generate(state))
        end
      end

      def normalize(state)
        {
          last_success_at:      parse_time(state["last_success_at"]),
          last_failure_at:      parse_time(state["last_failure_at"]),
          consecutive_failures: state["consecutive_failures"].to_i,
          next_retry_at:        parse_time(state["next_retry_at"]),
          last_error_class:     state["last_error_class"]
        }.freeze
      end

      def parse_time(value)
        return nil if value.nil?
        return value if value.is_a?(Time)
        Time.iso8601(value)
      rescue ArgumentError
        nil
      end
    end
  end
end
