defmodule ZtlpNs.StructuredLogTest do
  use ExUnit.Case

  import ExUnit.CaptureLog

  alias ZtlpNs.StructuredLog

  setup do
    # Ensure info-level logs are captured (test env may default to :warn)
    prev_level = Logger.level()
    Logger.configure(level: :debug)
    on_exit(fn -> Logger.configure(level: prev_level) end)
    :ok
  end

  # ── Info events ────────────────────────────────────────────────────────

  describe "info/2" do
    test "logs startup event" do
      log = capture_log(fn -> StructuredLog.info(:startup) end)
      assert log =~ "NS starting"
    end

    test "logs config_loaded event" do
      log = capture_log(fn -> StructuredLog.info(:config_loaded) end)
      assert log =~ "Configuration loaded"
    end

    test "logs listening event" do
      log = capture_log(fn -> StructuredLog.info(:listening, port: 23096) end)
      assert log =~ "UDP listener started"
    end

    test "logs record_created event" do
      log = capture_log(fn -> StructuredLog.info(:record_created, name: "web.example.ztlp") end)
      assert log =~ "Record created"
    end

    test "logs record_updated event" do
      log = capture_log(fn -> StructuredLog.info(:record_updated, name: "web.example.ztlp") end)
      assert log =~ "Record updated"
    end

    test "logs record_expired event" do
      log = capture_log(fn -> StructuredLog.info(:record_expired, name: "old.example.ztlp") end)
      assert log =~ "Record expired"
    end

    test "logs record_deleted event" do
      log = capture_log(fn -> StructuredLog.info(:record_deleted, name: "gone.example.ztlp") end)
      assert log =~ "Record deleted"
    end

    test "logs zone_delegated event" do
      log = capture_log(fn -> StructuredLog.info(:zone_delegated, zone: "example.ztlp") end)
      assert log =~ "Zone delegated"
    end

    test "logs zone_revoked event" do
      log = capture_log(fn -> StructuredLog.info(:zone_revoked, zone: "example.ztlp") end)
      assert log =~ "Zone revoked"
    end

    test "logs query_received event" do
      log = capture_log(fn -> StructuredLog.info(:query_received, name: "web.example.ztlp") end)
      assert log =~ "Query received"
    end

    test "logs query_resolved event" do
      log = capture_log(fn -> StructuredLog.info(:query_resolved, name: "web.example.ztlp") end)
      assert log =~ "Query resolved"
    end

    test "logs query_not_found event" do
      log = capture_log(fn -> StructuredLog.info(:query_not_found, name: "missing.ztlp") end)
      assert log =~ "Query not found"
    end

    test "logs registration_received event" do
      log = capture_log(fn -> StructuredLog.info(:registration_received, name: "new.example.ztlp") end)
      assert log =~ "Registration received"
    end

    test "logs registration_accepted event" do
      log = capture_log(fn -> StructuredLog.info(:registration_accepted, name: "new.example.ztlp") end)
      assert log =~ "Registration accepted"
    end

    test "logs bootstrap_started event" do
      log = capture_log(fn -> StructuredLog.info(:bootstrap_started) end)
      assert log =~ "Bootstrap started"
    end

    test "logs bootstrap_complete event" do
      log = capture_log(fn -> StructuredLog.info(:bootstrap_complete) end)
      assert log =~ "Bootstrap complete"
    end

    test "logs stats_summary event" do
      log = capture_log(fn -> StructuredLog.info(:stats_summary, records: 100, zones: 5) end)
      assert log =~ "Periodic stats"
    end

    test "handles unknown event" do
      log = capture_log(fn -> StructuredLog.info(:some_unknown_event) end)
      assert log =~ "some_unknown_event"
    end
  end

  # ── Debug events ──────────────────────────────────────────────────────

  describe "debug/2" do
    test "logs at debug level" do
      log = capture_log(fn -> StructuredLog.debug(:query_received, name: "test.ztlp") end)
      assert log =~ "Query received"
    end
  end

  # ── Trace events ──────────────────────────────────────────────────────

  describe "trace/2" do
    test "logs at debug level with trace metadata" do
      log = capture_log(fn -> StructuredLog.trace(:query_received, name: "test.ztlp") end)
      assert log =~ "Query received"
    end
  end

  # ── Warn events ───────────────────────────────────────────────────────

  describe "warn/2" do
    test "logs at warn level" do
      log = capture_log(fn -> StructuredLog.warn(:record_expired, name: "old.ztlp") end)
      assert log =~ "Record expired"
    end
  end

  # ── Error events ──────────────────────────────────────────────────────

  describe "error/2" do
    test "logs at error level" do
      log = capture_log(fn -> StructuredLog.error(:zone_revoked, zone: "bad.ztlp", reason: "key_compromised") end)
      assert log =~ "Zone revoked"
    end
  end

  # ── Metadata with structured format ───────────────────────────────────

  describe "structured format integration" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "structured")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "metadata appears in structured output" do
      log = capture_log(fn ->
        StructuredLog.info(:record_created, name: "web.example.ztlp")
      end)
      assert log =~ "event=record_created"
      assert log =~ "name=web.example.ztlp"
    end
  end

  # ── Metadata with JSON format ─────────────────────────────────────────

  describe "json format integration" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "json")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "metadata appears in JSON output" do
      log = capture_log(fn ->
        StructuredLog.info(:record_created, name: "web.example.ztlp")
      end)
      assert log =~ ~s("event":"record_created")
      assert log =~ ~s("name":"web.example.ztlp")
    end

    test "JSON output includes component=ns" do
      log = capture_log(fn ->
        StructuredLog.info(:startup)
      end)
      assert log =~ ~s("component":"ns")
    end
  end
end
