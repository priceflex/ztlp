defmodule ZtlpGateway.AuditCollectorTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.AuditCollector

  # The app supervisor starts AuditCollector; just clean the table between tests.
  setup do
    # Ensure app is started (brings up AuditCollector via supervisor)
    Application.ensure_all_started(:ztlp_gateway)

    # Clear existing events and reset counter
    :ets.delete_all_objects(:ztlp_gateway_audit_events)
    :ets.insert(:ztlp_gateway_audit_counter, {:next_id, 0})
    :ok
  end

  defp get_or_start_http_server do
    # Check if the named server already has a working port
    case GenServer.whereis(ZtlpGateway.AuditCollectorServer) do
      nil ->
        start_ephemeral_http_server()

      _pid ->
        port = ZtlpGateway.AuditCollectorServer.port()

        if port do
          {nil, port}
        else
          # Named server has no port (failed to bind); start unnamed ephemeral server
          start_ephemeral_http_server()
        end
    end
  end

  defp start_ephemeral_http_server do
    Application.put_env(:ztlp_gateway, :audit_port, 0)
    {:ok, pid} = GenServer.start(ZtlpGateway.AuditCollectorServer, [], [])
    port = GenServer.call(pid, :get_port)
    {pid, port}
  end

  # ── Test 1: log_event stores event with correct fields ──

  test "log_event stores event with correct fields" do
    AuditCollector.log_event(%{
      event: "session.created",
      component: "gateway",
      level: "info",
      service: "vault",
      username: "steve",
      source_ip: "10.0.0.1",
      details: %{session_id: "abc123"}
    })

    result = AuditCollector.query()
    assert result.total == 1
    [event] = result.events

    assert event.id == 1
    assert event.event == "session.created"
    assert event.component == "gateway"
    assert event.level == "info"
    assert event.service == "vault"
    assert event.username == "steve"
    assert event.source_ip == "10.0.0.1"
    assert event.details == %{session_id: "abc123"}
    assert is_binary(event.timestamp)
    assert is_binary(event.hostname)
  end

  # ── Test 2: query with no filters returns all events (up to limit) ──

  test "query with no filters returns all events up to limit" do
    for i <- 1..5 do
      AuditCollector.log_event(%{
        event: "test.event.#{i}",
        component: "gateway",
        level: "info"
      })
    end

    result = AuditCollector.query()
    assert result.total == 5
    assert length(result.events) == 5

    # Default limit is 100 but with limit 3
    result = AuditCollector.query(limit: 3)
    assert result.total == 5
    assert length(result.events) == 3
  end

  # ── Test 3: query with component filter ──

  test "query with component filter" do
    AuditCollector.log_event(%{event: "e1", component: "gateway", level: "info"})
    AuditCollector.log_event(%{event: "e2", component: "ns", level: "info"})
    AuditCollector.log_event(%{event: "e3", component: "gateway", level: "warn"})

    result = AuditCollector.query(component: "gateway")
    assert result.total == 2
    assert Enum.all?(result.events, fn e -> e.component == "gateway" end)

    result = AuditCollector.query(component: "ns")
    assert result.total == 1
    assert hd(result.events).event == "e2"
  end

  # ── Test 4: query with level filter ──

  test "query with level filter" do
    AuditCollector.log_event(%{event: "e1", component: "gateway", level: "info"})
    AuditCollector.log_event(%{event: "e2", component: "gateway", level: "error"})
    AuditCollector.log_event(%{event: "e3", component: "gateway", level: "info"})

    result = AuditCollector.query(level: "error")
    assert result.total == 1
    assert hd(result.events).event == "e2"
  end

  # ── Test 5: query with time range filter ──

  test "query with time range filter" do
    # Insert events with explicit timestamps
    AuditCollector.log_event(%{
      event: "old",
      component: "gateway",
      level: "info",
      timestamp: "2025-01-01T00:00:00Z"
    })

    AuditCollector.log_event(%{
      event: "mid",
      component: "gateway",
      level: "info",
      timestamp: "2026-03-15T12:00:00Z"
    })

    AuditCollector.log_event(%{
      event: "new",
      component: "gateway",
      level: "info",
      timestamp: "2026-03-29T20:00:00Z"
    })

    # Since filter
    result = AuditCollector.query(since: "2026-03-01T00:00:00Z")
    assert result.total == 2
    events = Enum.map(result.events, & &1.event)
    assert "mid" in events
    assert "new" in events

    # Until filter
    result = AuditCollector.query(until: "2026-03-20T00:00:00Z")
    assert result.total == 2
    events = Enum.map(result.events, & &1.event)
    assert "old" in events
    assert "mid" in events

    # Combined range
    result = AuditCollector.query(since: "2026-03-01T00:00:00Z", until: "2026-03-20T00:00:00Z")
    assert result.total == 1
    assert hd(result.events).event == "mid"
  end

  # ── Test 6: stats returns correct counts ──

  test "stats returns correct counts" do
    AuditCollector.log_event(%{event: "e1", component: "gateway", level: "info", service: "vault"})
    AuditCollector.log_event(%{event: "e2", component: "ns", level: "warn", service: "vault"})
    AuditCollector.log_event(%{event: "e3", component: "gateway", level: "error", service: "api"})
    AuditCollector.log_event(%{event: "e4", component: "relay", level: "info"})

    stats = AuditCollector.stats()
    assert stats.total_events == 4
    assert stats.by_component == %{"gateway" => 2, "ns" => 1, "relay" => 1}
    assert stats.by_level == %{"info" => 2, "warn" => 1, "error" => 1}
    assert stats.by_service == %{"vault" => 2, "api" => 1}
    assert is_binary(stats.oldest_event)
    assert is_binary(stats.newest_event)
  end

  # ── Test 7: retention sweep removes old events ──

  test "retention sweep removes old events" do
    # Insert an event with a very old timestamp
    AuditCollector.log_event(%{
      event: "ancient",
      component: "gateway",
      level: "info",
      timestamp: "2020-01-01T00:00:00Z"
    })

    # Insert a recent event
    AuditCollector.log_event(%{
      event: "recent",
      component: "gateway",
      level: "info"
    })

    # Force a sweep
    AuditCollector.sweep()

    result = AuditCollector.query()
    assert result.total == 1
    assert hd(result.events).event == "recent"
  end

  # ── Test 8: max events cap enforced ──

  test "max events cap enforced" do
    # Set a low cap for testing
    original = Application.get_env(:ztlp_gateway, :audit_max_events)
    Application.put_env(:ztlp_gateway, :audit_max_events, 5)

    try do
      for i <- 1..10 do
        AuditCollector.log_event(%{
          event: "event_#{i}",
          component: "gateway",
          level: "info"
        })
      end

      result = AuditCollector.query(limit: 100)
      # Should be capped at 5
      assert result.total == 5
      # Should have the newest events (highest IDs)
      events = result.events
      assert Enum.all?(events, fn e -> e.id > 5 end)
    after
      if original do
        Application.put_env(:ztlp_gateway, :audit_max_events, original)
      else
        Application.delete_env(:ztlp_gateway, :audit_max_events)
      end
    end
  end

  # ── Test 9: HTTP API returns JSON for /audit/events ──

  test "HTTP API returns JSON for /audit/events" do
    AuditCollector.log_event(%{
      event: "test.http",
      component: "gateway",
      level: "info",
      service: "vault"
    })

    {_pid, port} = get_or_start_http_server()

    if port do
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      :gen_tcp.send(socket, "GET /audit/events?component=gateway HTTP/1.1\r\nHost: localhost\r\n\r\n")

      {:ok, response} = :gen_tcp.recv(socket, 0, 5_000)
      :gen_tcp.close(socket)

      assert response =~ "HTTP/1.1 200 OK"
      assert response =~ "application/json"
      assert response =~ "test.http"
      assert response =~ "\"total\""
    end
  end

  # ── Test 10: HTTP API returns JSON for /audit/stats ──

  test "HTTP API returns JSON for /audit/stats" do
    AuditCollector.log_event(%{
      event: "test.stats",
      component: "ns",
      level: "warn"
    })

    {_pid, port} = get_or_start_http_server()

    if port do
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      :gen_tcp.send(socket, "GET /audit/stats HTTP/1.1\r\nHost: localhost\r\n\r\n")

      {:ok, response} = :gen_tcp.recv(socket, 0, 5_000)
      :gen_tcp.close(socket)

      assert response =~ "HTTP/1.1 200 OK"
      assert response =~ "application/json"
      assert response =~ "total_events"
      assert response =~ "by_component"
    end
  end

  # ── Wire protocol 0x15 ──

  test "handle_wire_event parses valid JSON and stores event" do
    json = ~s({"event":"session_established","component":"ns","level":"info","hostname":"ns-1"})
    packet = <<0x15>> <> json

    assert :ok == AuditCollector.handle_wire_event(packet)

    result = AuditCollector.query()
    assert result.total == 1
    assert hd(result.events).event == "session_established"
    assert hd(result.events).component == "ns"
    assert hd(result.events).hostname == "ns-1"
  end

  test "handle_wire_event rejects invalid JSON" do
    packet = <<0x15>> <> "not json"
    assert {:error, :invalid_json} == AuditCollector.handle_wire_event(packet)
  end

  test "handle_wire_event rejects missing required fields" do
    json = ~s({"event":"test"})
    packet = <<0x15>> <> json
    assert {:error, :missing_fields} == AuditCollector.handle_wire_event(packet)
  end

  test "handle_wire_event rejects wrong opcode" do
    assert {:error, :invalid_opcode} == AuditCollector.handle_wire_event(<<0x99, "test">>)
  end

  # ── JSON encode/decode round-trip ──

  test "json_encode and json_decode round-trip" do
    original = %{
      "name" => "test",
      "count" => 42,
      "active" => true,
      "tags" => ["a", "b"],
      "nested" => %{"key" => "value"}
    }

    encoded = AuditCollector.json_encode(original)
    assert is_binary(encoded)

    {:ok, decoded} = AuditCollector.json_decode(encoded)
    assert decoded["name"] == "test"
    assert decoded["count"] == 42
    assert decoded["active"] == true
    assert decoded["tags"] == ["a", "b"]
    assert decoded["nested"]["key"] == "value"
  end

  # ── Query with offset/pagination ──

  test "query with offset supports pagination" do
    for i <- 1..10 do
      AuditCollector.log_event(%{event: "page_#{i}", component: "gateway", level: "info"})
    end

    page1 = AuditCollector.query(limit: 3, offset: 0)
    assert length(page1.events) == 3
    assert page1.total == 10

    page2 = AuditCollector.query(limit: 3, offset: 3)
    assert length(page2.events) == 3

    # No overlap between pages
    ids1 = Enum.map(page1.events, & &1.id)
    ids2 = Enum.map(page2.events, & &1.id)
    assert MapSet.disjoint?(MapSet.new(ids1), MapSet.new(ids2))
  end

  # ── Auto-incrementing ID ──

  test "events get auto-incrementing IDs" do
    AuditCollector.log_event(%{event: "first", component: "gateway", level: "info"})
    AuditCollector.log_event(%{event: "second", component: "gateway", level: "info"})
    AuditCollector.log_event(%{event: "third", component: "gateway", level: "info"})

    result = AuditCollector.query()
    ids = Enum.map(result.events, & &1.id) |> Enum.sort()
    assert ids == [1, 2, 3]
  end

  # ── Disabled audit ──

  test "log_event is a no-op when audit is disabled" do
    Application.put_env(:ztlp_gateway, :audit_enabled, false)

    try do
      AuditCollector.log_event(%{event: "should_not_store", component: "gateway", level: "info"})
      result = AuditCollector.query()
      assert result.total == 0
    after
      Application.delete_env(:ztlp_gateway, :audit_enabled)
    end
  end
end
