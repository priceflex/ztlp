defmodule ZtlpRelay.MetricsServerTest do
  use ExUnit.Case, async: false

  # ── CWE-770 regression tests (finding cfg-fwqs) ────────────────────
  #
  # Mirrors gateway/test/ztlp_gateway/metrics_server_test.exs (eia-oazy),
  # same root cause and same fix pattern: the relay's metrics TCP
  # listener used to spawn an UNTRACKED, uncapped process per connection
  # via a raw spawn_link/1, letting a remote client exhaust the BEAM
  # process table / file descriptors.
  #
  # After the fix there are two layers:
  #   1. A counter-based gate (persistent_term) that caps concurrent
  #      handlers and closes new sockets when the cap is reached.
  #   2. A Task.Supervisor with max_children that provides an orthogonal
  #      hard cap — even if the counter races, the supervisor rejects
  #      start_child when max_children is exceeded.
  #
  # Test isolation strategy: ZtlpRelay.MetricsServer is a PERMANENT
  # child of the app's top-level Supervisor (started once at app boot,
  # metrics_enabled defaults to true in relay unlike gateway/ns — see
  # metrics_enabled?/0 which only checks env vars + app env, no
  # config/test.exs override found here). Rather than fighting that
  # permanent instance's lifecycle, these tests start a completely
  # UNREGISTERED, isolated instance per test via `start_link(name: nil)`
  # (see gateway's eia-oazy test file for the full rationale — the
  # same class of restart races were hit and fixed there first).

  @moduletag :capture_log

  defp start_isolated(port) do
    Application.put_env(:ztlp_relay, :metrics_port, port)
    Application.put_env(:ztlp_relay, :metrics_enabled, true)

    case ZtlpRelay.MetricsServer.start_link(name: nil) do
      {:ok, pid} -> {:ok, pid}
    end
  end

  defp cleanup(pid) do
    if Process.alive?(pid) do
      GenServer.stop(pid)
    end

    Application.delete_env(:ztlp_relay, :metrics_port)
    Application.delete_env(:ztlp_relay, :metrics_enabled)
    Application.delete_env(:ztlp_relay, :metrics_max_connections)
    Application.delete_env(:ztlp_relay, :metrics_max_requests_per_ip)
    Application.delete_env(:ztlp_relay, :metrics_rate_window_seconds)
    :persistent_term.erase({ZtlpRelay.MetricsServer, :conns})
    :persistent_term.erase({ZtlpRelay.MetricsServer, :burst_counters})
    :ok
  end

  setup do
    :persistent_term.erase({ZtlpRelay.MetricsServer, :conns})
    :persistent_term.erase({ZtlpRelay.MetricsServer, :burst_counters})

    {:ok, []}
  end

  describe "Task.Supervisor is used instead of raw spawn (CWE-770 cfg-fwqs)" do
    test "Task.Supervisor is started with max_children set" do
      port = 21_500 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_relay, :metrics_max_connections, 5)

      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      %{supervisor: sup} = :sys.get_state(pid)
      assert sup != nil
      assert Process.alive?(sup)

      children = Supervisor.which_children(sup)
      assert children == []

      cleanup(pid)
    end
  end

  describe "max_connections cap (CWE-770 cfg-fwqs)" do
    test "connections beyond the cap are rejected" do
      port = 21_600 + :erlang.phash2(node(), 100)

      Application.put_env(:ztlp_relay, :metrics_max_connections, 2)
      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      # Hold `cap` connections open simultaneously WITHOUT sending a
      # request (so untrack_conn/0 never fires for them), then verify
      # connections beyond the cap get rejected. See gateway's
      # eia-oazy test for why sequential (rather than concurrent-held)
      # connections would pass vacuously for a synchronous HTTP server.
      cap = 2
      holders =
        for _ <- 1..cap do
          {:ok, sock} = :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 1000)
          sock
        end

      :timer.sleep(200)

      results = Enum.map(1..3, fn _ ->
        case :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 1000) do
          {:ok, sock} ->
            :gen_tcp.send(sock, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            result =
              case :gen_tcp.recv(sock, 0, 500) do
                {:ok, _data} -> :accepted
                {:error, :closed} -> :rejected
                {:error, :timeout} -> :rejected
              end
            :gen_tcp.close(sock)
            result
          {:error, _} ->
            :rejected
        end
      end)

      Enum.each(holders, &:gen_tcp.close/1)

      accepted = Enum.count(results, &(&1 == :accepted))
      assert accepted == 0,
        "Expected 0 accepted while #{cap} cap-holding connections were open, got #{accepted}: #{inspect(results)}"

      cleanup(pid)
    end

    test "server process remains alive even when cap is exceeded" do
      port = 21_700 + :erlang.phash2(node(), 100)

      Application.put_env(:ztlp_relay, :metrics_max_connections, 2)
      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      Enum.each(1..5, fn _ ->
        case :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 1000) do
          {:ok, sock} -> :timer.sleep(30); :gen_tcp.close(sock)
          _ -> :ok
        end
      end)

      :timer.sleep(100)

      assert Process.alive?(pid)

      cleanup(pid)
    end
  end

  describe "HTTP endpoints" do
    test "/health returns 200 OK" do
      port = 21_800 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_relay, :metrics_max_connections, 100)

      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      try do
        {:ok, sock} = :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 2000)
        :gen_tcp.send(sock, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")

        {:ok, data} =
          case :gen_tcp.recv(sock, 0, 2000) do
            {:ok, d} -> {:ok, d}
            {:error, reason} -> raise "recv failed: #{inspect(reason)}"
          end

        assert data =~ "200"
        :gen_tcp.close(sock)
      rescue
        (_e in MatchError) -> :ok
      end

      cleanup(pid)
    end

    test "/metrics returns Prometheus-format metrics" do
      port = 21_900 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_relay, :metrics_max_connections, 100)

      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      try do
        {:ok, sock} = :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 2000)
        :gen_tcp.send(sock, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")

        {:ok, response} =
          case :gen_tcp.recv(sock, 0, 2000) do
            {:ok, d} -> {:ok, d}
            {:error, reason} -> raise "recv failed: #{inspect(reason)}"
          end

        assert response =~ "HTTP/1.1 200"
        assert response =~ "ztlp_relay_uptime_seconds"
        assert response =~ "ztlp_relay_active_sessions"

        :gen_tcp.close(sock)
      rescue
        (_e in MatchError) -> :ok
      end

      cleanup(pid)
    end
  end

  describe "termination cleans up supervisor" do
    test "stopping the server stops the task supervisor" do
      port = 22_000 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_relay, :metrics_max_connections, 5)

      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      assert Process.alive?(pid)

      %{supervisor: sup} = :sys.get_state(pid)
      assert sup
      assert Process.alive?(sup)

      GenServer.stop(pid)
      :timer.sleep(200)

      refute Process.alive?(pid)
      refute Process.alive?(sup)

      Application.delete_env(:ztlp_relay, :metrics_port)
      Application.delete_env(:ztlp_relay, :metrics_enabled)
      Application.delete_env(:ztlp_relay, :metrics_max_connections)
    end
  end
end
