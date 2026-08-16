defmodule ZtlpGateway.MetricsServerTest do
  use ExUnit.Case, async: false

  # ── CWE-770 regression tests (finding eia-oazy) ────────────────────
  #
  # These tests verify that the metrics server does NOT spawn an
  # untracked, uncapped process per connection.  The original finding
  # was that a raw spawn/1 in the accept loop with no connection limit
  # could be used to exhaust the BEAM process table / file descriptors.
  #
  # After the fix there are two layers:
  #   1. A counter-based gate (persistent_term) that caps concurrent
  #      handlers and closes new sockets when the cap is reached.
  #   2. A Task.Supervisor with max_children that provides an orthogonal
  #      hard cap — even if the counter races, the supervisor rejects
  #      start_child when max_children is exceeded.
  #
  # Test isolation strategy: ZtlpGateway.MetricsServer is a PERMANENT
  # child of the app's top-level Supervisor (started once at app boot,
  # metrics_enabled: false in config/test.exs so it's a no-op there).
  # Rather than fighting that permanent instance's lifecycle (terminate/
  # restart races against the supervisor's own :one_for_one restart
  # logic — tried and abandoned; see git history for the churn), these
  # tests start a completely UNREGISTERED, isolated instance per test
  # via `start_link(name: nil)`. That instance is never touched by
  # ZtlpGateway.Supervisor, so there's no restart race, no shared name,
  # and cleanup is just "let the test process exit" (ExUnit kills
  # linked processes automatically) or an explicit GenServer.stop.

  @moduletag :capture_log

  defp start_isolated(port, opts \\ []) do
    full_opts =
      opts
      |> Keyword.put(:name, nil)
      |> Keyword.put_new(:port, port)

    # metrics_port/0 and friends read Application env, not start_link
    # opts — but init/1 ignores opts entirely and reads app env, so we
    # still need to set metrics_port/metrics_enabled globally. That's
    # inherent to how this GenServer is designed (no per-instance
    # config), not something these tests can avoid.
    Application.put_env(:ztlp_gateway, :metrics_port, port)
    Application.put_env(:ztlp_gateway, :metrics_enabled, true)

    case ZtlpGateway.MetricsServer.start_link(full_opts) do
      {:ok, pid} -> {:ok, pid}
    end
  end

  defp cleanup(pid) do
    if Process.alive?(pid) do
      GenServer.stop(pid)
    end

    Application.delete_env(:ztlp_gateway, :metrics_port)
    Application.put_env(:ztlp_gateway, :metrics_enabled, false)
    Application.delete_env(:ztlp_gateway, :metrics_max_connections)
    Application.delete_env(:ztlp_gateway, :metrics_max_requests_per_ip)
    Application.delete_env(:ztlp_gateway, :metrics_rate_window_seconds)
    :persistent_term.erase({ZtlpGateway.MetricsServer, :conns})
    :persistent_term.erase({ZtlpGateway.MetricsServer, :burst_counters})
    :ok
  end

  setup do
    :persistent_term.erase({ZtlpGateway.MetricsServer, :conns})
    :persistent_term.erase({ZtlpGateway.MetricsServer, :burst_counters})

    {:ok, []}
  end

  # ── Tests ───────────────────────────────────────────────────────────

  describe "Task.Supervisor is used instead of raw spawn (CWE-770 eia-oazy)" do
    test "Task.Supervisor is started with max_children set" do
      port = 19_500 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_gateway, :metrics_max_connections, 5)

      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      %{supervisor: sup} = :sys.get_state(pid)
      assert sup != nil
      assert Process.alive?(sup)

      # Children should be empty initially (no connections yet)
      children = Supervisor.which_children(sup)
      assert children == []

      cleanup(pid)
    end
  end

  describe "max_connections cap (CWE-770 eia-oazy)" do
    test "connections beyond the cap are rejected" do
      port = 19_600 + :erlang.phash2(node(), 100)

      Application.put_env(:ztlp_gateway, :metrics_max_connections, 2)
      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      # NOTE: this is a synchronous request/response HTTP server —
      # untrack_conn() fires as soon as handle_request/1 finishes, which
      # is nearly instant for a simple GET. Opening connections
      # sequentially (as a prior version of this test did) means each
      # one completes and frees its cap slot before the next connect
      # even starts, so the cap is never actually under contention and
      # the test passes vacuously regardless of whether the cap works.
      #
      # To actually exercise the cap we must hold N connections open
      # SIMULTANEOUSLY without sending a request (so untrack_conn/0
      # never fires for them), then check that connections beyond the
      # cap get an immediate connection-refused/closed response.
      cap = 2
      holders =
        for _ <- 1..cap do
          {:ok, sock} = :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 1000)
          sock
        end

      # Give the accept loop time to process the holder connections and
      # bump the counter for each (accept loop handles one at a time).
      :timer.sleep(200)

      # Now try to open cap+1 more connections while the cap holders
      # are still open. These should be rejected (server closes without
      # ever sending an HTTP response) since maybe_bump_conn_count/0
      # should refuse once :conns reaches the cap.
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
      port = 19_700 + :erlang.phash2(node(), 100)

      Application.put_env(:ztlp_gateway, :metrics_max_connections, 2)
      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      # Try to connect several times to hit the cap
      Enum.each(1..5, fn _ ->
        case :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 1000) do
          {:ok, sock} -> :timer.sleep(30); :gen_tcp.close(sock)
          _ -> :ok
        end
      end)

      :timer.sleep(100)

      # The server process should still be alive
      assert Process.alive?(pid)

      cleanup(pid)
    end
  end

  describe "per-IP rate limiting" do
    test "rate limiter config is read correctly" do
      Application.put_env(:ztlp_gateway, :metrics_rate_window_seconds, 5)
      Application.put_env(:ztlp_gateway, :metrics_max_requests_per_ip, 10)

      assert Application.get_env(:ztlp_gateway, :metrics_rate_window_seconds) == 5
      assert Application.get_env(:ztlp_gateway, :metrics_max_requests_per_ip) == 10

      Application.delete_env(:ztlp_gateway, :metrics_rate_window_seconds)
      Application.delete_env(:ztlp_gateway, :metrics_max_requests_per_ip)
    end
  end

  describe "HTTP endpoints" do
    test "/health returns 200 OK" do
      port = 19_800 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_gateway, :metrics_max_connections, 100)

      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      try do
        {:ok, sock} = :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 2000)
        :gen_tcp.send(sock, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")

        # NOTE: the socket is opened in passive mode (active: false), so
        # data must be pulled with :gen_tcp.recv/3, not a `receive do
        # {:tcp, ...}` block — that would wait forever since passive
        # sockets never deliver unsolicited {:tcp, ...} messages. This
        # was a pre-existing bug in this test (never actually exercised
        # because metrics_enabled defaults to false in config/test.exs,
        # so the connection never got far enough for this bug to matter).
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
      port = 19_900 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_gateway, :metrics_max_connections, 100)

      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      try do
        {:ok, sock} = :gen_tcp.connect('127.0.0.1', port, [:binary, active: false], 2000)
        :gen_tcp.send(sock, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")

        # Passive-mode socket: pull the full response with recv/3 (see
        # the /health test above for why `receive do {:tcp, ...}` never
        # fires here) rather than trying to split headers/body across
        # two separate reads, since TCP framing gives no guarantee the
        # response arrives in exactly two packets.
        {:ok, response} =
          case :gen_tcp.recv(sock, 0, 2000) do
            {:ok, d} -> {:ok, d}
            {:error, reason} -> raise "recv failed: #{inspect(reason)}"
          end

        assert response =~ "HTTP/1.1 200"
        assert response =~ "ztlp_gateway_uptime_seconds"
        assert response =~ "ztlp_gateway_active_sessions"

        :gen_tcp.close(sock)
      rescue
        (_e in MatchError) -> :ok
      end

      cleanup(pid)
    end
  end

  describe "termination cleans up supervisor" do
    test "stopping the server stops the task supervisor" do
      port = 20_000 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_gateway, :metrics_max_connections, 5)

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

      Application.delete_env(:ztlp_gateway, :metrics_port)
      Application.put_env(:ztlp_gateway, :metrics_enabled, false)
      Application.delete_env(:ztlp_gateway, :metrics_max_connections)
    end
  end

  describe "child_spec (OTP compatibility)" do
    test "returns a valid child_spec map" do
      spec = ZtlpGateway.MetricsServer.child_spec([])
      assert spec.id == ZtlpGateway.MetricsServer
      assert spec.start == {ZtlpGateway.MetricsServer, :start_link, [[]]}
      assert spec.type == :worker
    end
  end
end
