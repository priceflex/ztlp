defmodule ZtlpNs.MetricsServerTest do
  use ExUnit.Case, async: false

  # ── CWE-770 regression tests ─────────────────────────────────────
  #
  # Mirrors gateway/test/ztlp_gateway/metrics_server_test.exs (eia-oazy)
  # and relay/test/ztlp_relay/metrics_server_test.exs (cfg-fwqs): the
  # NS metrics TCP listener used to spawn an UNTRACKED, uncapped process
  # per connection via a raw spawn_link/1, letting a remote client
  # exhaust the BEAM process table / file descriptors.
  #
  # After the fix there are two layers:
  #   1. A counter-based gate (persistent_term) that caps concurrent
  #      handlers and closes new sockets when the cap is reached.
  #   2. A Task.Supervisor with max_children that provides an orthogonal
  #      hard cap — even if the counter races, the supervisor rejects
  #      start_child when max_children is exceeded.
  #
  # Unlike gateway/relay, this MetricsServer's init/1 already accepts
  # `enabled:`/`port:` opts directly (a pre-existing test-friendliness
  # feature), so isolation is simpler: pass `name: nil, enabled: true,
  # port: <ephemeral>` per test instead of touching global Application
  # env at all.

  @moduletag :capture_log

  defp start_isolated(port) do
    case ZtlpNs.MetricsServer.start_link(name: nil, enabled: true, port: port) do
      {:ok, pid} -> {:ok, pid}
    end
  end

  defp cleanup(pid) do
    if Process.alive?(pid) do
      GenServer.stop(pid)
    end

    Application.delete_env(:ztlp_ns, :metrics_max_connections)
    Application.delete_env(:ztlp_ns, :metrics_max_requests_per_ip)
    Application.delete_env(:ztlp_ns, :metrics_rate_window_seconds)
    :persistent_term.erase({ZtlpNs.MetricsServer, :conns})
    :persistent_term.erase({ZtlpNs.MetricsServer, :burst_counters})
    :ok
  end

  setup do
    :persistent_term.erase({ZtlpNs.MetricsServer, :conns})
    :persistent_term.erase({ZtlpNs.MetricsServer, :burst_counters})

    {:ok, []}
  end

  describe "Task.Supervisor is used instead of raw spawn (CWE-770)" do
    test "Task.Supervisor is started with max_children set" do
      port = 22_500 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_ns, :metrics_max_connections, 5)

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

  describe "max_connections cap (CWE-770)" do
    test "connections beyond the cap are rejected" do
      port = 22_600 + :erlang.phash2(node(), 100)

      Application.put_env(:ztlp_ns, :metrics_max_connections, 2)
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
      port = 22_700 + :erlang.phash2(node(), 100)

      Application.put_env(:ztlp_ns, :metrics_max_connections, 2)
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
      port = 22_800 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_ns, :metrics_max_connections, 100)

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
  end

  # ── CWE-200 htb-ojqx / CWE-79 oaq-mmqh regression tests ────────────
  #
  # /token_status previously returned per-device identity (name, node_id,
  # zone, enrolled_at) via raw string interpolation into a JSON literal.
  # Verify the fixed endpoint (a) only exposes zone-level aggregates, not
  # per-device identity, and (b) is immune to JSON injection via a
  # maliciously-named enrollment (proper JSON encoding via Jason).
  describe "/token_status (CWE-200 / CWE-79)" do
    setup do
      ZtlpNs.Enrollment.init()
      :ets.delete_all_objects(:ztlp_enrollment_log)
      on_exit(fn -> :ets.delete_all_objects(:ztlp_enrollment_log) end)
      :ok
    end

    defp insert_enrollment(name, node_id, zone, enrolled_at) do
      entry = %{name: name, node_id: node_id, pubkey: "deadbeef", zone: zone, enrolled_at: enrolled_at}
      :ets.insert(:ztlp_enrollment_log, {{enrolled_at, name}, entry})
    end

    defp get_token_status(port) do
      {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1000)
      :gen_tcp.send(sock, "GET /token_status HTTP/1.1\r\nHost: localhost\r\n\r\n")
      {:ok, data} = :gen_tcp.recv(sock, 0, 1000)
      :gen_tcp.close(sock)
      # Strip HTTP headers, keep body
      [_headers, body] = String.split(data, "\r\n\r\n", parts: 2)
      body
    end

    test "response does not expose per-device name or node_id" do
      port = 22_950 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_ns, :metrics_max_connections, 5)
      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      insert_enrollment("laptop-alice", "aabbccdd", "zone-a", 1_000)
      insert_enrollment("phone-bob", "eeff0011", "zone-a", 1_001)
      insert_enrollment("server-charlie", "22334455", "zone-b", 1_002)

      body = get_token_status(port)
      {:ok, parsed} = Jason.decode(body)

      # No device names or node_ids anywhere in the response.
      refute body =~ "laptop-alice"
      refute body =~ "phone-bob"
      refute body =~ "server-charlie"
      refute body =~ "aabbccdd"
      refute body =~ "eeff0011"
      refute body =~ "22334455"

      # But zone-level aggregation IS present and correct.
      zones = parsed["enrollments"] |> Enum.into(%{}, fn e -> {e["zone"], e["count"]} end)
      assert zones["zone-a"] == 2
      assert zones["zone-b"] == 1

      cleanup(pid)
    end

    test "a malicious device name cannot corrupt the JSON response" do
      port = 23_050 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_ns, :metrics_max_connections, 5)
      {:ok, pid} = start_isolated(port)
      :timer.sleep(100)

      # This name would have broken the old string-interpolation format:
      # closing the string, injecting a bogus JSON key, and re-opening.
      malicious_name = ~s(x","injected":"pwned)
      insert_enrollment(malicious_name, "aabbccdd", "evil-zone", 1_000)

      body = get_token_status(port)

      # Must still be valid, parseable JSON -- proves Jason.encode! is
      # actually being used rather than string interpolation.
      assert {:ok, parsed} = Jason.decode(body)
      refute Map.has_key?(parsed, "injected")
      # The zone value itself should be encoded verbatim (zones aren't
      # attacker-controlled the same way device names are, but confirm
      # aggregation by zone still doesn't leak the malicious name).
      refute body =~ malicious_name

      cleanup(pid)
    end
  end

  describe "termination cleans up supervisor" do
    test "stopping the server stops the task supervisor" do
      port = 22_900 + :erlang.phash2(node(), 100)
      Application.put_env(:ztlp_ns, :metrics_max_connections, 5)

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

      Application.delete_env(:ztlp_ns, :metrics_max_connections)
    end
  end
end
