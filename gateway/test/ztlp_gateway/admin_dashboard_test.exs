defmodule ZtlpGateway.AdminDashboardTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.AdminDashboard

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp get_dashboard_port do
    # Always (re)configure the token so it matches @test_token
    # regardless of whether the dashboard GenServer was already
    # running (e.g. started by the app supervisor before any test in
    # this file executed, with dashboard_token unset/nil) — the
    # config is read per-request, not cached at process start, so
    # this takes effect immediately without needing a restart.
    Application.put_env(:ztlp_gateway, :dashboard_token, test_token())

    # The Application supervisor starts AdminDashboard automatically.
    # It may have failed to bind (port in use) so port can be nil.
    # In that case, restart it on port 0 (OS-assigned).
    case GenServer.whereis(AdminDashboard) do
      nil ->
        start_fresh_dashboard()

      _pid ->
        case AdminDashboard.port() do
          nil ->
            # Existing instance has no socket (port conflict or disabled).
            # Stop and restart on a random port.
            start_fresh_dashboard()

          port when is_integer(port) and port > 0 ->
            port
        end
    end
  end

  defp start_fresh_dashboard do
    # Set port to 0 BEFORE stopping, so when the supervisor restarts
    # the process, it will bind to a random port instead of 9105.
    Application.put_env(:ztlp_gateway, :dashboard_enabled, true)
    Application.put_env(:ztlp_gateway, :dashboard_port, 0)
    Application.put_env(:ztlp_gateway, :dashboard_token, test_token())

    case GenServer.whereis(AdminDashboard) do
      nil ->
        {:ok, _pid} = AdminDashboard.start_link([])
        AdminDashboard.port()

      _pid ->
        port = AdminDashboard.port()

        if is_integer(port) and port > 0 do
          # Already running with a valid port
          port
        else
          # Running but no valid port — stop and let supervisor restart with port 0
          do_stop()
          # Let the supervisor restart it (now with port=0)
          Process.sleep(300)

          case GenServer.whereis(AdminDashboard) do
            nil ->
              # Supervisor didn't restart — start manually
              {:ok, _pid} = AdminDashboard.start_link([])
              AdminDashboard.port()

            _pid2 ->
              AdminDashboard.port()
          end
        end
    end
  end

  defp do_stop do
    case GenServer.whereis(AdminDashboard) do
      nil ->
        :ok

      pid ->
        try do
          GenServer.stop(pid, :normal, 5_000)
        catch
          :exit, _ -> :ok
        end

        ref = Process.monitor(pid)

        receive do
          {:DOWN, ^ref, :process, ^pid, _} -> :ok
        after
          2_000 -> :ok
        end
    end
  end



  # Fixed (not per-process) so that every test in this file agrees on
  # the token regardless of which test's process happened to trigger
  # start_fresh_dashboard/0 first — the dashboard GenServer persists
  # across tests within a run (only started/reconfigured once), so a
  # process-derived token would only match the ONE test that set it.
  @test_token "test-dashboard-token-fixed-for-suite"
  defp test_token, do: @test_token

  defp http_get(port, path, headers \\ []) do
    {:ok, socket} =
      :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])

    header_lines =
      Enum.map(headers, fn {k, v} -> "#{k}: #{v}\r\n" end)
      |> Enum.join("")

    :gen_tcp.send(
      socket,
      "GET #{path} HTTP/1.1\r\nHost: localhost\r\n#{header_lines}Connection: close\r\n\r\n"
    )

    {:ok, response} = recv_all(socket, <<>>)
    :gen_tcp.close(socket)
    parse_response(response)
  end

  defp authed_get(port, path) do
    http_get(port, path, [{"Authorization", "Bearer #{test_token()}"}])
  end

  defp recv_all(socket, acc) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} -> recv_all(socket, acc <> data)
      {:error, :closed} -> {:ok, acc}
      {:error, _} = err -> err
    end
  end

  defp parse_response(raw) do
    case String.split(raw, "\r\n\r\n", parts: 2) do
      [headers, body] ->
        [status_line | header_lines] = String.split(headers, "\r\n")
        [_, code_str | _] = String.split(status_line, " ", parts: 3)
        status = String.to_integer(code_str)

        header_map =
          header_lines
          |> Enum.map(fn line ->
            case String.split(line, ": ", parts: 2) do
              [k, v] -> {String.downcase(k), v}
              _ -> nil
            end
          end)
          |> Enum.reject(&is_nil/1)
          |> Map.new()

        %{status: status, headers: header_map, body: body}

      _ ->
        %{status: 0, headers: %{}, body: raw}
    end
  end

  # ---------------------------------------------------------------------------
  # Tests
  # ---------------------------------------------------------------------------

  describe "dashboard starts and listens" do
    test "starts on configured port" do
      port = get_dashboard_port()
      assert is_integer(port)
      assert port > 0
    end
  end

  describe "GET / returns HTML" do
    test "returns 200 with text/html content-type" do
      port = get_dashboard_port()
      %{status: status, headers: headers, body: body} = authed_get(port, "/")
      assert status == 200
      assert String.contains?(headers["content-type"], "text/html")
      assert String.contains?(body, "ZTLP Gateway Dashboard")
      assert String.contains?(body, "/api/stats")
    end

    test "rejects request with no Authorization header (gae-cymv)" do
      port = get_dashboard_port()
      %{status: status} = http_get(port, "/")
      assert status == 401
    end

    test "rejects request with a wrong bearer token" do
      port = get_dashboard_port()
      %{status: status} = http_get(port, "/", [{"Authorization", "Bearer wrong-token"}])
      assert status == 401
    end

    test "accepts a ?token= query param on the initial page load" do
      port = get_dashboard_port()
      %{status: status} = http_get(port, "/?token=#{test_token()}")
      assert status == 200
    end
  end

  describe "GET /api/stats returns JSON" do
    test "returns 200 with application/json content-type" do
      port = get_dashboard_port()
      %{status: status, headers: headers} = authed_get(port, "/api/stats")
      assert status == 200
      assert String.contains?(headers["content-type"], "application/json")
    end

    test "rejects unauthenticated /api/stats requests (gae-cymv)" do
      port = get_dashboard_port()
      %{status: status} = http_get(port, "/api/stats")
      assert status == 401
    end

    test "response no longer sends Access-Control-Allow-Origin: * (gae-cymv)" do
      port = get_dashboard_port()
      %{headers: headers} = authed_get(port, "/api/stats")
      refute Map.has_key?(headers, "access-control-allow-origin")
    end

    test "JSON contains expected top-level keys" do
      port = get_dashboard_port()
      %{body: body} = authed_get(port, "/api/stats")
      assert String.contains?(body, "\"hostname\"")
      assert String.contains?(body, "\"uptime_seconds\"")
      assert String.contains?(body, "\"sessions\"")
      assert String.contains?(body, "\"system\"")
    end

    test "system stats contain process_count, memory_mb, schedulers" do
      port = get_dashboard_port()
      %{body: body} = authed_get(port, "/api/stats")
      assert String.contains?(body, "\"process_count\"")
      assert String.contains?(body, "\"memory_mb\"")
      assert String.contains?(body, "\"schedulers\"")
    end
  end

  describe "no token configured (fail-closed)" do
    test "rejects every request when dashboard_token is unset" do
      port = get_dashboard_port()
      Application.delete_env(:ztlp_gateway, :dashboard_token)
      on_exit(fn -> Application.put_env(:ztlp_gateway, :dashboard_token, test_token()) end)

      %{status: status} = authed_get(port, "/")
      assert status == 401
    end
  end

  describe "404 for unknown paths" do
    test "returns 404 for /nonexistent" do
      port = get_dashboard_port()
      %{status: status} = authed_get(port, "/nonexistent")
      assert status == 404
    end
  end

  describe "dashboard disabled" do
    test "init returns nil port when dashboard_enabled is false" do
      # Test the init logic directly without fighting the supervisor
      Application.put_env(:ztlp_gateway, :dashboard_enabled, false)

      # Call init directly to verify it returns nil port state
      {:ok, state} = AdminDashboard.init([])
      assert state.port == nil
      assert state.socket == nil
    after
      Application.put_env(:ztlp_gateway, :dashboard_enabled, true)
    end
  end

  describe "collect_stats/0" do
    test "returns a map with expected structure" do
      _port = get_dashboard_port()
      stats = AdminDashboard.collect_stats()
      assert is_map(stats)
      assert is_binary(stats.hostname)
      assert is_integer(stats.uptime_seconds)
      assert is_map(stats.sessions)
      assert is_integer(stats.sessions.total)
      assert is_list(stats.sessions.list)
      assert is_map(stats.system)
      assert is_integer(stats.system.process_count)
      assert is_integer(stats.system.memory_mb)
      assert is_integer(stats.system.schedulers)
    end
  end
end
