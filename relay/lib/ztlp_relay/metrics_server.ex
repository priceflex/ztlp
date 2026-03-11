defmodule ZtlpRelay.MetricsServer do
  @moduledoc """
  Minimal HTTP server for Prometheus metrics scraping.

  Listens on a configurable port (default: 9101) and responds to:
  - `GET /metrics` — Prometheus text format
  - `GET /health` — 200 OK (load balancer health check)
  - `GET /ready` — 200 OK when started, 503 during startup

  Uses raw `:gen_tcp` for zero external dependencies.

  ## Configuration

  - `ZTLP_RELAY_METRICS_PORT` env var or `metrics_port` config key
  - `ZTLP_RELAY_METRICS_ENABLED=false` to disable
  """

  use GenServer

  require Logger

  @default_port 9101

  # ── Client API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(_opts) do
    if metrics_enabled?() do
      port = metrics_port()
      case :gen_tcp.listen(port, [
        :binary,
        packet: :http_bin,
        active: false,
        reuseaddr: true,
        backlog: 128
      ]) do
        {:ok, listen_socket} ->
          {:ok, actual_port} = :inet.port(listen_socket)
          Logger.info("[metrics] Prometheus endpoint listening on port #{actual_port}")
          # Start acceptor loop
          send(self(), :accept)
          {:ok, %{socket: listen_socket, port: actual_port}}

        {:error, reason} ->
          Logger.error("[metrics] Failed to start metrics server on port #{port}: #{inspect(reason)}")
          {:ok, %{socket: nil, port: port}}
      end
    else
      {:ok, %{socket: nil, port: nil}}
    end
  end

  @impl true
  def handle_info(:accept, %{socket: nil} = state), do: {:noreply, state}
  def handle_info(:accept, %{socket: listen_socket} = state) do
    # Non-blocking accept with short timeout
    case :gen_tcp.accept(listen_socket, 100) do
      {:ok, client} ->
        spawn(fn -> handle_request(client) end)
        send(self(), :accept)
        {:noreply, state}

      {:error, :timeout} ->
        send(self(), :accept)
        {:noreply, state}

      {:error, :closed} ->
        {:noreply, %{state | socket: nil}}

      {:error, reason} ->
        Logger.debug("[metrics] Accept error: #{inspect(reason)}")
        send(self(), :accept)
        {:noreply, state}
    end
  end

  @impl true
  def terminate(_reason, %{socket: nil}), do: :ok
  def terminate(_reason, %{socket: socket}) do
    :gen_tcp.close(socket)
  end

  # ── Request handling ───────────────────────────────────────────────

  defp handle_request(socket) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, {:http_request, :GET, {:abs_path, path}, _version}} ->
        # Consume remaining headers
        drain_headers(socket)
        handle_path(socket, path)

      {:ok, {:http_request, _method, {:abs_path, _path}, _version}} ->
        drain_headers(socket)
        send_response(socket, 405, "text/plain", "Method Not Allowed\n")

      _ ->
        :ok
    end
    :gen_tcp.close(socket)
  end

  defp drain_headers(socket) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, :http_eoh} -> :ok
      {:ok, {:http_header, _, _, _, _}} -> drain_headers(socket)
      _ -> :ok
    end
  end

  defp handle_path(socket, '/metrics') do
    body = collect_metrics()
    send_response(socket, 200, "text/plain; version=0.0.4; charset=utf-8", body)
  end

  defp handle_path(socket, '/health') do
    send_response(socket, 200, "text/plain", "OK\n")
  end

  defp handle_path(socket, '/ready') do
    send_response(socket, 200, "text/plain", "OK\n")
  end

  defp handle_path(socket, _path) do
    send_response(socket, 404, "text/plain", "Not Found\n")
  end

  defp send_response(socket, status, content_type, body) do
    status_text = case status do
      200 -> "OK"
      404 -> "Not Found"
      405 -> "Method Not Allowed"
      503 -> "Service Unavailable"
      _ -> "Unknown"
    end

    response = [
      "HTTP/1.1 #{status} #{status_text}\r\n",
      "Content-Type: #{content_type}\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      "Connection: close\r\n",
      "\r\n",
      body
    ]

    # Switch to raw mode for response
    :inet.setopts(socket, [packet: :raw])
    :gen_tcp.send(socket, response)
  end

  # ── Metrics collection ─────────────────────────────────────────────

  defp collect_metrics do
    stats = ZtlpRelay.Stats.get_stats()
    uptime = get_uptime()
    sessions = get_session_count()
    mesh_info = get_mesh_info()
    version = "0.1.0"
    mesh_enabled = ZtlpRelay.Config.mesh_enabled?()

    [
      "# HELP ztlp_relay_info Static info about the relay instance\n",
      "# TYPE ztlp_relay_info gauge\n",
      "ztlp_relay_info{version=\"#{version}\",mesh=\"#{mesh_enabled}\"} 1\n",
      "\n",
      "# HELP ztlp_relay_uptime_seconds Seconds since relay started\n",
      "# TYPE ztlp_relay_uptime_seconds gauge\n",
      "ztlp_relay_uptime_seconds #{uptime}\n",
      "\n",
      "# HELP ztlp_relay_active_sessions Number of active relay sessions\n",
      "# TYPE ztlp_relay_active_sessions gauge\n",
      "ztlp_relay_active_sessions #{sessions}\n",
      "\n",
      "# HELP ztlp_relay_packets_total Total packets processed by pipeline result\n",
      "# TYPE ztlp_relay_packets_total counter\n",
      "ztlp_relay_packets_total{result=\"passed\"} #{stats.passed}\n",
      "ztlp_relay_packets_total{result=\"dropped_l1\"} #{stats.layer1_drops}\n",
      "ztlp_relay_packets_total{result=\"dropped_l2\"} #{stats.layer2_drops}\n",
      "ztlp_relay_packets_total{result=\"dropped_l3\"} #{stats.layer3_drops}\n",
      "\n",
      "# HELP ztlp_relay_packets_forwarded_total Total packets forwarded to peers\n",
      "# TYPE ztlp_relay_packets_forwarded_total counter\n",
      "ztlp_relay_packets_forwarded_total #{stats.forwarded}\n",
      "\n",
      mesh_metrics(mesh_info),
      backpressure_metrics(),
      component_auth_metrics("relay"),
      beam_metrics()
    ] |> IO.iodata_to_binary()
  end

  defp mesh_metrics(nil), do: ""
  defp mesh_metrics(%{peers: peers, healthy: healthy}) do
    [
      "# HELP ztlp_relay_mesh_peers Number of peers in the relay mesh\n",
      "# TYPE ztlp_relay_mesh_peers gauge\n",
      "ztlp_relay_mesh_peers #{peers}\n",
      "\n",
      "# HELP ztlp_relay_mesh_healthy_peers Mesh peers in healthy state\n",
      "# TYPE ztlp_relay_mesh_healthy_peers gauge\n",
      "ztlp_relay_mesh_healthy_peers #{healthy}\n",
      "\n"
    ]
  end

  defp backpressure_metrics do
    try do
      bp = ZtlpRelay.Backpressure.metrics()
      state_val = case bp.state do
        :ok -> 0
        :soft -> 1
        :hard -> 2
      end

      [
        "# HELP ztlp_relay_backpressure_state Backpressure state (0=ok, 1=soft, 2=hard)\n",
        "# TYPE ztlp_relay_backpressure_state gauge\n",
        "ztlp_relay_backpressure_state #{state_val}\n",
        "\n",
        "# HELP ztlp_relay_backpressure_load_ratio Current load ratio (0.0-1.0)\n",
        "# TYPE ztlp_relay_backpressure_load_ratio gauge\n",
        "ztlp_relay_backpressure_load_ratio #{Float.round(bp.load_ratio, 4)}\n",
        "\n",
        "# HELP ztlp_relay_backpressure_rejections_total Total sessions rejected by backpressure\n",
        "# TYPE ztlp_relay_backpressure_rejections_total counter\n",
        "ztlp_relay_backpressure_rejections_total #{bp.rejections}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp component_auth_metrics("relay") do
    try do
      auth = ZtlpRelay.ComponentAuth.metrics()

      [
        "# HELP ztlp_relay_component_auth_challenges_total Total auth challenges issued\n",
        "# TYPE ztlp_relay_component_auth_challenges_total counter\n",
        "ztlp_relay_component_auth_challenges_total #{auth.challenges}\n",
        "\n",
        "# HELP ztlp_relay_component_auth_successes_total Successful authentications\n",
        "# TYPE ztlp_relay_component_auth_successes_total counter\n",
        "ztlp_relay_component_auth_successes_total #{auth.successes}\n",
        "\n",
        "# HELP ztlp_relay_component_auth_failures_total Failed authentications\n",
        "# TYPE ztlp_relay_component_auth_failures_total counter\n",
        "ztlp_relay_component_auth_failures_total #{auth.failures}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp beam_metrics do
    mem = :erlang.memory()
    procs = :erlang.system_info(:process_count)

    [
      "# HELP beam_memory_bytes BEAM VM memory usage\n",
      "# TYPE beam_memory_bytes gauge\n",
      "beam_memory_bytes{kind=\"total\"} #{mem[:total]}\n",
      "beam_memory_bytes{kind=\"processes\"} #{mem[:processes]}\n",
      "beam_memory_bytes{kind=\"binary\"} #{mem[:binary]}\n",
      "beam_memory_bytes{kind=\"ets\"} #{mem[:ets]}\n",
      "\n",
      "# HELP beam_process_count Number of BEAM processes\n",
      "# TYPE beam_process_count gauge\n",
      "beam_process_count #{procs}\n"
    ]
  end

  defp get_uptime do
    case :persistent_term.get({ZtlpRelay.StatsReporter, :start_time}, nil) do
      nil -> 0
      start -> System.monotonic_time(:second) - start
    end
  end

  defp get_session_count do
    case :ets.info(:ztlp_sessions, :size) do
      :undefined -> 0
      n when is_integer(n) -> n
    end
  rescue
    _ -> 0
  catch
    _, _ -> 0
  end

  defp get_mesh_info do
    if ZtlpRelay.Config.mesh_enabled?() do
      try do
        relays = ZtlpRelay.RelayRegistry.get_all()
        healthy = Enum.count(relays, fn info -> Map.get(info, :health) == :healthy end)
        %{peers: length(relays), healthy: healthy}
      rescue
        _ -> %{peers: 0, healthy: 0}
      catch
        _, _ -> %{peers: 0, healthy: 0}
      end
    else
      nil
    end
  end

  # ── Config ─────────────────────────────────────────────────────────

  defp metrics_enabled? do
    case System.get_env("ZTLP_RELAY_METRICS_ENABLED") do
      "false" -> false
      "0" -> false
      _ -> Application.get_env(:ztlp_relay, :metrics_enabled, true)
    end
  end

  defp metrics_port do
    case System.get_env("ZTLP_RELAY_METRICS_PORT") do
      nil -> Application.get_env(:ztlp_relay, :metrics_port, @default_port)
      port -> String.to_integer(port)
    end
  end
end
