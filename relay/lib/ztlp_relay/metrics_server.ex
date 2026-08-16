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
  @default_bind "127.0.0.1"

  # ── DoS mitigation — CWE-770 (finding cfg-fwqs) ──────────────────────
  #
  # Max concurrent metric-acceptor processes. Each handler holds one slot
  # until the HTTP request completes and the socket is closed. Exceeding
  # this cap closes the socket immediately without spawning a process.
  # A Task.Supervisor with max_children provides an orthogonal second
  # cap (same pattern as gateway/lib/ztlp_gateway/metrics_server.ex's
  # eia-oazy fix): even if the counter-based check races and lets one
  # extra connection through, the supervisor refuses start_child once
  # its own max_children is hit.
  @max_connections 32

  # Per-IP burst window (seconds) and max connections per IP within
  # that window. Protects against a single source flooding the
  # unauthenticated listener. Tunable via `:max_requests_per_ip` and
  # `:rate_window_seconds`.
  @rate_window_seconds 10
  @max_requests_per_ip 20

  # ── Client API ─────────────────────────────────────────────────────

  @doc """
  Start the metrics server GenServer.

  Pass `name: nil` to start a fully isolated, unregistered instance —
  used by tests so they don't collide with (or fight the automatic
  restart of) the permanent instance the app supervision tree starts.
  """
  def start_link(opts \\ []) do
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(_opts) do
    max_conn = max_connections()

    if metrics_enabled?() do
      port = metrics_port()
      bind = metrics_bind()

      supervisor_opts = [
        max_children: max_conn,
        max_restarts: max_conn,
        max_seconds: 60
      ]

      case Task.Supervisor.start_link(supervisor_opts) do
        {:ok, sup} ->
          # [pre-existing bug, found+fixed alongside the eia-oazy/cfg-fwqs
          # DoS mitigation work] :gen_tcp's :ip option requires an erlang
          # ip-address tuple (e.g. {127,0,0,1}), NOT a charlist — the
          # original to_charlist(bind) always raised :badarg the moment
          # this listener actually tried to bind. Never caught by tests
          # because metrics_enabled defaults to false in config/test.exs.
          bind_ip =
            case :inet.parse_address(to_charlist(bind)) do
              {:ok, ip} -> ip
              {:error, _} -> {127, 0, 0, 1}
            end

          case :gen_tcp.listen(port, [
            :binary,
            packet: :http_bin,
            active: false,
            reuseaddr: true,
            backlog: 128,
            ip: bind_ip
          ]) do
            {:ok, listen_socket} ->
              {:ok, actual_port} = :inet.port(listen_socket)
              Logger.info("[metrics] Prometheus endpoint listening on port #{actual_port}")
              # Start acceptor loop
              send(self(), :accept)
              {:ok, %{socket: listen_socket, port: actual_port, supervisor: sup}}

            {:error, reason} ->
              Supervisor.stop(sup, :normal)
              Logger.error("[metrics] Failed to start metrics server on port #{port}: #{inspect(reason)}")
              {:ok, %{socket: nil, port: port, supervisor: nil}}
          end

        {:error, reason} ->
          Logger.error("[metrics] Task.Supervisor failed to start: #{inspect(reason)}")
          {:ok, %{socket: nil, port: port, supervisor: nil}}
      end
    else
      {:ok, %{socket: nil, port: nil, supervisor: nil}}
    end
  end

  @impl true
  def handle_info(:accept, %{socket: nil} = state), do: {:noreply, state}
  def handle_info(:accept, %{socket: listen_socket, supervisor: sup} = state) do
    # Non-blocking accept with short timeout
    case :gen_tcp.accept(listen_socket, 100) do
      {:ok, client} ->
        peer_ip = peer_ip_for(client)

        # DoS gate 1: global concurrent-connection cap
        if maybe_bump_conn_count() do
          # DoS gate 2: per-IP rate limit
          if maybe_burst_check(peer_ip) do
            # Dispatch to supervised task — crashes are contained, no
            # risk to the accept loop.  [CWE-770 cfg-fwqs]
            case Task.Supervisor.start_child(sup, fn ->
                 try do
                   handle_request(client)
                 after
                   untrack_conn()
                 end
               end) do
              {:ok, _pid} ->
                :ok

              {:error, {:max_children, _}} ->
                Logger.warning("[metrics] Connection rejected: supervisor max_children reached")
                :gen_tcp.close(client)
                untrack_conn()

              {:error, reason} ->
                Logger.warning("[metrics] Task.Supervisor failed: #{inspect(reason)}")
                :gen_tcp.close(client)
                untrack_conn()
            end
          else
            # Per-IP rate limited — close the socket, no process spawned
            :inet.setopts(client, [packet: :raw])
            :gen_tcp.send(client, "HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n")
            :gen_tcp.close(client)
          end
        else
          # Global cap hit — close immediately, no process spawned
          Logger.warning("[metrics] Connection rejected: max_connections (#{max_connections()}) reached")
          :gen_tcp.close(client)
        end

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

  # ── DoS mitigation helpers ───────────────────────────────────────
  # Trackers live in :persistent_term so they survive hibernation
  # and are accessible from spawned processes.

  defp peer_ip_for(socket) do
    case :inet.peername(socket) do
      {:ok, {ip, _port}} -> ip
      {:error, _} -> {0, 0, 0, 0}
    end
  end

  defp maybe_bump_conn_count do
    max = max_connections()
    current = :persistent_term.get({__MODULE__, :conns}, 0)
    if current >= max do
      false
    else
      :persistent_term.put({__MODULE__, :conns}, current + 1)
      true
    end
  end

  defp untrack_conn do
    # [SAST fix] :persistent_term.update/2 does not exist — would raise
    # UndefinedFunctionError on every connection teardown. See gateway's
    # metrics_server.ex for the full explanation (identical bug, fixed
    # identically across all 3 apps).
    current = :persistent_term.get({__MODULE__, :conns}, 0)
    :persistent_term.put({__MODULE__, :conns}, max(0, current - 1))
  end

  # Fixed-window burst limiter keyed by IP tuple.
  # [SAST fix] :counters.new/3, :counters.info/2, and 4-arg get/put/add
  # do not exist in the real :counters API (new/2, get/2, add/3, sub/3,
  # put/3, info/1 only) — every call here raised UndefinedFunctionError
  # on the first request, silently swallowed by `rescue _ -> true`,
  # making the per-IP rate limiter a permanent no-op. Fixed to use the
  # real API: :counters.new/2 returns an opaque ref that must be shared
  # via :persistent_term (no name-based registration exists).
  defp maybe_burst_check(ip) do
    max_req = max_requests_per_ip()
    window  = rate_window_seconds()

    now = System.system_time(:second)
    cut = now - window

    ref = burst_counters_ref()
    # Col 1 = window_start (epoch s), Col 2 = request_count
    key = :erlang.phash2(ip, 64) + 1

    start = :counters.get(ref, key * 2 - 1)
    count = :counters.get(ref, key * 2)

    cond do
      start == 0 or start < cut ->
        # Window expired — reset and count this request
        :counters.put(ref, key * 2 - 1, now)
        :counters.put(ref, key * 2, 1)
        true
      count >= max_req ->
        false  # rate limited
      true ->
        :counters.add(ref, key * 2, 1)  # bump count
        true
    end
  rescue
    _ -> true  # if counters are flaky, let the request through
  end

  defp burst_counters_ref do
    case :persistent_term.get({__MODULE__, :burst_counters}, nil) do
      nil ->
        ref = :counters.new(64 * 2, [:atomics])
        :persistent_term.put({__MODULE__, :burst_counters}, ref)
        ref
      ref ->
        ref
    end
  end

  defp max_connections do
    Application.get_env(:ztlp_relay, :metrics_max_connections, @max_connections)
  end

  defp max_requests_per_ip do
    Application.get_env(:ztlp_relay, :metrics_max_requests_per_ip, @max_requests_per_ip)
  end

  defp rate_window_seconds do
    Application.get_env(:ztlp_relay, :metrics_rate_window_seconds, @rate_window_seconds)
  end

  @impl true
  def terminate(_reason, %{socket: nil, supervisor: nil}), do: :ok
  def terminate(_reason, %{socket: nil, supervisor: sup}), do: Supervisor.stop(sup, :normal)
  def terminate(_reason, %{socket: socket, supervisor: sup}) do
    if sup, do: Supervisor.stop(sup, :normal, 5000)
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

  defp handle_path(socket, path) do
    # Normalize path: http_bin returns binary strings, http returns charlists
    path_str = if is_list(path), do: List.to_string(path), else: path
    case path_str do
      "/metrics" ->
        body = collect_metrics()
        send_response(socket, 200, "text/plain; version=0.0.4; charset=utf-8", body)
      "/health" -> send_response(socket, 200, "text/plain", "OK\n")
      "/ready" -> send_response(socket, 200, "text/plain", "OK\n")
      _ -> send_response(socket, 404, "text/plain", "Not Found\n")
    end
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

  defp metrics_bind do
    case System.get_env("ZTLP_RELAY_METRICS_BIND") do
      nil -> Application.get_env(:ztlp_relay, :metrics_bind, @default_bind)
      bind -> bind
    end
  end
end
