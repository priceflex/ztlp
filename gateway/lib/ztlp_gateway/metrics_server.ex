defmodule ZtlpGateway.MetricsServer do
  @moduledoc """
  Minimal HTTP server for Prometheus metrics scraping on the Gateway.

  Default port: 9102. Endpoints: /metrics, /health, /ready.
  Uses raw `:gen_tcp` — zero external dependencies.

  ## DoS Mitigation (CWE-770 — eia-oazy)

  Three layers protect the BEAM process table and file descriptors:

  1. **Global connection cap** (`max_connections`, default 300) — the accept
     loop counts in-flight handlers in `:persistent_term` and closes new
     sockets immediately once the cap is reached.  No process is spawned for
     connections that would exceed the limit.

  2. **Per-IP rate limiter** (`max_requests_per_ip`, default 20 per 10 s) — a
     single source cannot hold the listener busy with a rapid burst.  Returns
     HTTP 429 when the per-IP quota is exceeded.

  3. **Supervised handlers** — each accepted connection is dispatched to a
     `Task.Supervisor` child instead of a raw `spawn/1`.  Crashed handlers are
     reaped automatically; they cannot take down the accept-loop GenServer.
     The supervisor's `max_children` is set to the same `max_connections`
     value, providing a second, orthogonal cap.
  """

  use GenServer
  require Logger

  @default_port 9102
  @default_bind "127.0.0.1"

  # ── DoS mitigation — CWE-770 (finding eia-oazy) ──────────────────────
  #
  # Max concurrent metric-acceptor processes.  Each handler holds one slot
  # until the HTTP request completes and the socket is closed.  Exceeding
  # this cap closes the socket immediately without spawning a process.
  #
  # 300 is well above any legitimate scraping rate (Prometheus defaults to
  # one scrape every 15 s per target) while keeping the process table and
  # file-descriptor footprint bounded.  Tunable via
  # `:metrics_max_connections` in app env.
  @max_connections 300

  # Per-IP burst window (seconds) and max connections per IP within
  # that window.  Protects against a single source flooding the
  # unauthenticated listener.  Tunable via `:metrics_max_requests_per_ip`
  # and `:metrics_rate_window_seconds`.
  @rate_window_seconds 10
  @max_requests_per_ip 20

  @doc false
  def child_spec(opts \\ []) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker
    }
  end

  @doc """
  Start the metrics server GenServer.

  Pass `name: nil` to start a fully isolated, unregistered instance —
  used by tests so they don't collide with (or fight the automatic
  restart of) the permanent instance the app supervision tree starts.
  Any other name (or omitting `:name`) registers under that name,
  defaulting to `__MODULE__` for the production/app-supervised case.
  """
  def start_link(opts \\ []) do
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  # ── GenServer callbacks ───────────────────────────────────────────────

  @impl true
  def init(_opts) do
    max_conn = max_connections()

    if metrics_enabled?() do
      port = metrics_port()
      bind = metrics_bind()

      # Task.Supervisor with max_children = max_connections provides an
      # orthogonal second cap: even if the counter-based check races and
      # allows one extra connection through, the supervisor refuses the
      # start_child call (max_children exceeded) and we fall through to a
      # safe close-without-spawn.  [CWE-770 eia-oazy]
      #
      # Deliberately UNNAMED: this GenServer itself can be started
      # unregistered (see start_link/1's `name: nil` test path), and a
      # hardcoded global name here would collide across concurrent
      # unregistered instances. The supervisor pid is threaded through
      # GenServer state and referenced by pid everywhere below, so a
      # registered name was never actually needed for correctness.
      supervisor_opts = [
        max_children: max_conn,
        max_restarts: max_conn,
        max_seconds: 60
      ]

      case Task.Supervisor.start_link(supervisor_opts) do
        {:ok, sup} ->
          # [pre-existing bug, found+fixed while stabilizing the
          # eia-oazy regression tests] :gen_tcp's :ip option requires
          # an erlang ip-address tuple (e.g. {127,0,0,1}), NOT a
          # charlist — passing to_charlist(bind) always raised :badarg
          # and crashed init/1. This path was never exercised before
          # because metrics_enabled defaults to false in config/test.exs,
          # so no test had ever actually booted this listener until the
          # eia-oazy test suite explicitly flipped it on.
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
              Logger.info("[metrics] Gateway Prometheus endpoint on port #{actual_port}")
              send(self(), :accept)
              {:ok, %{socket: listen_socket, port: actual_port, supervisor: sup}}

            {:error, reason} ->
              Supervisor.stop(sup, :normal)
              Logger.error("[metrics] Failed to start on port #{port}: #{inspect(reason)}")
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

  def handle_info(:accept, %{socket: ls, supervisor: sup} = state) do
    case :gen_tcp.accept(ls, 100) do
      {:ok, client} ->
        peer_ip = peer_ip_for(client)

        # DoS gate 1: global concurrent-connection cap
        if maybe_bump_conn_count() do
          # DoS gate 2: per-IP rate limit
          if maybe_burst_check(peer_ip) do
            # Dispatch to supervised task — crashes are contained, no
            # risk to the accept loop.  [CWE-770 eia-oazy]
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
                # Supervisor's own cap kicked in (race window above).
                # Close the socket without spawning.
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
            :gen_tcp.send(client,
              "HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n"
            )
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

      {:error, _} ->
        send(self(), :accept)
        {:noreply, state}
    end
  end

  @impl true
  def terminate(_reason, %{socket: nil, supervisor: nil}), do: :ok
  def terminate(_reason, %{socket: nil, supervisor: sup}), do: Supervisor.stop(sup, :normal)
  def terminate(_reason, %{socket: s, supervisor: sup}) do
    Supervisor.stop(sup, :normal, 5000)
    :gen_tcp.close(s)
  end

  # ── DoS mitigation helpers ────────────────────────────────────────────
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
    # :persistent_term has no update/2 — use read-modify-write.
    # Non-atomic by design: this counter is an approximation for DoS
    # protection, not a hard correctness invariant.  The Task.Supervisor's
    # max_children provides the hard cap.  [CWE-770 eia-oazy]
    current = :persistent_term.get({__MODULE__, :conns}, 0)
    :persistent_term.put({__MODULE__, :conns}, max(0, current - 1))
  end

  # Fixed-window burst limiter keyed by IP tuple.
  # :counters gives O(1) atomic ops without locks.
  # [SAST fix] The original code called non-existent :counters variants;
  # fixed to use only real API: new/2, get/2, add/3, put/3, info/1.
  defp maybe_burst_check(ip) do
    max_req = max_requests_per_ip()
    window = rate_window_seconds()

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

  # Lazily create (once, process-safe via persistent_term's
  # copy-on-write semantics) the shared :counters reference used by
  # the burst limiter. 64 IP buckets x 2 columns (window_start, count).
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
    Application.get_env(:ztlp_gateway, :metrics_max_connections, @max_connections)
  end

  defp max_requests_per_ip do
    Application.get_env(:ztlp_gateway, :metrics_max_requests_per_ip, @max_requests_per_ip)
  end

  defp rate_window_seconds do
    Application.get_env(:ztlp_gateway, :metrics_rate_window_seconds, @rate_window_seconds)
  end

  # ── HTTP handler ──────────────────────────────────────────────────────

  defp handle_request(socket) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, {:http_request, :GET, {:abs_path, path}, _}} ->
        drain_headers(socket)
        handle_path(socket, path)

      {:ok, {:http_request, _, _, _}} ->
        drain_headers(socket)
        send_response(socket, 405, "Method Not Allowed\n")

      _ -> :ok
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
        send_response(socket, 200, body, "text/plain; version=0.0.4; charset=utf-8")

      "/health" -> send_response(socket, 200, "OK\n")
      "/ready" -> send_response(socket, 200, "OK\n")
      _ -> send_response(socket, 404, "Not Found\n")
    end
  end

  defp send_response(socket, status, body, ct \\ "text/plain") do
    status_text = case status do
      200 -> "OK"; 404 -> "Not Found"; 405 -> "Method Not Allowed"; _ -> "Error"
    end

    :inet.setopts(socket, [packet: :raw])
    :gen_tcp.send(socket, [
      "HTTP/1.1 #{status} #{status_text}\r\n",
      "Content-Type: #{ct}\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      "Connection: close\r\n\r\n",
      body
    ])
  end

  defp collect_metrics do
    stats = ZtlpGateway.Stats.snapshot()
    uptime = get_uptime()

    [
      "# HELP ztlp_gateway_info Static info\n",
      "# TYPE ztlp_gateway_info gauge\n",
      "ztlp_gateway_info{version=\"0.1.0\"} 1\n\n",
      "# HELP ztlp_gateway_uptime_seconds Seconds since gateway started\n",
      "# TYPE ztlp_gateway_uptime_seconds gauge\n",
      "ztlp_gateway_uptime_seconds #{uptime}\n\n",
      "# HELP ztlp_gateway_active_sessions Current active sessions\n",
      "# TYPE ztlp_gateway_active_sessions gauge\n",
      "ztlp_gateway_active_sessions #{stats.active_sessions}\n\n",
      "# HELP ztlp_gateway_bytes_received_total Bytes received from clients\n",
      "# TYPE ztlp_gateway_bytes_received_total counter\n",
      "ztlp_gateway_bytes_received_total #{stats.bytes_in}\n\n",
      "# HELP ztlp_gateway_bytes_sent_total Bytes sent to clients\n",
      "# TYPE ztlp_gateway_bytes_sent_total counter\n",
      "ztlp_gateway_bytes_sent_total #{stats.bytes_out}\n\n",
      "# HELP ztlp_gateway_handshakes_total Handshake attempts\n",
      "# TYPE ztlp_gateway_handshakes_total counter\n",
      "ztlp_gateway_handshakes_total{result=\"ok\"} #{stats.handshakes_ok}\n",
      "ztlp_gateway_handshakes_total{result=\"fail\"} #{stats.handshakes_fail}\n\n",
      "# HELP ztlp_gateway_policy_denials_total Policy denials\n",
      "# TYPE ztlp_gateway_policy_denials_total counter\n",
      "ztlp_gateway_policy_denials_total #{stats.policy_denials}\n\n",
      "# HELP ztlp_gateway_backend_errors_total Backend errors\n",
      "# TYPE ztlp_gateway_backend_errors_total counter\n",
      "ztlp_gateway_backend_errors_total #{stats.backend_errors}\n\n",
      circuit_breaker_metrics(),
      gateway_component_auth_metrics(),
      tls_metrics(),
      beam_metrics()
    ] |> IO.iodata_to_binary()
  end

  defp circuit_breaker_metrics do
    try do
      backends = ZtlpGateway.CircuitBreaker.metrics()

      if backends == [] do
        ""
      else
        state_lines = Enum.map(backends, fn b ->
          state_val = case b.state do
            :closed -> 0
            :open -> 1
            :half_open -> 2
          end
          "ztlp_gateway_circuit_breaker_state{backend=\"#{b.backend}\"} #{state_val}\n"
        end)

        trips_lines = Enum.map(backends, fn b ->
          "ztlp_gateway_circuit_breaker_trips_total{backend=\"#{b.backend}\"} #{b.trips}\n"
        end)

        successes_lines = Enum.map(backends, fn b ->
          "ztlp_gateway_circuit_breaker_successes_total{backend=\"#{b.backend}\"} #{b.successes}\n"
        end)

        failures_lines = Enum.map(backends, fn b ->
          "ztlp_gateway_circuit_breaker_failures_total{backend=\"#{b.backend}\"} #{b.failures}\n"
        end)

        [
          "# HELP ztlp_gateway_circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half_open)\n",
          "# TYPE ztlp_gateway_circuit_breaker_state gauge\n",
          state_lines,
          "\n",
          "# HELP ztlp_gateway_circuit_breaker_trips_total Times circuit breaker tripped to open\n",
          "# TYPE ztlp_gateway_circuit_breaker_trips_total counter\n",
          trips_lines,
          "\n",
          "# HELP ztlp_gateway_circuit_breaker_successes_total Successful requests through circuit breaker\n",
          "# TYPE ztlp_gateway_circuit_breaker_successes_total counter\n",
          successes_lines,
          "\n",
          "# HELP ztlp_gateway_circuit_breaker_failures_total Failed requests through circuit breaker\n",
          "# TYPE ztlp_gateway_circuit_breaker_failures_total counter\n",
          failures_lines,
          "\n"
        ]
      end
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp gateway_component_auth_metrics do
    try do
      auth = ZtlpGateway.ComponentAuth.metrics()

      [
        "# HELP ztlp_gateway_component_auth_challenges_total Total auth challenges issued\n",
        "# TYPE ztlp_gateway_component_auth_challenges_total counter\n",
        "ztlp_gateway_component_auth_challenges_total #{auth.challenges}\n",
        "\n",
        "# HELP ztlp_gateway_component_auth_successes_total Successful authentications\n",
        "# TYPE ztlp_gateway_component_auth_successes_total counter\n",
        "ztlp_gateway_component_auth_successes_total #{auth.successes}\n",
        "\n",
        "# HELP ztlp_gateway_component_auth_failures_total Failed authentications\n",
        "# TYPE ztlp_gateway_component_auth_failures_total counter\n",
        "ztlp_gateway_component_auth_failures_total #{auth.failures}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp tls_metrics do
    try do
      tls_stats = ZtlpGateway.TlsListener.stats()

      [
        "# HELP ztlp_gateway_tls_connections_total TLS connections by status\n",
        "# TYPE ztlp_gateway_tls_connections_total counter\n",
        "ztlp_gateway_tls_connections_total{status=\"established\"} #{Map.get(tls_stats, :established, 0)}\n",
        "ztlp_gateway_tls_connections_total{status=\"rejected\"} #{Map.get(tls_stats, :rejected, 0)}\n",
        "ztlp_gateway_tls_connections_total{status=\"error\"} #{Map.get(tls_stats, :errors, 0)}\n",
        "\n",
        "# HELP ztlp_gateway_tls_connections_active Active TLS connections\n",
        "# TYPE ztlp_gateway_tls_connections_active gauge\n",
        "ztlp_gateway_tls_connections_active #{Map.get(tls_stats, :active, 0)}\n",
        "\n",
        "# HELP ztlp_gateway_tls_mtls_auth_total mTLS authentication results\n",
        "# TYPE ztlp_gateway_tls_mtls_auth_total counter\n",
        "ztlp_gateway_tls_mtls_auth_total{result=\"success\"} #{Map.get(tls_stats, :mtls_success, 0)}\n",
        "ztlp_gateway_tls_mtls_auth_total{result=\"failure\"} #{Map.get(tls_stats, :mtls_failure, 0)}\n",
        "ztlp_gateway_tls_mtls_auth_total{result=\"none\"} #{Map.get(tls_stats, :mtls_none, 0)}\n",
        "\n",
        "# HELP ztlp_gateway_tls_cert_renewals_total Certificate renewals\n",
        "# TYPE ztlp_gateway_tls_cert_renewals_total counter\n",
        "ztlp_gateway_tls_cert_renewals_total{status=\"success\"} #{Map.get(tls_stats, :cert_renewals_ok, 0)}\n",
        "ztlp_gateway_tls_cert_renewals_total{status=\"failure\"} #{Map.get(tls_stats, :cert_renewals_fail, 0)}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  # ── Helpers ───────────────────────────────────────────────────────────

  defp metrics_enabled? do
    Application.get_env(:ztlp_gateway, :metrics_enabled, true)
  end

  defp metrics_port do
    Application.get_env(:ztlp_gateway, :metrics_port, @default_port)
  end

  defp metrics_bind do
    case System.get_env("ZTLP_GATEWAY_METRICS_BIND") do
      nil -> Application.get_env(:ztlp_gateway, :metrics_bind, @default_bind)
      bind -> bind
    end
  end

  defp get_uptime do
    {total_ms, _since_last} = :erlang.statistics(:wall_clock)
    div(total_ms, 1000)
  end

  defp beam_metrics do
    try do
      mem = :erlang.memory()
      procs = :erlang.system_info(:process_count)
      {reductions, _} = :erlang.statistics(:reductions)

      [
        "# HELP erlang_memory_bytes BEAM memory usage\n",
        "# TYPE erlang_memory_bytes gauge\n",
        "erlang_memory_bytes{type=\"total\"} #{Keyword.get(mem, :total, 0)}\n",
        "erlang_memory_bytes{type=\"processes\"} #{Keyword.get(mem, :processes, 0)}\n",
        "erlang_memory_bytes{type=\"binary\"} #{Keyword.get(mem, :binary, 0)}\n",
        "erlang_memory_bytes{type=\"ets\"} #{Keyword.get(mem, :ets, 0)}\n",
        "\n",
        "# HELP erlang_processes BEAM process count\n",
        "# TYPE erlang_processes gauge\n",
        "erlang_processes #{procs}\n",
        "\n",
        "# HELP erlang_reductions_total BEAM reductions\n",
        "# TYPE erlang_reductions_total counter\n",
        "erlang_reductions_total #{reductions}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end
end
