defmodule ZtlpGateway.MetricsServer do
  @moduledoc """
  Minimal HTTP server for Prometheus metrics scraping on the Gateway.

  Default port: 9102. Endpoints: /metrics, /health, /ready.
  Uses raw `:gen_tcp` — zero external dependencies.
  """

  use GenServer
  require Logger

  @default_port 9102

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    if metrics_enabled?() do
      port = metrics_port()
      case :gen_tcp.listen(port, [:binary, packet: :http_bin, active: false, reuseaddr: true, backlog: 128]) do
        {:ok, listen_socket} ->
          {:ok, actual_port} = :inet.port(listen_socket)
          Logger.info("[metrics] Gateway Prometheus endpoint on port #{actual_port}")
          send(self(), :accept)
          {:ok, %{socket: listen_socket, port: actual_port}}
        {:error, reason} ->
          Logger.error("[metrics] Failed to start on port #{port}: #{inspect(reason)}")
          {:ok, %{socket: nil, port: port}}
      end
    else
      {:ok, %{socket: nil, port: nil}}
    end
  end

  @impl true
  def handle_info(:accept, %{socket: nil} = state), do: {:noreply, state}
  def handle_info(:accept, %{socket: ls} = state) do
    case :gen_tcp.accept(ls, 100) do
      {:ok, client} ->
        spawn(fn -> handle_request(client) end)
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
  def terminate(_reason, %{socket: nil}), do: :ok
  def terminate(_reason, %{socket: s}), do: :gen_tcp.close(s)

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

  # ── Helpers ──────────────────────────────────────────────────────

  defp metrics_enabled? do
    Application.get_env(:ztlp_gateway, :metrics_enabled, true)
  end

  defp metrics_port do
    Application.get_env(:ztlp_gateway, :metrics_port, @default_port)
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
