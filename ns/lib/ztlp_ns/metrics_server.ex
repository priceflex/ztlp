defmodule ZtlpNs.MetricsServer do
  @moduledoc """
  Minimal HTTP server for Prometheus metrics scraping on ZTLP-NS.

  Default port: 9103. Endpoints: /metrics, /health, /ready.
  Uses raw `:gen_tcp` — zero external dependencies.
  """

  use GenServer
  require Logger

  @default_port 9103

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    :persistent_term.put({__MODULE__, :start_time}, System.monotonic_time(:second))

    if metrics_enabled?() do
      port = metrics_port()
      case :gen_tcp.listen(port, [:binary, packet: :http_bin, active: false, reuseaddr: true, backlog: 128]) do
        {:ok, ls} ->
          {:ok, actual_port} = :inet.port(ls)
          Logger.info("[metrics] NS Prometheus endpoint on port #{actual_port}")
          send(self(), :accept)
          {:ok, %{socket: ls, port: actual_port}}
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
      {:error, :closed} -> {:noreply, %{state | socket: nil}}
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
      {:ok, {:http_request, :GET, {:abs_path, '/metrics'}, _}} ->
        drain_headers(socket)
        body = collect_metrics()
        send_response(socket, 200, body, "text/plain; version=0.0.4; charset=utf-8")
      {:ok, {:http_request, :GET, {:abs_path, '/health'}, _}} ->
        drain_headers(socket)
        send_response(socket, 200, "OK\n")
      {:ok, {:http_request, :GET, {:abs_path, '/ready'}, _}} ->
        drain_headers(socket)
        send_response(socket, 200, "OK\n")
      {:ok, {:http_request, :GET, _, _}} ->
        drain_headers(socket)
        send_response(socket, 404, "Not Found\n")
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
    uptime = System.monotonic_time(:second) - :persistent_term.get({__MODULE__, :start_time}, 0)
    records = get_record_count()
    storage = ZtlpNs.Config.storage_mode()

    [
      "# HELP ztlp_ns_info Static info\n# TYPE ztlp_ns_info gauge\n",
      "ztlp_ns_info{version=\"0.1.0\",storage=\"#{storage}\"} 1\n\n",
      "# HELP ztlp_ns_uptime_seconds Seconds since NS started\n# TYPE ztlp_ns_uptime_seconds gauge\n",
      "ztlp_ns_uptime_seconds #{uptime}\n\n",
      "# HELP ztlp_ns_records_total Records in the store\n# TYPE ztlp_ns_records_total gauge\n",
      "ztlp_ns_records_total #{records}\n\n",
      antientropy_metrics(),
      replication_metrics(),
      ratelimit_metrics(),
      cluster_metrics(),
      ns_component_auth_metrics(),
      beam_metrics()
    ] |> IO.iodata_to_binary()
  end

  defp get_record_count do
    try do
      :mnesia.table_info(:ztlp_ns_records, :size)
    rescue
      _ -> 0
    catch
      _, _ -> 0
    end
  end

  defp antientropy_metrics do
    try do
      ae = ZtlpNs.AntiEntropy.metrics()

      [
        "# HELP ztlp_ns_antientropy_syncs_total Total anti-entropy sync attempts\n",
        "# TYPE ztlp_ns_antientropy_syncs_total counter\n",
        "ztlp_ns_antientropy_syncs_total #{ae.syncs_total}\n",
        "\n",
        "# HELP ztlp_ns_antientropy_syncs_needed_total Syncs where data was exchanged\n",
        "# TYPE ztlp_ns_antientropy_syncs_needed_total counter\n",
        "ztlp_ns_antientropy_syncs_needed_total #{ae.syncs_needed}\n",
        "\n",
        "# HELP ztlp_ns_antientropy_records_merged_total Records accepted via merge\n",
        "# TYPE ztlp_ns_antientropy_records_merged_total counter\n",
        "ztlp_ns_antientropy_records_merged_total #{ae.records_merged}\n",
        "\n",
        "# HELP ztlp_ns_antientropy_records_rejected_total Records rejected during merge\n",
        "# TYPE ztlp_ns_antientropy_records_rejected_total counter\n",
        "ztlp_ns_antientropy_records_rejected_total #{ae.records_rejected}\n",
        "\n",
        "# HELP ztlp_ns_antientropy_last_sync_epoch Unix timestamp of last sync\n",
        "# TYPE ztlp_ns_antientropy_last_sync_epoch gauge\n",
        "ztlp_ns_antientropy_last_sync_epoch #{ae.last_sync_epoch}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp replication_metrics do
    try do
      rep = ZtlpNs.Replication.metrics()

      [
        "# HELP ztlp_ns_replication_pushes_total Total replication pushes\n",
        "# TYPE ztlp_ns_replication_pushes_total counter\n",
        "ztlp_ns_replication_pushes_total #{rep.pushes_total}\n",
        "\n",
        "# HELP ztlp_ns_replication_push_successes_total Successful peer pushes\n",
        "# TYPE ztlp_ns_replication_push_successes_total counter\n",
        "ztlp_ns_replication_push_successes_total #{rep.push_successes}\n",
        "\n",
        "# HELP ztlp_ns_replication_push_failures_total Failed peer pushes\n",
        "# TYPE ztlp_ns_replication_push_failures_total counter\n",
        "ztlp_ns_replication_push_failures_total #{rep.push_failures}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp ratelimit_metrics do
    try do
      rl = ZtlpNs.RateLimiter.metrics()

      [
        "# HELP ztlp_ns_ratelimit_allowed_total Queries allowed by rate limiter\n",
        "# TYPE ztlp_ns_ratelimit_allowed_total counter\n",
        "ztlp_ns_ratelimit_allowed_total #{rl.allowed}\n",
        "\n",
        "# HELP ztlp_ns_ratelimit_rejected_total Queries rejected by rate limiter\n",
        "# TYPE ztlp_ns_ratelimit_rejected_total counter\n",
        "ztlp_ns_ratelimit_rejected_total #{rl.rejected}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp cluster_metrics do
    try do
      all_members = [node() | Node.list()]
      total = length(all_members)
      # All visible nodes plus ourselves are considered "running"
      running = total

      [
        "# HELP ztlp_ns_cluster_members Number of cluster members\n",
        "# TYPE ztlp_ns_cluster_members gauge\n",
        "ztlp_ns_cluster_members #{total}\n",
        "\n",
        "# HELP ztlp_ns_cluster_running_members Number of running cluster members\n",
        "# TYPE ztlp_ns_cluster_running_members gauge\n",
        "ztlp_ns_cluster_running_members #{running}\n",
        "\n"
      ]
    rescue
      _ -> ""
    catch
      _, _ -> ""
    end
  end

  defp ns_component_auth_metrics do
    try do
      auth = ZtlpNs.ComponentAuth.metrics()

      [
        "# HELP ztlp_ns_component_auth_challenges_total Total auth challenges issued\n",
        "# TYPE ztlp_ns_component_auth_challenges_total counter\n",
        "ztlp_ns_component_auth_challenges_total #{auth.challenges}\n",
        "\n",
        "# HELP ztlp_ns_component_auth_successes_total Successful authentications\n",
        "# TYPE ztlp_ns_component_auth_successes_total counter\n",
        "ztlp_ns_component_auth_successes_total #{auth.successes}\n",
        "\n",
        "# HELP ztlp_ns_component_auth_failures_total Failed authentications\n",
        "# TYPE ztlp_ns_component_auth_failures_total counter\n",
        "ztlp_ns_component_auth_failures_total #{auth.failures}\n",
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
      "# HELP beam_memory_bytes BEAM VM memory\n# TYPE beam_memory_bytes gauge\n",
      "beam_memory_bytes{kind=\"total\"} #{mem[:total]}\n",
      "beam_memory_bytes{kind=\"processes\"} #{mem[:processes]}\n\n",
      "# HELP beam_process_count BEAM processes\n# TYPE beam_process_count gauge\n",
      "beam_process_count #{procs}\n"
    ]
  end

  defp metrics_enabled? do
    case System.get_env("ZTLP_NS_METRICS_ENABLED") do
      "false" -> false
      "0" -> false
      _ -> Application.get_env(:ztlp_ns, :metrics_enabled, true)
    end
  end

  defp metrics_port do
    case System.get_env("ZTLP_NS_METRICS_PORT") do
      nil -> Application.get_env(:ztlp_ns, :metrics_port, @default_port)
      port -> String.to_integer(port)
    end
  end
end
