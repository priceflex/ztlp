defmodule ZtlpNs.MetricsServer do
  @moduledoc """
  Minimal HTTP server for Prometheus metrics scraping on ZTLP-NS.

  Default port: 9103. Endpoints: /metrics, /health, /ready.
  Uses raw `:gen_tcp` — zero external dependencies.
  """

  use GenServer
  require Logger

  @default_port 9103

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Return the listen port for a running MetricsServer (test helper)."
  def port(server \\ __MODULE__), do: GenServer.call(server, :port)

  @impl true
  def init(opts) do
    :persistent_term.put({__MODULE__, :start_time}, System.monotonic_time(:second))

    # Tests can pass `enabled: true` and `port: 0` to start an ephemeral
    # listener even when the global `:metrics_enabled` config is false.
    enabled = Keyword.get(opts, :enabled, metrics_enabled?())
    port_override = Keyword.get(opts, :port)

    if enabled do
      port = port_override || metrics_port()
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
        peer_ip = peer_ip_for(client)
        spawn(fn -> handle_request(client, peer_ip) end)
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
  def handle_call(:port, _from, %{port: p} = state), do: {:reply, p, state}

  @impl true
  def terminate(_reason, %{socket: nil}), do: :ok
  def terminate(_reason, %{socket: s}), do: :gen_tcp.close(s)

  defp handle_request(socket, peer_ip) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, {:http_request, :GET, {:abs_path, path}, _}} ->
        # Normalize path: http_bin returns binary strings, http returns charlists
        path_str = if is_list(path), do: List.to_string(path), else: path
        {path_only, query} = split_path(path_str)
        case path_only do
          "/metrics" ->
            drain_headers(socket)
            body = collect_metrics()
            send_response(socket, 200, body, "text/plain; version=0.0.4; charset=utf-8")
          "/health" ->
            drain_headers(socket)
            send_response(socket, 200, "OK\n")
          "/ready" ->
            drain_headers(socket)
            send_response(socket, 200, "OK\n")
          "/token_status" ->
            drain_headers(socket)
            body = collect_token_status()
            send_response(socket, 200, body, "application/json")
          "/admin/records" ->
            headers = collect_headers(socket, %{})
            handle_admin_records(socket, path_str, query, headers, peer_ip)
          _ ->
            drain_headers(socket)
            send_response(socket, 404, "Not Found\n")
        end
      {:ok, {:http_request, _, _, _}} ->
        drain_headers(socket)
        send_response(socket, 405, "Method Not Allowed\n")
      _ -> :ok
    end
    :gen_tcp.close(socket)
  end

  # Returns peer IP tuple, or {0,0,0,0} if the socket has no remote address yet.
  defp peer_ip_for(socket) do
    case :inet.peername(socket) do
      {:ok, {ip, _port}} -> ip
      {:error, _} -> {0, 0, 0, 0}
    end
  end

  defp split_path(path) do
    case String.split(path, "?", parts: 2) do
      [p] -> {p, ""}
      [p, q] -> {p, q}
    end
  end

  defp drain_headers(socket) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, :http_eoh} -> :ok
      {:ok, {:http_header, _, _, _, _}} -> drain_headers(socket)
      _ -> :ok
    end
  end

  # Like drain_headers but accumulates {downcased-name => value} into a map
  # so handlers can verify HMAC headers.
  defp collect_headers(socket, acc) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, :http_eoh} -> acc
      {:ok, {:http_header, _, name, _, value}} ->
        name_str = name |> to_string() |> String.downcase()
        value_str = to_string(value)
        collect_headers(socket, Map.put(acc, name_str, value_str))
      _ -> acc
    end
  end

  defp handle_admin_records(socket, path_with_query, query_str, headers, peer_ip) do
    Logger.info("[admin_api] peer_ip=#{:inet.ntoa(peer_ip)} path=#{path_with_query}")

    case ZtlpNs.AdminApiRateLimiter.check(peer_ip) do
      :rate_limited ->
        {_count, window} = ZtlpNs.Config.admin_api_rate_limit()
        Logger.warning("[admin_api] 429 peer=#{:inet.ntoa(peer_ip)} path=#{path_with_query}")
        send_response(socket, 429, "", "text/plain", [{"Retry-After", to_string(window)}])

      :ok ->
        secret = Application.get_env(:ztlp_ns, :admin_api_secret)

        case ZtlpNs.AdminApi.verify_request("GET", path_with_query, "", headers, secret: secret) do
          :ok ->
            opts = parse_admin_query(query_str)
            records = ZtlpNs.AdminApi.list_records(opts)
            body = Jason.encode!(records)

            ZtlpNs.Audit.log(:admin_api_records_pulled, "/admin/records", :admin_api, %{
              peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
              zone_filter: Keyword.get(opts, :zone),
              type_filter: Keyword.get(opts, :type),
              count: records[:count]
            })

            send_response(socket, 200, body, "application/json")
          {:error, reason} ->
            ZtlpNs.Audit.log(:admin_api_auth_failed, "/admin/records", :admin_api, %{
              peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
              reason: inspect(reason)
            })

            Logger.warning("[admin_api] 401 reason=#{inspect(reason)} path=#{path_with_query}")
            send_response(socket, 401, "")
        end
    end
  end

  @admin_record_types %{
    "key" => :key, "svc" => :svc, "relay" => :relay, "policy" => :policy,
    "revoke" => :revoke, "bootstrap" => :bootstrap, "operator" => :operator,
    "device" => :device, "user" => :user, "group" => :group,
    "ca" => :ca, "cert" => :cert
  }

  defp parse_admin_query(""), do: []
  defp parse_admin_query(qs) do
    qs
    |> String.split("&", trim: true)
    |> Enum.reduce([], fn pair, acc ->
      case String.split(pair, "=", parts: 2) do
        ["type", v] ->
          case Map.get(@admin_record_types, String.downcase(v)) do
            nil -> acc
            atom -> Keyword.put(acc, :type, atom)
          end
        ["zone", v] -> Keyword.put(acc, :zone, URI.decode(v))
        _ -> acc
      end
    end)
  end

  defp send_response(socket, status, body, ct \\ "text/plain", extra_headers \\ []) do
    status_text = case status do
      200 -> "OK"
      401 -> "Unauthorized"
      404 -> "Not Found"
      405 -> "Method Not Allowed"
      429 -> "Too Many Requests"
      _ -> "Error"
    end
    :inet.setopts(socket, [packet: :raw])
    extra = Enum.map(extra_headers, fn {k, v} -> "#{k}: #{v}\r\n" end)
    :gen_tcp.send(socket, [
      "HTTP/1.1 #{status} #{status_text}\r\n",
      "Content-Type: #{ct}\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      extra,
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

  # Returns JSON with enrollment log entries for Bootstrap to reconcile tokens.
  # Each entry has the device name, node_id, pubkey, zone, and enrollment timestamp.
  defp collect_token_status do
    try do
      entries = ZtlpNs.Enrollment.enrollment_log()

      enrollments =
        Enum.map(entries, fn entry ->
          ~s({"name":"#{entry.name}","node_id":"#{entry.node_id}","zone":"#{entry.zone}","enrolled_at":#{entry.enrolled_at}})
        end)

      ~s({"enrollments":[#{Enum.join(enrollments, ",")}]})
    rescue
      _ -> ~s({"enrollments":[],"error":"unavailable"})
    catch
      _, _ -> ~s({"enrollments":[],"error":"unavailable"})
    end
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
