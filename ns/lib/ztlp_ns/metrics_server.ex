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
          "/admin/audit" ->
            headers = collect_headers(socket, %{})
            handle_admin_audit(socket, path_str, query, headers, peer_ip)
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
    handle_admin_gated(socket, :records, "/admin/records", path_with_query, query_str, headers, peer_ip)
  end

  defp handle_admin_audit(socket, path_with_query, query_str, headers, peer_ip) do
    handle_admin_gated(socket, :audit, "/admin/audit", path_with_query, query_str, headers, peer_ip)
  end

  # Shared gate pipeline for every authenticated admin endpoint. `kind`
  # selects the resource handler after the request clears the gates;
  # `resource_path` is the canonical (query-less) path used for audit
  # log `name` fields so events stay grouped per endpoint.
  #
  # Stages (order is security-critical — do not reorder):
  #   1. CIDR union gate (only enforced when tenants are configured)
  #   2. per-IP rate limit
  #   3. HMAC verify + tenant identification
  #   4. per-tenant CIDR recheck (CodeRabbit PR #98 F4)
  #   5. trust-authority hook (T7)
  #   6. zone-glob scope + encode + success audit
  defp handle_admin_gated(socket, kind, resource_path, path_with_query, query_str, headers, peer_ip) do
    Logger.info("[admin_api] peer_ip=#{:inet.ntoa(peer_ip)} path=#{path_with_query}")

    case maybe_gate_by_cidr(socket, resource_path, peer_ip, path_with_query) do
      :rejected ->
        :ok

      :ok ->
        case ZtlpNs.AdminApiRateLimiter.check(peer_ip) do
          :rate_limited ->
            {_count, window} = ZtlpNs.Config.admin_api_rate_limit()
            Logger.warning("[admin_api] 429 peer=#{:inet.ntoa(peer_ip)} path=#{path_with_query}")
            send_response(socket, 429, "", "text/plain", [{"Retry-After", to_string(window)}])

          :ok ->
            secret = Application.get_env(:ztlp_ns, :admin_api_secret)
            registry = ZtlpNs.AdminApi.TenantRegistry.cached()

            case ZtlpNs.AdminApi.verify_request_with_registry(
                   "GET",
                   path_with_query,
                   "",
                   headers,
                   registry,
                   secret
                 ) do
              {:ok, identity} ->
                # CodeRabbit PR #98 F4: the union CIDR gate above is
                # necessary but NOT sufficient — it admits a request
                # signed as tenant A that arrives from tenant B's CIDR.
                # Now that we know which tenant the HMAC identifies,
                # re-verify the peer IP against THAT tenant's CIDRs.
                enforce_identified_tenant_cidr(
                  socket,
                  kind,
                  resource_path,
                  identity,
                  registry,
                  query_str,
                  peer_ip
                )

              {:error, reason} ->
                ZtlpNs.Audit.log(:admin_api_auth_failed, resource_path, :admin_api, %{
                  peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
                  reason: inspect(reason),
                  severity: :high
                })

                Logger.warning("[admin_api] 401 reason=#{inspect(reason)} path=#{path_with_query}")
                send_response(socket, 401, "")
            end
        end
    end
  end

  # F4 (CodeRabbit PR #98): after a request has been HMAC-identified to
  # a specific tenant, re-check that the peer IP is inside THAT tenant's
  # CIDRs. The earlier union check (maybe_gate_by_cidr/4) only proves
  # the IP belongs to SOME tenant — it cannot prevent cross-tenant CIDR
  # escape (request signed as A from B's CIDR). Legacy identities skip
  # this — they use the global secret, predate per-tenant CIDRs, and
  # are gated only by the union (T3 + production-readiness item #5).
  defp enforce_identified_tenant_cidr(socket, kind, resource_path, identity, registry, query_str, peer_ip) do
    case identity do
      {:tenant, tenant} ->
        if ZtlpNs.AdminApi.TenantRegistry.ip_in_cidrs?(tenant, peer_ip) do
          handle_authenticated_admin(socket, kind, resource_path, identity, query_str, peer_ip, registry)
        else
          ZtlpNs.Audit.log(:admin_api_ip_rejected, resource_path, :admin_api, %{
            peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
            tenant: tenant.slug,
            severity: :medium,
            reason: "ip_outside_identified_tenant_cidrs"
          })

          Logger.warning(
            "[admin_api] 403 tenant=#{tenant.slug} ip_outside_tenant_cidrs peer=#{:inet.ntoa(peer_ip)}"
          )

          send_response(socket, 403, "")
        end

      :legacy ->
        handle_authenticated_admin(socket, kind, resource_path, identity, query_str, peer_ip, registry)
    end
  end

  # Post-auth, post-CIDR-recheck fan-out: emit the legacy-global-secret
  # audit signal when applicable, then drive the trust-authority hook
  # → authorized-fan-out chain. Extracted so the F4 case branches stay
  # narrow.
  defp handle_authenticated_admin(socket, kind, resource_path, identity, query_str, peer_ip, registry) do
    # Surface legacy-mode use when tenants are ALSO configured
    # (transition period) so operators can grep for it.
    if identity == :legacy and map_size(registry) > 0 do
      ZtlpNs.Audit.log(:admin_api_legacy_global_secret, resource_path, :admin_api, %{
        peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
        severity: :medium
      })
    end

    # Trust-authority extension hook (T7). Returns :ok today;
    # Phase 3+ implementations of this function can deny here.
    authority_context = %{
      peer_ip: peer_ip,
      method: "GET",
      path: resource_path,
      query: query_str,
      identity: identity
    }

    case ZtlpNs.AdminApi.verify_authority(identity, authority_context) do
      :ok ->
        dispatch_authorized_admin(socket, kind, query_str, identity, peer_ip)

      {:error, :authority_denied} ->
        ZtlpNs.Audit.log(:admin_api_authority_denied, resource_path, :admin_api, %{
          peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
          identity: identity_label(identity),
          severity: :critical
        })

        Logger.warning(
          "[admin_api] 403 authority_denied identity=#{identity_label(identity)} peer=#{:inet.ntoa(peer_ip)}"
        )

        send_response(socket, 403, "")
    end
  end

  # Resource dispatch after all gates clear.
  defp dispatch_authorized_admin(socket, :records, query_str, identity, peer_ip) do
    opts = parse_admin_query(query_str)
    handle_authorized_admin_records(socket, opts, identity, peer_ip)
  end

  defp dispatch_authorized_admin(socket, :audit, query_str, identity, peer_ip) do
    handle_authorized_admin_audit(socket, query_str, identity, peer_ip)
  end

  # Render the calling identity as a short string for audit log details.
  # `:legacy` means the request used the global ZTLP_NS_ADMIN_API_SECRET;
  # `{:tenant, t}` carries the tenant struct from the registry.
  defp identity_label({:tenant, %ZtlpNs.AdminApi.TenantRegistry{slug: slug}}), do: "tenant:#{slug}"
  defp identity_label(:legacy), do: "legacy"

  # Authorized-request fan-out: at this point the request has cleared
  # peer-IP CIDR gate (T3), rate limit (T2 of PR #97), HMAC verify (T4),
  # and trust-authority hook (T7). Run zone-glob scoping (T5), encode
  # the body, and emit the success audit event.
  defp handle_authorized_admin_records(socket, opts, identity, peer_ip) do
    # Audit cross-tenant probe attempts BEFORE running the filter (the
    # filter would just return empty for an out-of-glob zone, but the
    # audit lets operators SEE the probe).
    maybe_audit_outside_glob(identity, opts, peer_ip)

    records =
      opts
      |> ZtlpNs.AdminApi.list_records()
      |> apply_tenant_scope(identity)

    body = Jason.encode!(records)

    ZtlpNs.Audit.log(:admin_api_records_pulled, "/admin/records", :admin_api, %{
      peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
      zone_filter: Keyword.get(opts, :zone),
      type_filter: Keyword.get(opts, :type),
      count: records[:count],
      identity: identity_label(identity),
      severity: :info
    })

    send_response(socket, 200, body, "application/json")
  end

  # Audit-log read endpoint. Same gate guarantees as records; here we
  # parse ?since / ?pattern, fetch from the bounded audit ring, project
  # to JSON-safe maps, and scope to the tenant's zone glob (a tenant may
  # only read audit lines whose `name` falls inside its own zone).
  defp handle_authorized_admin_audit(socket, query_str, identity, peer_ip) do
    entries =
      query_str
      |> fetch_audit_entries()
      |> apply_audit_tenant_scope(identity)

    body =
      Jason.encode!(%{
        entries: entries,
        count: length(entries),
        generated_at: System.system_time(:second)
      })

    ZtlpNs.Audit.log(:admin_api_audit_pulled, "/admin/audit", :admin_api, %{
      peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
      count: length(entries),
      identity: identity_label(identity),
      severity: :info
    })

    send_response(socket, 200, body, "application/json")
  end

  # Parse + fetch audit entries per the ?since / ?pattern query params,
  # then project each {ts, action, name, type, details} tuple into a
  # JSON-safe map. Mirrors the field set the removed UDP 0x13 audit
  # opcodes used to emit.
  defp fetch_audit_entries(query_str) do
    params = parse_audit_query(query_str)
    since = params[:since]
    pattern = params[:pattern]

    entries =
      cond do
        pattern != nil and since != nil -> ZtlpNs.Audit.filter_since(pattern, since)
        pattern != nil -> ZtlpNs.Audit.filter(pattern)
        since != nil -> ZtlpNs.Audit.since(since)
        true -> ZtlpNs.Audit.all()
      end

    Enum.map(entries, &project_audit_entry/1)
  end

  defp project_audit_entry({ts, action, name, type, details}) do
    %{
      timestamp: ts,
      action: to_string(action),
      name: name,
      type: to_string(type),
      details: jsonable_details(details)
    }
  end

  # Coerce arbitrary audit `details` into a strictly JSON-encodable map.
  # Audit details may carry atoms (e.g. severity: :high), nested maps,
  # lists, or the odd tuple — Jason can't encode bare tuples, so we
  # recursively normalize. Atom VALUES become strings; tuples are
  # inspected (last-resort, shouldn't normally occur).
  defp jsonable_details(details) when is_map(details) do
    Map.new(details, fn {k, v} -> {to_string(k), jsonable_value(v)} end)
  end

  defp jsonable_details(other), do: %{"value" => jsonable_value(other)}

  defp jsonable_value(v)
       when is_binary(v) or is_integer(v) or is_float(v) or is_boolean(v) or is_nil(v),
       do: v

  defp jsonable_value(v) when is_atom(v), do: Atom.to_string(v)
  defp jsonable_value(v) when is_map(v), do: jsonable_details(v)
  defp jsonable_value(v) when is_list(v), do: Enum.map(v, &jsonable_value/1)
  defp jsonable_value(v), do: inspect(v)

  # ?since=<unix_ts>&pattern=<glob>. Unknown/malformed params are
  # silently dropped (same forgiving posture as parse_admin_query/1).
  defp parse_audit_query(""), do: []

  defp parse_audit_query(qs) do
    qs
    |> String.split("&", trim: true)
    |> Enum.reduce([], fn pair, acc ->
      case String.split(pair, "=", parts: 2) do
        ["since", v] ->
          case Integer.parse(v) do
            {ts, ""} -> Keyword.put(acc, :since, ts)
            _ -> acc
          end

        ["pattern", v] ->
          Keyword.put(acc, :pattern, URI.decode(v))

        _ ->
          acc
      end
    end)
  end

  # Filter projected audit entries to the tenant's zone_glob (matched on
  # the entry `name`). Legacy mode (global secret) sees everything.
  #
  # SECURITY: cross-tenant audit isolation. A leaked tenant secret
  # authenticates via T4 but THIS function ensures it can only read
  # audit lines for names inside its own zone_glob.
  defp apply_audit_tenant_scope(entries, {:tenant, tenant}) do
    Enum.filter(entries, fn entry ->
      name = entry[:name] || entry["name"]
      is_binary(name) and ZtlpNs.AdminApi.TenantRegistry.zone_matches?(tenant, name)
    end)
  end

  defp apply_audit_tenant_scope(entries, :legacy), do: entries

  # Filter the list_records response to the tenant's zone_glob. Legacy mode
  # (global secret) sees everything — preserves backwards-compat.
  #
  # SECURITY: this is the cross-tenant isolation enforcement. A leaked tenant
  # secret authenticates correctly via T4, but THIS function ensures it can
  # only see records inside its own zone_glob.
  defp apply_tenant_scope(%{records: rs} = response, {:tenant, tenant}) do
    filtered =
      Enum.filter(rs, fn record ->
        name = record[:name] || record["name"]
        is_binary(name) and
          ZtlpNs.AdminApi.TenantRegistry.zone_matches?(tenant, name)
      end)

    %{response | records: filtered, count: length(filtered)}
  end

  defp apply_tenant_scope(response, :legacy), do: response

  # When a tenant requests `?zone=X` outside its glob, the response filter
  # already returns empty. We separately log this as :admin_api_zone_outside_glob
  # at severity :high so operators can detect cross-tenant probe attempts.
  defp maybe_audit_outside_glob({:tenant, tenant}, opts, peer_ip) do
    case Keyword.get(opts, :zone) do
      nil ->
        :ok

      user_zone ->
        unless ZtlpNs.AdminApi.TenantRegistry.zone_matches?(tenant, user_zone) do
          ZtlpNs.Audit.log(:admin_api_zone_outside_glob, "/admin/records", :admin_api, %{
            peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
            tenant: tenant.slug,
            requested_zone: user_zone,
            tenant_glob: tenant.zone_glob,
            severity: :high
          })
        end

        :ok
    end
  end

  defp maybe_audit_outside_glob(:legacy, _opts, _peer_ip), do: :ok

  # IP allow-list gate: only enforced when the tenant registry is non-empty.
  # When empty (legacy mode = only the global ZTLP_NS_ADMIN_API_SECRET is set),
  # this returns :ok unconditionally — pure backwards-compat.
  defp maybe_gate_by_cidr(socket, resource_path, peer_ip, path_with_query) do
    if ZtlpNs.AdminApi.TenantRegistry.any_tenant_allows_ip?(peer_ip) do
      :ok
    else
      Logger.warning(
        "[admin_api] 403 ip not in any tenant CIDR peer=#{:inet.ntoa(peer_ip)} path=#{path_with_query}"
      )

      ZtlpNs.Audit.log(:admin_api_ip_rejected, resource_path, :admin_api, %{
        peer_ip: peer_ip |> :inet.ntoa() |> to_string(),
        severity: :medium
      })

      send_response(socket, 403, "")
      :rejected
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
      403 -> "Forbidden"
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
      "ztlp_ns_info{version=\"#{ZtlpNs.version()}\",storage=\"#{storage}\"} 1\n\n",
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
