defmodule ZtlpGateway.AdminDashboard do
  @moduledoc """
  Single-page HTML admin dashboard for ZTLP Gateway operators.

  Serves a real-time monitoring UI on `127.0.0.1:ZTLP_GATEWAY_DASHBOARD_PORT`
  (default 9105, localhost only). Uses raw `:gen_tcp` — zero external dependencies.

  ## Endpoints

  - `GET /`          → Self-contained HTML dashboard (dark theme, auto-refresh)
  - `GET /api/stats` → JSON with all dashboard data

  ## Data Sources

  - `:ztlp_gateway_sessions` ETS table (connected sessions)
  - `ZtlpGateway.AuditCollector.stats/0` and `query/1` (audit events)
  - Erlang VM stats (processes, memory, schedulers, uptime)
  """

  use GenServer

  require Logger

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the admin dashboard HTTP server."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Get the actual port the server is bound to (useful in tests with port 0)."
  @spec port() :: non_neg_integer() | nil
  def port do
    GenServer.call(__MODULE__, :get_port)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    if ZtlpGateway.Config.get(:dashboard_enabled) do
      dash_port = ZtlpGateway.Config.get(:dashboard_port)

      case :gen_tcp.listen(dash_port, [
             :binary,
             packet: :http_bin,
             active: false,
             reuseaddr: true,
             backlog: 32,
             ip: {127, 0, 0, 1}
           ]) do
        {:ok, listen_socket} ->
          {:ok, actual_port} = :inet.port(listen_socket)
          Logger.info("[AdminDashboard] Listening on http://127.0.0.1:#{actual_port}")
          send(self(), :accept)
          {:ok, %{socket: listen_socket, port: actual_port}}

        {:error, reason} ->
          Logger.error("[AdminDashboard] Failed to start on port #{dash_port}: #{inspect(reason)}")
          {:ok, %{socket: nil, port: nil}}
      end
    else
      Logger.info("[AdminDashboard] Disabled via configuration")
      {:ok, %{socket: nil, port: nil}}
    end
  end

  @impl true
  def handle_call(:get_port, _from, state) do
    {:reply, state.port, state}
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

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{socket: nil}), do: :ok
  def terminate(_reason, %{socket: s}), do: :gen_tcp.close(s)

  # ---------------------------------------------------------------------------
  # Request Handling
  # ---------------------------------------------------------------------------

  defp handle_request(socket) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, {:http_request, :GET, {:abs_path, path}, _}} ->
        drain_headers(socket)
        handle_path(socket, path)

      {:ok, {:http_request, _, _, _}} ->
        drain_headers(socket)
        send_response(socket, 405, "Method Not Allowed\n")

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
    path_str = if is_list(path), do: List.to_string(path), else: path

    case strip_query(path_str) do
      "/" ->
        body = render_html()
        send_response(socket, 200, body, "text/html; charset=utf-8")

      "/api/stats" ->
        body = json_encode(collect_stats()) <> "\n"
        send_response(socket, 200, body, "application/json")

      _ ->
        send_response(socket, 404, ~s({"error":"not_found"}\n), "application/json")
    end
  end

  defp strip_query(path) do
    case String.split(path, "?", parts: 2) do
      [base, _] -> base
      [base] -> base
    end
  end

  # ---------------------------------------------------------------------------
  # Stats Collection
  # ---------------------------------------------------------------------------

  @doc false
  def collect_stats do
    %{
      hostname: get_hostname(),
      uptime_seconds: div(elem(:erlang.statistics(:wall_clock), 0), 1000),
      sessions: collect_session_stats(),
      pool: collect_pool_stats(),
      audit: collect_audit_stats(),
      system: %{
        process_count: :erlang.system_info(:process_count),
        memory_mb: div(:erlang.memory(:total), 1_048_576),
        schedulers: :erlang.system_info(:schedulers_online)
      }
    }
  end

  defp collect_session_stats do
    case :ets.info(:ztlp_gateway_sessions) do
      :undefined ->
        %{total: 0, list: []}

      _ ->
        sessions = :ets.tab2list(:ztlp_gateway_sessions)

        list =
          Enum.map(sessions, fn {session_id, pid} ->
            id_display =
              if is_binary(session_id) and byte_size(session_id) > 0 do
                session_id |> Base.encode16(case: :lower) |> String.slice(0..15)
              else
                inspect(session_id)
              end

            %{id: id_display, pid: inspect(pid)}
          end)

        %{total: length(sessions), list: list}
    end
  end

  defp collect_pool_stats do
    # BackendPool may not expose a stats/0 function; use apply to avoid compile-time warnings
    if function_exported?(ZtlpGateway.BackendPool, :stats, 0) do
      try do
        apply(ZtlpGateway.BackendPool, :stats, [])
      rescue
        _ -> %{available: false}
      catch
        _, _ -> %{available: false}
      end
    else
      %{available: false}
    end
  end

  defp collect_audit_stats do
    if function_exported?(ZtlpGateway.AuditCollector, :stats, 0) do
      try do
        stats = ZtlpGateway.AuditCollector.stats()

        recent =
          if function_exported?(ZtlpGateway.AuditCollector, :query, 1) do
            result = ZtlpGateway.AuditCollector.query(limit: 20)
            Map.get(result, :events, [])
          else
            []
          end

        Map.put(stats, :recent_events, recent)
      rescue
        _ -> %{available: false}
      catch
        _, _ -> %{available: false}
      end
    else
      %{available: false}
    end
  end

  defp get_hostname do
    case :inet.gethostname() do
      {:ok, name} -> List.to_string(name)
      _ -> "unknown"
    end
  end

  # ---------------------------------------------------------------------------
  # JSON Encoder (self-contained, no external deps)
  # ---------------------------------------------------------------------------

  @doc false
  def json_encode(nil), do: "null"
  def json_encode(true), do: "true"
  def json_encode(false), do: "false"
  def json_encode(n) when is_integer(n), do: Integer.to_string(n)
  def json_encode(n) when is_float(n), do: Float.to_string(n)
  def json_encode(a) when is_atom(a), do: json_encode(Atom.to_string(a))

  def json_encode(s) when is_binary(s) do
    escaped =
      s
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
      |> String.replace("\n", "\\n")
      |> String.replace("\r", "\\r")
      |> String.replace("\t", "\\t")

    "\"" <> escaped <> "\""
  end

  def json_encode(map) when is_map(map) do
    pairs =
      map
      |> Enum.map(fn {k, v} ->
        key = if is_atom(k), do: Atom.to_string(k), else: to_string(k)
        json_encode(key) <> ":" <> json_encode(v)
      end)
      |> Enum.join(",")

    "{" <> pairs <> "}"
  end

  def json_encode(list) when is_list(list) do
    items = Enum.map(list, &json_encode/1) |> Enum.join(",")
    "[" <> items <> "]"
  end

  def json_encode(other), do: json_encode(inspect(other))

  # ---------------------------------------------------------------------------
  # HTTP Response
  # ---------------------------------------------------------------------------

  defp send_response(socket, status, body, ct \\ "text/plain") do
    status_text =
      case status do
        200 -> "OK"
        404 -> "Not Found"
        405 -> "Method Not Allowed"
        _ -> "Error"
      end

    :inet.setopts(socket, packet: :raw)

    :gen_tcp.send(socket, [
      "HTTP/1.1 #{status} #{status_text}\r\n",
      "Content-Type: #{ct}\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      "Connection: close\r\n",
      "Access-Control-Allow-Origin: *\r\n\r\n",
      body
    ])
  end

  # ---------------------------------------------------------------------------
  # HTML Dashboard
  # ---------------------------------------------------------------------------

  defp render_html do
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ZTLP Gateway Dashboard</title>
    <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#1a1a2e;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:20px}
    .header{text-align:center;margin-bottom:24px;padding:20px;background:#16213e;border-radius:8px;border:1px solid #0f3460}
    .header h1{font-size:1.5em;color:#e94560;margin-bottom:8px}
    .header .meta{font-family:'Courier New',monospace;font-size:0.85em;color:#a0a0c0}
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
    .card{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:16px;text-align:center}
    .card .label{font-size:0.75em;text-transform:uppercase;color:#a0a0c0;margin-bottom:4px}
    .card .value{font-size:1.8em;font-weight:bold;color:#e94560;font-family:'Courier New',monospace}
    .section{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:16px;margin-bottom:16px}
    .section h2{font-size:1em;color:#e94560;margin-bottom:12px;border-bottom:1px solid #0f3460;padding-bottom:8px}
    table{width:100%;border-collapse:collapse;font-family:'Courier New',monospace;font-size:0.85em}
    th{text-align:left;padding:8px;border-bottom:1px solid #0f3460;color:#a0a0c0;font-size:0.75em;text-transform:uppercase}
    td{padding:8px;border-bottom:1px solid rgba(15,52,96,0.5)}
    tr:hover{background:rgba(15,52,96,0.3)}
    .events-list{max-height:300px;overflow-y:auto;font-family:'Courier New',monospace;font-size:0.8em}
    .event-item{padding:6px 8px;border-bottom:1px solid rgba(15,52,96,0.3)}
    .event-item .level-info{color:#4fc3f7}
    .event-item .level-warn,.event-item .level-warning{color:#ffb74d}
    .event-item .level-error{color:#e94560}
    .empty{color:#666;font-style:italic;text-align:center;padding:20px}
    .refresh-indicator{position:fixed;top:8px;right:12px;font-size:0.7em;color:#555}
    @media(max-width:600px){.cards{grid-template-columns:1fr 1fr}body{padding:10px}}
    </style>
    </head>
    <body>
    <div class="header">
      <h1>ZTLP Gateway Dashboard</h1>
      <div class="meta">
        <span id="hostname">loading...</span> &middot; uptime <span id="uptime">--</span>
      </div>
    </div>
    <div class="cards">
      <div class="card"><div class="label">Sessions</div><div class="value" id="c-sessions">-</div></div>
      <div class="card"><div class="label">Processes</div><div class="value" id="c-procs">-</div></div>
      <div class="card"><div class="label">Memory (MB)</div><div class="value" id="c-mem">-</div></div>
      <div class="card"><div class="label">Schedulers</div><div class="value" id="c-sched">-</div></div>
    </div>
    <div class="section">
      <h2>Connected Sessions</h2>
      <table>
        <thead><tr><th>Session ID</th><th>PID</th></tr></thead>
        <tbody id="sessions-body"><tr><td colspan="2" class="empty">No sessions</td></tr></tbody>
      </table>
    </div>
    <div class="section">
      <h2>Audit Stats</h2>
      <div id="audit-stats" class="empty">Loading...</div>
    </div>
    <div class="section">
      <h2>Recent Audit Events</h2>
      <div class="events-list" id="events-list"><div class="empty">No events</div></div>
    </div>
    <div class="section">
      <h2>System</h2>
      <table>
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody id="system-body"></tbody>
      </table>
    </div>
    <div class="refresh-indicator" id="refresh-ind">&#9679; live</div>
    <script>
    """ <> dashboard_js() <> """
    </script>
    </body>
    </html>
    """
  end

  defp dashboard_js do
    # Kept as a separate function to avoid sigil/delimiter issues with JS syntax
    "function fmt_uptime(s){" <>
    "var d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);" <>
    "var p=[];if(d)p.push(d+'d');if(h)p.push(h+'h');p.push(m+'m');return p.join(' ');}" <>
    "function esc(s){if(typeof s!=='string')s=String(s);return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}" <>
    "function update(data){" <>
    "document.getElementById('hostname').textContent=data.hostname||'unknown';" <>
    "document.getElementById('uptime').textContent=fmt_uptime(data.uptime_seconds||0);" <>
    "document.getElementById('c-sessions').textContent=data.sessions?data.sessions.total:0;" <>
    "var sys=data.system||{};" <>
    "document.getElementById('c-procs').textContent=sys.process_count||0;" <>
    "document.getElementById('c-mem').textContent=sys.memory_mb||0;" <>
    "document.getElementById('c-sched').textContent=sys.schedulers||0;" <>
    "var sb=document.getElementById('sessions-body');" <>
    "if(data.sessions&&data.sessions.list&&data.sessions.list.length>0){" <>
    "sb.innerHTML=data.sessions.list.map(function(s){" <>
    "return '<tr><td>'+esc(s.id)+'</td><td>'+esc(s.pid)+'</td></tr>';}).join('');" <>
    "}else{sb.innerHTML='<tr><td colspan=\"2\" class=\"empty\">No sessions</td></tr>';}" <>
    "var as=document.getElementById('audit-stats');" <>
    "if(data.audit&&data.audit.available!==false){" <>
    "var a=data.audit;" <>
    "var h='<strong>Total events:</strong> '+(a.total_events||0);" <>
    "if(a.by_level){h+=' &middot; ';var lv=[];for(var k in a.by_level){lv.push(k+': '+a.by_level[k]);}h+=lv.join(', ');}" <>
    "as.innerHTML=h;as.className='';" <>
    "}else{as.innerHTML='Audit collector not available';as.className='empty';}" <>
    "var el=document.getElementById('events-list');" <>
    "if(data.audit&&data.audit.recent_events&&data.audit.recent_events.length>0){" <>
    "el.innerHTML=data.audit.recent_events.map(function(e){" <>
    "var lc='level-'+(e.level||'info');" <>
    "return '<div class=\"event-item\"><span class=\"'+lc+'\">['+esc(e.level||'info')+']</span> '" <>
    "+esc(e.timestamp||'')+' <strong>'+esc(e.event||'')+'</strong> '+esc(e.component||'')" <>
    "+(e.service?' svc='+esc(e.service):'')+'</div>';}).join('');" <>
    "}else{el.innerHTML='<div class=\"empty\">No recent events</div>';}" <>
    "var stb=document.getElementById('system-body');" <>
    "stb.innerHTML='<tr><td>Processes</td><td>'+(sys.process_count||0)+'</td></tr>'" <>
    "+'<tr><td>Memory</td><td>'+(sys.memory_mb||0)+' MB</td></tr>'" <>
    "+'<tr><td>Schedulers</td><td>'+(sys.schedulers||0)+'</td></tr>'" <>
    "+'<tr><td>Uptime</td><td>'+fmt_uptime(data.uptime_seconds||0)+'</td></tr>';}" <>
    "function refresh(){" <>
    "fetch('/api/stats').then(function(r){return r.json();}).then(update)" <>
    ".catch(function(){document.getElementById('refresh-ind').textContent='\\u25cf offline';});}" <>
    "refresh();setInterval(refresh,5000);"
  end
end
