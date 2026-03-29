defmodule ZtlpGateway.AuditCollectorServer do
  @moduledoc """
  Minimal HTTP server for the Audit Collector query API.

  Binds to `127.0.0.1:ZTLP_GATEWAY_AUDIT_PORT` (default 9104, localhost only).
  Uses raw `:gen_tcp` — zero external dependencies.

  ## Endpoints

  - `GET /audit/events?component=gateway&level=error&limit=50` → JSON array
  - `GET /audit/stats` → JSON object with aggregate counts
  """

  use GenServer

  require Logger

  alias ZtlpGateway.AuditCollector

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the audit HTTP server."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Get the actual port the server is bound to."
  @spec port() :: non_neg_integer() | nil
  def port do
    GenServer.call(__MODULE__, :get_port)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    if AuditCollector.enabled?() do
      audit_port = ZtlpGateway.Config.get(:audit_port)

      case :gen_tcp.listen(audit_port, [
             :binary,
             packet: :http_bin,
             active: false,
             reuseaddr: true,
             backlog: 32,
             ip: {127, 0, 0, 1}
           ]) do
        {:ok, listen_socket} ->
          {:ok, actual_port} = :inet.port(listen_socket)
          Logger.info("[AuditCollectorServer] Audit HTTP API on 127.0.0.1:#{actual_port}")
          send(self(), :accept)
          {:ok, %{socket: listen_socket, port: actual_port}}

        {:error, reason} ->
          Logger.error("[AuditCollectorServer] Failed to start on port #{audit_port}: #{inspect(reason)}")
          {:ok, %{socket: nil, port: nil}}
      end
    else
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

    case parse_path(path_str) do
      {"/audit/events", params} ->
        handle_events(socket, params)

      {"/audit/stats", _params} ->
        handle_stats(socket)

      _ ->
        send_response(socket, 404, ~s({"error":"not_found"}\n), "application/json")
    end
  end

  defp handle_events(socket, params) do
    opts =
      []
      |> maybe_add(:component, Map.get(params, "component"))
      |> maybe_add(:level, Map.get(params, "level"))
      |> maybe_add(:event, Map.get(params, "event"))
      |> maybe_add(:service, Map.get(params, "service"))
      |> maybe_add(:since, Map.get(params, "since"))
      |> maybe_add(:until, Map.get(params, "until"))
      |> maybe_add_int(:limit, Map.get(params, "limit"))
      |> maybe_add_int(:offset, Map.get(params, "offset"))

    result = AuditCollector.query(opts)
    body = AuditCollector.json_encode(result) <> "\n"
    send_response(socket, 200, body, "application/json")
  end

  defp handle_stats(socket) do
    result = AuditCollector.stats()
    body = AuditCollector.json_encode(result) <> "\n"
    send_response(socket, 200, body, "application/json")
  end

  # ---------------------------------------------------------------------------
  # Helpers
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
      "Connection: close\r\n\r\n",
      body
    ])
  end

  defp parse_path(path_str) do
    case String.split(path_str, "?", parts: 2) do
      [path, query] -> {path, parse_query(query)}
      [path] -> {path, %{}}
    end
  end

  defp parse_query(query) do
    query
    |> String.split("&", trim: true)
    |> Enum.reduce(%{}, fn pair, acc ->
      case String.split(pair, "=", parts: 2) do
        [key, value] -> Map.put(acc, URI.decode(key), URI.decode(value))
        [key] -> Map.put(acc, URI.decode(key), "")
      end
    end)
  end

  defp maybe_add(opts, _key, nil), do: opts
  defp maybe_add(opts, _key, ""), do: opts
  defp maybe_add(opts, key, value), do: [{key, value} | opts]

  defp maybe_add_int(opts, _key, nil), do: opts
  defp maybe_add_int(opts, _key, ""), do: opts

  defp maybe_add_int(opts, key, value) do
    case Integer.parse(value) do
      {n, _} -> [{key, n} | opts]
      :error -> opts
    end
  end
end
