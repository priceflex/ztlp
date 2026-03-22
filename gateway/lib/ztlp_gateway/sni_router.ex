defmodule ZtlpGateway.SniRouter do
  @moduledoc """
  SNI-based routing for the ZTLP Gateway TLS listener.

  Maps TLS Server Name Indication (SNI) hostnames to backend
  services. When a client connects with a specific SNI hostname,
  the router determines which backend service to forward to.

  ## Route Configuration

  Routes are stored in an ETS table and can be configured via:
  - Application config
  - YAML config (`tls.routes` section)
  - Runtime API (`put_route/3`)

  ## Example

      # In gateway.yaml:
      tls:
        routes:
          "web.corp.ztlp":
            backend: "127.0.0.1:8080"
            auth_mode: identity
          "api.corp.ztlp":
            backend: "127.0.0.1:3000"
            auth_mode: enforce
            min_assurance: software
  """

  use GenServer
  require Logger

  @table :ztlp_sni_routes

  # ── Public API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Resolve an SNI hostname to a service name.

  Returns the service name or the hostname itself as fallback.
  """
  @spec resolve(charlist() | String.t() | nil) :: String.t() | nil
  def resolve(nil), do: nil
  def resolve(hostname) when is_list(hostname), do: resolve(to_string(hostname))
  def resolve(hostname) when is_binary(hostname) do
    case :ets.lookup(@table, hostname) do
      [{^hostname, route}] -> Map.get(route, :service, hostname)
      [] ->
        # Try wildcard match
        case find_wildcard_match(hostname) do
          nil -> hostname
          route -> Map.get(route, :service, hostname)
        end
    end
  end

  @doc """
  Get the backend host:port for a service.

  Returns `{:ok, {host_tuple, port}}` or `{:error, :no_route}`.
  """
  @spec backend_for(String.t() | nil) :: {:ok, {tuple(), non_neg_integer()}} | {:error, term()}
  def backend_for(nil), do: {:error, :no_route}
  def backend_for(service) do
    case :ets.lookup(@table, service) do
      [{^service, route}] -> parse_backend(route.backend)
      [] ->
        # Service might be the hostname directly
        routes = :ets.tab2list(@table)
        case Enum.find(routes, fn {_k, v} -> Map.get(v, :service) == service end) do
          {_k, route} -> parse_backend(route.backend)
          nil -> {:error, :no_route}
        end
    end
  end

  @doc """
  Get route configuration for a hostname/service.
  """
  @spec get_route(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_route(hostname) do
    case :ets.lookup(@table, hostname) do
      [{^hostname, route}] -> {:ok, route}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Add or update a route.

  ## Parameters
  - `hostname` — SNI hostname
  - `backend` — backend address string (e.g., "127.0.0.1:8080")
  - `opts` — options:
    - `:service` — service name (default: hostname)
    - `:auth_mode` — :passthrough, :identity, or :enforce (default: :passthrough)
    - `:min_assurance` — minimum assurance level (default: :unknown)
  """
  @spec put_route(String.t(), String.t(), keyword()) :: :ok
  def put_route(hostname, backend, opts \\ []) do
    route = %{
      backend: backend,
      service: Keyword.get(opts, :service, hostname),
      auth_mode: Keyword.get(opts, :auth_mode, :passthrough),
      min_assurance: Keyword.get(opts, :min_assurance, :unknown)
    }
    :ets.insert(@table, {hostname, route})
    :ok
  end

  @doc "Remove a route."
  @spec delete_route(String.t()) :: :ok
  def delete_route(hostname) do
    :ets.delete(@table, hostname)
    :ok
  end

  @doc "List all routes."
  @spec list_routes() :: [{String.t(), map()}]
  def list_routes do
    :ets.tab2list(@table)
  end

  # ── GenServer ──────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])

    # Load routes from config
    routes = Keyword.get(opts, :routes, get_config_routes())
    Enum.each(routes, fn {hostname, config} ->
      route = %{
        backend: Map.get(config, :backend, Map.get(config, "backend", "")),
        service: Map.get(config, :service, Map.get(config, "service", to_string(hostname))),
        auth_mode: parse_auth_mode(Map.get(config, :auth_mode, Map.get(config, "auth_mode", "passthrough"))),
        min_assurance: parse_assurance(Map.get(config, :min_assurance, Map.get(config, "min_assurance", "unknown")))
      }
      :ets.insert(table, {to_string(hostname), route})
    end)

    {:ok, %{table: table}}
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp find_wildcard_match(hostname) do
    routes = :ets.tab2list(@table)
    Enum.find_value(routes, fn
      {"*." <> zone = _pattern, route} ->
        if String.ends_with?(hostname, "." <> zone), do: route, else: nil
      _ -> nil
    end)
  end

  defp parse_backend(backend) when is_binary(backend) do
    case String.split(backend, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, _} ->
            host_tuple = parse_host(host)
            {:ok, {host_tuple, port}}
          :error -> {:error, :invalid_port}
        end
      _ -> {:error, :invalid_backend}
    end
  end
  defp parse_backend(_), do: {:error, :invalid_backend}

  defp parse_host(host) do
    case :inet.parse_address(to_charlist(host)) do
      {:ok, addr} -> addr
      _ -> {127, 0, 0, 1}
    end
  end

  defp parse_auth_mode(:passthrough), do: :passthrough
  defp parse_auth_mode(:identity), do: :identity
  defp parse_auth_mode(:enforce), do: :enforce
  defp parse_auth_mode("passthrough"), do: :passthrough
  defp parse_auth_mode("identity"), do: :identity
  defp parse_auth_mode("enforce"), do: :enforce
  defp parse_auth_mode(_), do: :passthrough

  defp parse_assurance(a) when is_atom(a), do: a
  defp parse_assurance("hardware"), do: :hardware
  defp parse_assurance("device_bound"), do: :device_bound
  defp parse_assurance("device-bound"), do: :device_bound
  defp parse_assurance("software"), do: :software
  defp parse_assurance("unknown"), do: :unknown
  defp parse_assurance(_), do: :unknown

  defp get_config_routes do
    Application.get_env(:ztlp_gateway, :tls_routes, [])
  end
end
