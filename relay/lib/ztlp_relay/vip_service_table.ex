defmodule ZtlpRelay.VipServiceTable do
  @moduledoc """
  ETS-backed VIP service routing table.

  Maps service name (string) → backend address {ip, port}.

  This is the authoritative source of truth for VIP TCP routing.
  Routing MUST be based on trusted ZTLP mux/service metadata (dst_svc_id),
  NOT on HTTP Host headers, SNI, or other application-layer hints.

  Populated from:
  - config.exs / environment at startup
  - `ZTLP_RELAY_VIP_SERVICES=service1=host1:port1,service2=host2:port2`
  """

  use GenServer

  @table_name :ztlp_vip_service_table

  @type backend_addr :: {:inet.ip_address(), :inet.port_number()}

  # Client API

  @doc """
  Start the VIP service routing table.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Look up a backend address for a service name.

  Returns `{:ok, {ip, port}}` or `:error`.
  """
  @spec lookup(String.t()) :: {:ok, backend_addr()} | :error
  def lookup(service_name) when is_binary(service_name) and service_name != "" do
    case :ets.lookup(@table_name, service_name) do
      [{^service_name, addr}] -> {:ok, addr}
      [] -> :error
    end
  rescue
    _e in ArgumentError -> :error
  end

  @doc """
  Check if a service name is configured for VIP routing.
  """
  @spec vip_service?(String.t()) :: boolean()
  def vip_service?(service_name) when is_binary(service_name) do
    :ets.member(@table_name, service_name)
  rescue
    _e in ArgumentError -> false
  end

  @doc """
  Register a service → backend mapping.
  """
  @spec register(String.t(), backend_addr()) :: :ok
  def register(service_name, backend_addr)
      when is_binary(service_name) and service_name != "" do
    :ets.insert(@table_name, {service_name, backend_addr})
    :ok
  end

  @doc """
  Unregister a service mapping.
  """
  @spec unregister(String.t()) :: :ok
  def unregister(service_name) when is_binary(service_name) do
    :ets.delete(@table_name, service_name)
    :ok
  end

  @doc """
  Load service routes from a string in the format:
  `"service1=host1:port1,service2=host2:port2"`
  """
  @spec load_from_string(String.t()) :: :ok | {:error, atom()}
  def load_from_string(spec) when is_binary(spec) and spec != "" do
    services =
      spec
      |> String.split(",", trim: true)
      |> Enum.reduce([], fn entry, acc ->
        case String.split(String.trim(entry), "=", parts: 2) do
          [svc, addr_str] ->
            case parse_host_port(String.trim(addr_str)) do
              {:ok, addr} -> [{String.trim(svc), addr} | acc]
              :error -> acc
            end

          _ ->
            acc
        end
      end)

    Enum.each(services, fn {svc, addr} -> register(svc, addr) end)
    :ok
  end

  def load_from_string(spec) when is_binary(spec), do: :ok

  @doc """
  Get all registered services.
  """
  @spec list() :: [{String.t(), backend_addr()}]
  def list do
    :ets.tab2list(@table_name)
  end

  @doc """
  Count registered services.
  """
  @spec count() :: non_neg_integer()
  def count do
    :ets.info(@table_name, :size)
  rescue
    _e in ArgumentError -> 0
  catch
    _, _ -> 0
  end

  # GenServer callbacks

  @impl true
  def init([]) do
    table =
      :ets.new(@table_name, [
        :named_table,
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    # Load from environment or config
    case System.get_env("ZTLP_RELAY_VIP_SERVICES") do
      nil ->
        case Application.get_env(:ztlp_relay, :vip_services, []) do
          [] -> :ok
          services when is_list(services) ->
            Enum.each(services, fn {svc, addr} -> register(svc, addr) end)
          spec when is_binary(spec) ->
            load_from_string(spec)
        end

      spec ->
        load_from_string(spec)
    end

    {:ok, %{table: table}}
  end

  defp parse_host_port(host_port) do
    case String.split(host_port, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, ""} ->
            case :inet.parse_address(String.to_charlist(host)) do
              {:ok, ip} -> {:ok, {ip, port}}
              {:error, _} -> :error
            end

          _ ->
            :error
        end

      _ ->
        :error
    end
  end
end
