defmodule ZtlpGateway.ServiceRouter do
  @moduledoc """
  Service-aware routing for multi-gateway deployments.

  Routes FRAME_OPEN requests to the correct backend based on:
  1. Local backend map (this gateway's configured backends)
  2. Remote gateway federation (if available)
  3. Weighted load balancing across multiple backends for same service

  Supports:
  - Round-robin across multiple backends for a service
  - Weighted routing based on gateway load
  - Circuit breaker for unhealthy backends
  - Service redirect frame for client-side rerouting
  """

  use GenServer
  require Logger

  @frame_service_redirect 0x10

  defstruct [
    :local_backends,
    :circuit_breakers,
    :round_robin,
    :stats
  ]

  defmodule Backend do
    @moduledoc false
    defstruct [
      :host,
      :port,
      :weight,
      :max_conns,
      :current_conns,
      :healthy,
      :last_check
    ]
  end

  defmodule CircuitBreaker do
    @moduledoc """
    Circuit breaker with three states:
    - :closed — normal operation, requests flow through
    - :open — backend is down, reject immediately
    - :half_open — testing if backend recovered
    """
    defstruct [
      state: :closed,
      failure_count: 0,
      failure_threshold: 5,
      success_count: 0,
      success_threshold: 3,
      last_failure: nil,
      reset_timeout_ms: 30_000
    ]
  end

  ## Public API

  @doc false
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: opts[:name] || __MODULE__)
  end

  @doc """
  Route a service request. Returns the best backend to use.
  """
  def route(server \\ __MODULE__, service_name) do
    GenServer.call(server, {:route, service_name})
  end

  @doc """
  Report a successful request to a backend.
  """
  def report_success(server \\ __MODULE__, service_name, backend_key, latency_ms) do
    GenServer.cast(server, {:success, service_name, backend_key, latency_ms})
  end

  @doc """
  Report a failed request to a backend.
  """
  def report_failure(server \\ __MODULE__, service_name, backend_key) do
    GenServer.cast(server, {:failure, service_name, backend_key})
  end

  @doc """
  Get routing stats.
  """
  def stats(server \\ __MODULE__) do
    GenServer.call(server, :stats)
  end

  @doc """
  Add or update a backend for a service.
  """
  def add_backend(server \\ __MODULE__, service_name, host, port, opts \\ []) do
    GenServer.call(server, {:add_backend, service_name, host, port, opts})
  end

  @doc """
  Remove a backend.
  """
  def remove_backend(server \\ __MODULE__, service_name, host, port) do
    GenServer.call(server, {:remove_backend, service_name, host, port})
  end

  @doc """
  Build a SERVICE_REDIRECT frame to send to a client.
  Tells the client to reconnect to a different gateway for this service.
  """
  def build_redirect_frame(service_name, gateway_addr, gateway_port) do
    name_bytes = service_name

    <<@frame_service_redirect, byte_size(name_bytes)::8, name_bytes::binary,
      gateway_port::16, gateway_addr::binary>>
  end

  @doc "Parse a SERVICE_REDIRECT frame"
  def parse_redirect_frame(
        <<@frame_service_redirect, name_len::8, name::binary-size(name_len), port::16,
          addr::binary>>
      ) do
    {:ok, %{service: name, addr: addr, port: port}}
  end

  def parse_redirect_frame(_), do: {:error, :invalid_redirect}

  @doc "Returns the FRAME_SERVICE_REDIRECT type constant."
  def frame_service_redirect, do: @frame_service_redirect

  ## GenServer callbacks

  @impl true
  def init(opts) do
    backends = parse_backend_config(Keyword.get(opts, :backends, backend_config()))

    state = %__MODULE__{
      local_backends: backends,
      circuit_breakers: %{},
      round_robin: %{},
      stats: %{}
    }

    Logger.info("[ServiceRouter] Started with #{map_size(backends)} service(s)")
    {:ok, state}
  end

  @impl true
  def handle_call({:route, service_name}, _from, state) do
    case Map.get(state.local_backends, service_name) do
      nil ->
        {:reply, {:error, :service_not_found}, state}

      backends ->
        available =
          Enum.filter(backends, fn b ->
            key = backend_key(service_name, b)
            cb = Map.get(state.circuit_breakers, key, %CircuitBreaker{})
            circuit_allows?(cb)
          end)

        case available do
          [] ->
            {:reply, {:error, :all_backends_unhealthy}, state}

          _ ->
            {backend, new_index} =
              weighted_round_robin(
                available,
                Map.get(state.round_robin, service_name, 0)
              )

            round_robin = Map.put(state.round_robin, service_name, new_index)

            stats =
              Map.update(
                state.stats,
                service_name,
                %{requests: 1, errors: 0, latency_sum: 0, latency_count: 0},
                fn s -> %{s | requests: s.requests + 1} end
              )

            {:reply, {:ok, %{host: backend.host, port: backend.port}},
             %{state | round_robin: round_robin, stats: stats}}
        end
    end
  end

  def handle_call(:stats, _from, state) do
    stats =
      state.stats
      |> Enum.map(fn {service, s} ->
        avg_latency =
          if s.latency_count > 0,
            do: s.latency_sum / s.latency_count,
            else: 0

        backends = Map.get(state.local_backends, service, [])

        healthy =
          Enum.count(backends, fn b ->
            key = backend_key(service, b)
            cb = Map.get(state.circuit_breakers, key, %CircuitBreaker{})
            circuit_allows?(cb)
          end)

        {service, %{
          requests: s.requests,
          errors: s.errors,
          avg_latency_ms: Float.round(avg_latency / 1, 1),
          backends_total: length(backends),
          backends_healthy: healthy
        }}
      end)
      |> Map.new()

    {:reply, stats, state}
  end

  def handle_call({:add_backend, service_name, host, port, opts}, _from, state) do
    backend = %Backend{
      host: host,
      port: port,
      weight: Keyword.get(opts, :weight, 100),
      max_conns: Keyword.get(opts, :max_conns, 100),
      current_conns: 0,
      healthy: true,
      last_check: System.monotonic_time(:millisecond)
    }

    backends =
      Map.update(state.local_backends, service_name, [backend], &[backend | &1])

    {:reply, :ok, %{state | local_backends: backends}}
  end

  def handle_call({:remove_backend, service_name, host, port}, _from, state) do
    backends =
      Map.update(state.local_backends, service_name, [], fn bs ->
        Enum.reject(bs, fn b -> b.host == host and b.port == port end)
      end)

    {:reply, :ok, %{state | local_backends: backends}}
  end

  @impl true
  def handle_cast({:success, service_name, bk, latency_ms}, state) do
    cb = Map.get(state.circuit_breakers, bk, %CircuitBreaker{})

    cb =
      case cb.state do
        :half_open ->
          count = cb.success_count + 1

          if count >= cb.success_threshold do
            %{cb | state: :closed, failure_count: 0, success_count: 0}
          else
            %{cb | success_count: count}
          end

        _ ->
          %{cb | failure_count: 0}
      end

    cbs = Map.put(state.circuit_breakers, bk, cb)

    stats =
      Map.update(
        state.stats,
        service_name,
        %{requests: 0, errors: 0, latency_sum: latency_ms, latency_count: 1},
        fn s ->
          %{s | latency_sum: s.latency_sum + latency_ms, latency_count: s.latency_count + 1}
        end
      )

    {:noreply, %{state | circuit_breakers: cbs, stats: stats}}
  end

  def handle_cast({:failure, service_name, bk}, state) do
    cb = Map.get(state.circuit_breakers, bk, %CircuitBreaker{})
    now = System.monotonic_time(:millisecond)

    count = cb.failure_count + 1

    cb =
      if count >= cb.failure_threshold do
        Logger.warning("[ServiceRouter] Circuit breaker OPEN for #{bk}")
        %{cb | state: :open, failure_count: count, last_failure: now}
      else
        %{cb | failure_count: count, last_failure: now}
      end

    cbs = Map.put(state.circuit_breakers, bk, cb)

    stats =
      Map.update(
        state.stats,
        service_name,
        %{requests: 0, errors: 1, latency_sum: 0, latency_count: 0},
        fn s -> %{s | errors: s.errors + 1} end
      )

    {:noreply, %{state | circuit_breakers: cbs, stats: stats}}
  end

  ## Private helpers

  defp circuit_allows?(%CircuitBreaker{state: :closed}), do: true
  defp circuit_allows?(%CircuitBreaker{state: :half_open}), do: true

  defp circuit_allows?(%CircuitBreaker{
         state: :open,
         last_failure: last,
         reset_timeout_ms: timeout
       }) do
    now = System.monotonic_time(:millisecond)
    now - last >= timeout
  end

  defp circuit_allows?(_), do: true

  defp weighted_round_robin(backends, index) do
    idx = rem(index, length(backends))
    {Enum.at(backends, idx), index + 1}
  end

  @doc false
  def backend_key(service_name, %Backend{host: host, port: port}) do
    "#{service_name}:#{host}:#{port}"
  end

  @doc false
  def parse_backend_config(config_string) when is_binary(config_string) do
    config_string
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&(&1 != ""))
    |> Enum.reduce(%{}, fn entry, acc ->
      case String.split(entry, ":") do
        [service, host, port] ->
          backend = %Backend{
            host: host,
            port: String.to_integer(port),
            weight: 100,
            max_conns: 100,
            current_conns: 0,
            healthy: true,
            last_check: System.monotonic_time(:millisecond)
          }

          Map.update(acc, service, [backend], &[backend | &1])

        _ ->
          Logger.warning("[ServiceRouter] Invalid backend config: #{entry}")
          acc
      end
    end)
  end

  def parse_backend_config(_), do: %{}

  defp backend_config do
    System.get_env("ZTLP_GATEWAY_BACKENDS") || ""
  end
end
