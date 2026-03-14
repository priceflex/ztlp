defmodule ZtlpNs.EndpointStore do
  @moduledoc """
  Tracks peer endpoints for NAT traversal hole punching.

  Stores two categories of addresses for each NodeID:

  - **Reported** — addresses the client tells us about (e.g., from STUN)
  - **Learned** — addresses we observe as the UDP source (what the NAT gives us)

  Entries have a configurable TTL (default 30 seconds) and are automatically
  expired on access. This module is used by the NS server to facilitate
  Nebula-style hole punching between peers.

  ## Storage

  Uses an ETS table for fast concurrent reads. The GenServer handles
  periodic cleanup of expired entries.
  """

  use GenServer

  @table :ztlp_ns_endpoints
  @cleanup_interval_ms 10_000
  @default_ttl_seconds 30

  # ── Types ──────────────────────────────────────────────────────────

  @type endpoint_type :: :reported | :learned
  @type endpoint :: {endpoint_type(), :inet.ip_address(), :inet.port_number(), integer()}

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record an endpoint for a node.

  - `node_id` — 16-byte binary NodeID (or hex string)
  - `ip` — IP address tuple (e.g., {192, 168, 1, 1})
  - `port` — UDP port number
  - `type` — `:reported` (client-provided) or `:learned` (observed source)
  - `opts` — optional `:ttl` override in seconds
  """
  @spec record_endpoint(binary(), :inet.ip_address(), :inet.port_number(), endpoint_type(), keyword()) :: :ok
  def record_endpoint(node_id, ip, port, type, opts \\ []) do
    node_key = normalize_node_id(node_id)
    ttl = Keyword.get(opts, :ttl, ttl_seconds())
    expires_at = System.monotonic_time(:second) + ttl

    # Key: {node_key, type, ip, port} — deduplicates same endpoint
    :ets.insert(@table, {{node_key, type, ip, port}, expires_at})
    :ok
  end

  @doc """
  Get all non-expired endpoints for a node.

  Returns a list of `{type, ip, port}` tuples.
  """
  @spec get_endpoints(binary()) :: [{endpoint_type(), :inet.ip_address(), :inet.port_number()}]
  def get_endpoints(node_id) do
    node_key = normalize_node_id(node_id)
    now = System.monotonic_time(:second)

    # Match all entries for this node
    match_spec = [
      {
        {{node_key, :"$1", :"$2", :"$3"}, :"$4"},
        [{:>, :"$4", now}],
        [{{:"$1", :"$2", :"$3"}}]
      }
    ]

    :ets.select(@table, match_spec)
  end

  @doc """
  Get all non-expired endpoints for a node, formatted as `{ip_string, port}` pairs.

  Returns a list suitable for wire encoding.
  """
  @spec get_endpoint_addrs(binary()) :: [{String.t(), :inet.port_number()}]
  def get_endpoint_addrs(node_id) do
    get_endpoints(node_id)
    |> Enum.map(fn {_type, ip, port} ->
      {format_ip(ip), port}
    end)
    |> Enum.uniq()
  end

  @doc """
  Remove all endpoints for a node.
  """
  @spec clear_node(binary()) :: :ok
  def clear_node(node_id) do
    node_key = normalize_node_id(node_id)
    # Delete all entries matching this node_key prefix
    match_spec = [
      {
        {{node_key, :_, :_, :_}, :_},
        [],
        [true]
      }
    ]

    :ets.select_delete(@table, match_spec)
    :ok
  end

  @doc """
  Remove all endpoints (used in tests).
  """
  @spec clear_all() :: :ok
  def clear_all do
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc """
  Count total entries in the store (including expired).
  """
  @spec count() :: non_neg_integer()
  def count do
    :ets.info(@table, :size)
  end

  @doc """
  Get the configured TTL in seconds.
  """
  @spec ttl_seconds() :: non_neg_integer()
  def ttl_seconds do
    Application.get_env(:ztlp_ns, :endpoint_ttl_seconds, @default_ttl_seconds)
  end

  # ── GenServer Callbacks ────────────────────────────────────────────

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :public, :set])
    schedule_cleanup()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    expire_entries()
    schedule_cleanup()
    {:noreply, state}
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  defp expire_entries do
    now = System.monotonic_time(:second)

    match_spec = [
      {
        {:_, :"$1"},
        [{:"=<", :"$1", now}],
        [true]
      }
    ]

    :ets.select_delete(@table, match_spec)
  end

  defp normalize_node_id(node_id) when is_binary(node_id) and byte_size(node_id) == 16 do
    node_id
  end

  defp normalize_node_id(hex) when is_binary(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} when byte_size(bin) == 16 -> bin
      _ -> hex
    end
  end

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  defp format_ip({a, b, c, d, e, f, g, h}) do
    :inet.ntoa({a, b, c, d, e, f, g, h}) |> to_string()
  end
end
