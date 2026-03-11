defmodule ZtlpNs.Application do
  @moduledoc """
  OTP Application for ZTLP-NS.

  Starts the supervision tree in dependency order:

  1. **Mnesia** — initialized before supervision tree starts (schema + tables)
  2. **Cluster** — attempts to join seed nodes if configured (federation)
  3. **TrustAnchor** — creates ETS table for root keys
  4. **Store** — GenServer that ensures Mnesia tables exist and are ready
  5. **AntiEntropy** — periodic Merkle-tree sync with cluster peers
  6. **Server** — opens the UDP socket for queries (depends on Store)

  Uses `:one_for_one` strategy because each component is independent
  and can be restarted without affecting the others. Unlike the old ETS
  implementation, Mnesia tables survive GenServer crashes — data persists
  on disk and is automatically reloaded on restart.

  ## Federation

  When `cluster.seed_nodes` is configured (or `ZTLP_NS_SEED_NODES` env var),
  the application will attempt to join an existing NS cluster on startup.
  If no seed nodes are reachable, it falls back to standalone operation.
  Anti-entropy runs periodically to keep clustered nodes in sync.
  """

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    # Load YAML config before starting supervision tree
    ZtlpNs.YamlConfig.load_and_apply()

    :ok = ensure_mnesia_started()

    # Try to join cluster if seed nodes are configured
    ZtlpNs.Cluster.ensure_replicated()

    children = [
      # Order matters: TrustAnchor first, then Store (Mnesia tables),
      # then AntiEntropy (needs Store), then Server (UDP)
      ZtlpNs.TrustAnchor,
      ZtlpNs.Store,
      ZtlpNs.AntiEntropy,
      ZtlpNs.MetricsServer,
      ZtlpNs.Server
    ]

    opts = [strategy: :one_for_one, name: ZtlpNs.Supervisor]
    result = Supervisor.start_link(children, opts)

    case result do
      {:ok, pid} ->
        if ZtlpNs.Cluster.clustered?() do
          Logger.info("[ztlp-ns] Started in cluster mode with #{length(ZtlpNs.Cluster.members())} nodes")
        else
          Logger.info("[ztlp-ns] Started in standalone mode")
        end
        {:ok, pid}

      error ->
        error
    end
  end

  # Initializes Mnesia before the supervision tree starts.
  # Schema creation must happen before Mnesia.start().
  # For :ram_copies mode, we skip schema creation (no disk needed).
  defp ensure_mnesia_started do
    # Set Mnesia directory if configured
    case ZtlpNs.Config.mnesia_dir() do
      nil -> :ok
      dir -> Application.put_env(:mnesia, :dir, dir)
    end

    storage_mode = ZtlpNs.Config.storage_mode()

    # Only create disk schema for disc_copies mode
    if storage_mode == :disc_copies do
      case :mnesia.create_schema([node()]) do
        :ok -> :ok
        {:error, {_, {:already_exists, _}}} -> :ok
        {:error, reason} -> raise "Mnesia schema creation failed: #{inspect(reason)}"
      end
    end

    case :mnesia.start() do
      :ok -> :ok
      {:error, {:already_started, :mnesia}} -> :ok
      {:error, reason} -> raise "Mnesia start failed: #{inspect(reason)}"
    end

    :ok
  end
end
