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

    # Initialize enrollment token tracking table
    ZtlpNs.Enrollment.init()

    # Initialize rate-limiting ETS table for registration auth
    ZtlpNs.RegistrationAuth.init_rate_limit()

    # Initialize the TOFU pin table for PEER_ENDPOINTS/PUNCH_REPORT
    # sender authentication (irt-rwzo).
    ZtlpNs.EndpointAuth.init()

    # Load enrollment secret from env if provided
    case System.get_env("ZTLP_ENROLLMENT_SECRET") do
      nil -> :ok
      hex when byte_size(hex) == 64 ->
        case Base.decode16(hex, case: :mixed) do
          {:ok, secret} -> ZtlpNs.Enrollment.set_zone_secret(secret)
          _ -> :ok
        end
      _ -> :ok
    end

    # Load admin API HMAC secret from env (read by AdminApi.verify_request/5
    # on every /admin/records request — supports rotation via Application.put_env
    # without a service restart).
    ZtlpNs.Config.load_admin_api_secret_from_env()

    # Load per-tenant admin-API registry from env once at boot, cache in
    # :persistent_term.
    #
    # CodeRabbit PR #98 F2: previously this rescue was UNCONDITIONAL fail-
    # open — any parse error logged and continued in legacy mode. That
    # silently disabled Phase 2 isolation on operator typos. The fix:
    #   * If NO ZTLP_NS_ADMIN_API_TENANT_* env vars are set → legacy
    #     mode is the EXPECTED state; swallow the (theoretical) error
    #     and continue.
    #   * If ANY tenant env vars ARE set → operator intended isolation;
    #     a parse failure is a deployment bug, not a fall-through case.
    #     Re-raise so OTP refuses to start the node (better than running
    #     prod with isolation silently disabled).
    try do
      ZtlpNs.AdminApi.TenantRegistry.cache_at_boot()
    rescue
      e ->
        tenant_env_present? =
          System.get_env()
          |> Map.keys()
          |> Enum.any?(&String.starts_with?(&1, "ZTLP_NS_ADMIN_API_TENANT_"))

        suffix =
          if tenant_env_present?,
            do: " — failing closed (tenant env present)",
            else: " — running in legacy mode"

        Logger.error(
          "[admin_api] tenant registry load failed: #{Exception.message(e)}" <> suffix
        )

        ZtlpNs.AdminApi.TenantRegistry.clear_cache()

        if tenant_env_present?, do: reraise(e, __STACKTRACE__)
    end

    children = [
      # Order matters: TrustAnchor first, then Store (Mnesia tables),
      # then RateLimiter (ETS), then QuerySupervisor (worker pool),
      # then AntiEntropy (needs Store), then Server (UDP)
      ZtlpNs.TrustAnchor,
      ZtlpNs.Store,
      ZtlpNs.RateLimiter,
      ZtlpNs.AdminApiRateLimiter,
      {Task.Supervisor, name: ZtlpNs.QuerySupervisor, max_children: ZtlpNs.Config.worker_pool_size()},
      ZtlpNs.EndpointStore,
      ZtlpNs.Audit,
      ZtlpNs.CertAuthority,
      ZtlpNs.AntiEntropy,
      ZtlpNs.MetricsServer,
      ZtlpNs.Server
    ]

    opts = [strategy: :one_for_one, name: ZtlpNs.Supervisor]
    result = Supervisor.start_link(children, opts)

    case result do
      {:ok, pid} ->
        # Seed initial relay records (rich format for iOS relay-side VIP)
        ZtlpNs.RelaySeeder.seed()

        vsn = ZtlpNs.version()

        if ZtlpNs.Cluster.clustered?() do
          Logger.info("[ztlp-ns] Started v#{vsn} in cluster mode with #{length(ZtlpNs.Cluster.members())} nodes")
        else
          Logger.info("[ztlp-ns] Started v#{vsn} in standalone mode")
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
      dir -> Application.put_env(:mnesia, :dir, dir |> to_charlist_if_needed())
    end

    storage_mode = ZtlpNs.Config.storage_mode()

    # For disc_copies mode, Mnesia schema must be created ON DISK before
    # Mnesia starts. But OTP auto-starts Mnesia (it's in extra_applications),
    # so we must stop it first, create the disk schema, then restart.
    if storage_mode == :disc_copies do
      # Stop Mnesia if auto-started by OTP
      :mnesia.stop()

      case :mnesia.create_schema([node()]) do
        :ok ->
          Logger.info("[NS] Created Mnesia disk schema for #{node()}")
        {:error, {_, {:already_exists, _}}} ->
          :ok
        {:error, reason} ->
          raise "Mnesia schema creation failed: #{inspect(reason)}"
      end
    end

    case :mnesia.start() do
      :ok -> :ok
      {:error, {:already_started, :mnesia}} -> :ok
      {:error, reason} -> raise "Mnesia start failed: #{inspect(reason)}"
    end

    :ok
  end

  defp to_charlist_if_needed(dir) when is_list(dir), do: dir
  defp to_charlist_if_needed(dir) when is_binary(dir), do: String.to_charlist(dir)
end
