defmodule ZtlpGateway.Application do
  @moduledoc """
  OTP Application for the ZTLP Gateway.

  Starts the supervision tree in dependency order:

      ZtlpGateway.Application
      ├── ZtlpGateway.Stats              (counters — no deps)
      ├── ZtlpGateway.AuditLog           (ETS table — no deps)
      ├── ZtlpGateway.SessionRegistry    (ETS table — no deps)
      ├── ZtlpGateway.HeaderSigner.NonceCache (ETS nonce cache)
      ├── ZtlpGateway.PolicyEngine       (loads config — depends on Config module)
      ├── ZtlpGateway.NsClient           (UDP client for ZTLP-NS queries — optional)
      ├── ZtlpGateway.SessionSupervisor  (DynamicSupervisor for Session GenServers)
      ├── ZtlpGateway.Listener           (UDP socket — starts last, depends on everything)
      └── ZtlpGateway.ServiceRegistrar   (NS service registration — periodic)

  The Identity cache is initialized as a side effect during app start
  (it's a plain ETS table, not a GenServer).

  ## Restart Strategy

  `:one_for_one` — if any child crashes, only that child restarts.
  The Listener restarting won't affect existing sessions.
  The SessionSupervisor crashing would lose all sessions (acceptable
  for the prototype; production would use `:rest_for_one`).
  """

  use Application

  @impl true
  def start(_type, _args) do
    # Load YAML config before starting supervision tree
    ZtlpGateway.YamlConfig.load_and_apply()

    # Initialize the identity cache (ETS table, not a supervised process)
    ZtlpGateway.Identity.init_cache()

    children =
      [
        ZtlpGateway.Stats,
        ZtlpGateway.StatsReporter,
        ZtlpGateway.MetricsServer,
        ZtlpGateway.AuditLog,
        ZtlpGateway.SessionRegistry,
        ZtlpGateway.HeaderSigner.NonceCache,
        ZtlpGateway.PolicyEngine,
        ZtlpGateway.NsClient,
        {DynamicSupervisor, strategy: :one_for_one, name: ZtlpGateway.SessionSupervisor},
        ZtlpGateway.Listener,
        ZtlpGateway.RelayRegistrar,
        ZtlpGateway.ServiceRegistrar
      ] ++ tls_children()

    opts = [strategy: :one_for_one, name: ZtlpGateway.Supervisor]
    result = Supervisor.start_link(children, opts)

    # Run post-startup validation (after supervision tree is running)
    case result do
      {:ok, _pid} ->
        Task.start(fn -> ZtlpGateway.HeaderSigner.validate_secret!() end)
      _ ->
        :ok
    end

    result
  end

  defp tls_children do
    if ZtlpGateway.Config.get(:tls_enabled) do
      opts = [
        port: ZtlpGateway.Config.get(:tls_port),
        certfile: ZtlpGateway.Config.get(:tls_cert_file),
        keyfile: ZtlpGateway.Config.get(:tls_key_file),
        cacertfile: ZtlpGateway.Config.get(:tls_ca_cert_file),
        acceptors: ZtlpGateway.Config.get(:tls_acceptors),
        require_client_cert: ZtlpGateway.Config.get(:tls_mtls_required)
      ]

      [
        ZtlpGateway.CertCache,
        ZtlpGateway.SniRouter,
        {ZtlpGateway.TlsListener, opts}
      ]
    else
      []
    end
  end
end
