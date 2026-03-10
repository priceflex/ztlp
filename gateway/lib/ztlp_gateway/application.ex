defmodule ZtlpGateway.Application do
  @moduledoc """
  OTP Application for the ZTLP Gateway.

  Starts the supervision tree in dependency order:

      ZtlpGateway.Application
      ├── ZtlpGateway.Stats              (counters — no deps)
      ├── ZtlpGateway.AuditLog           (ETS table — no deps)
      ├── ZtlpGateway.SessionRegistry    (ETS table — no deps)
      ├── ZtlpGateway.PolicyEngine       (loads config — depends on Config module)
      ├── ZtlpGateway.NsClient           (UDP client for ZTLP-NS queries — optional)
      ├── ZtlpGateway.SessionSupervisor  (DynamicSupervisor for Session GenServers)
      └── ZtlpGateway.Listener           (UDP socket — starts last, depends on everything)

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
    # Initialize the identity cache (ETS table, not a supervised process)
    ZtlpGateway.Identity.init_cache()

    children = [
      ZtlpGateway.Stats,
      ZtlpGateway.AuditLog,
      ZtlpGateway.SessionRegistry,
      ZtlpGateway.PolicyEngine,
      ZtlpGateway.NsClient,
      {DynamicSupervisor, strategy: :one_for_one, name: ZtlpGateway.SessionSupervisor},
      ZtlpGateway.Listener
    ]

    opts = [strategy: :one_for_one, name: ZtlpGateway.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
