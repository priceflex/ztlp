defmodule ZtlpRelay.Application do
  @moduledoc """
  OTP Application for the ZTLP Relay.

  Starts the supervision tree:

      ZtlpRelay.Application
      ├── ZtlpRelay.Stats
      ├── ZtlpRelay.SessionRegistry
      ├── ZtlpRelay.SessionSupervisor (DynamicSupervisor)
      ├── ZtlpRelay.RelayRegistry        (mesh mode only)
      ├── ZtlpRelay.MeshManager           (mesh mode only)
      └── ZtlpRelay.UdpListener

  Mesh components are only started when `ZTLP_RELAY_MESH=true` or
  `config :ztlp_relay, mesh_enabled: true`.
  """

  use Application

  @impl true
  def start(_type, _args) do
    # Load YAML config before starting supervision tree
    ZtlpRelay.YamlConfig.load_and_apply()

    base_children = [
      ZtlpRelay.Stats,
      ZtlpRelay.Drain,
      ZtlpRelay.SignalHandler,
      ZtlpRelay.StatsReporter,
      ZtlpRelay.MetricsServer,
      ZtlpRelay.SessionRegistry,
      {DynamicSupervisor, strategy: :one_for_one, name: ZtlpRelay.SessionSupervisor}
    ]

    mesh_children =
      if ZtlpRelay.Config.mesh_enabled?() do
        ns_children =
          if ZtlpRelay.Config.ns_server() do
            [ZtlpRelay.NsClient]
          else
            []
          end

        [ZtlpRelay.RelayRegistry, ZtlpRelay.ForwardingTable] ++
          ns_children ++ [ZtlpRelay.MeshManager]
      else
        []
      end

    children = base_children ++ mesh_children ++ [ZtlpRelay.UdpListener]

    opts = [strategy: :one_for_one, name: ZtlpRelay.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
