defmodule ZtlpRelay.Application do
  @moduledoc """
  OTP Application for the ZTLP Relay.

  Starts the supervision tree:

      ZtlpRelay.Application
      ├── ZtlpRelay.Stats
      ├── ZtlpRelay.SessionRegistry
      ├── ZtlpRelay.SessionSupervisor (DynamicSupervisor)
      └── ZtlpRelay.UdpListener
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      ZtlpRelay.Stats,
      ZtlpRelay.SessionRegistry,
      {DynamicSupervisor, strategy: :one_for_one, name: ZtlpRelay.SessionSupervisor},
      ZtlpRelay.UdpListener
    ]

    opts = [strategy: :one_for_one, name: ZtlpRelay.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
