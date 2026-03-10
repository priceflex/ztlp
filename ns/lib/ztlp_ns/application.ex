defmodule ZtlpNs.Application do
  @moduledoc """
  OTP Application for ZTLP-NS.

  Starts the supervision tree in dependency order:

  1. **TrustAnchor** — must start first (creates ETS table for root keys)
  2. **Store** — creates the records + revocation ETS tables
  3. **Server** — opens the UDP socket for queries (depends on Store)

  Uses `:one_for_one` strategy because each component is independent
  and can be restarted without affecting the others. If the Store
  crashes, the ETS tables are lost (they're owned by the GenServer
  process), but records can be re-populated from the zone authorities.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Order matters: TrustAnchor first (ETS), then Store (ETS), then Server (UDP)
      ZtlpNs.TrustAnchor,
      ZtlpNs.Store,
      ZtlpNs.Server
    ]

    opts = [strategy: :one_for_one, name: ZtlpNs.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
