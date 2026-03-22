defmodule ZtlpGateway.AuditLog do
  @moduledoc """
  Session audit trail for the ZTLP Gateway.

  Records structured events for every session lifecycle change:
  - Session established (NodeID, source address, target service)
  - Session terminated (reason, duration, bytes transferred)
  - Policy denial (NodeID, requested service, denial reason)

  Events are stored in an ETS table (ordered by timestamp) for the
  prototype. Production deployments would persist to disk or ship
  to a log aggregator.

  ## Event Structure

  Each event is a map with at least:
  - `:event` — event type atom (:session_established, :session_terminated, :policy_denied)
  - `:timestamp` — monotonic timestamp (from System.monotonic_time)
  - `:wall_clock` — UTC datetime string
  - Additional fields depending on event type
  """

  use GenServer

  @table :ztlp_gateway_audit

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the audit log."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Log a session establishment event.

  ## Parameters
  - `session_id` — the ZTLP SessionID (16 bytes)
  - `remote_static` — the client's static X25519 public key
  - `source` — `{ip, port}` of the client
  - `service` — name of the target backend service
  """
  @spec session_established(binary(), binary(), {tuple(), non_neg_integer()}, String.t()) :: :ok
  def session_established(session_id, remote_static, source, service) do
    log(%{
      event: :session_established,
      session_id: session_id,
      remote_static: remote_static,
      source: source,
      service: service
    })
  end

  @doc """
  Log a session termination event.

  ## Parameters
  - `session_id` — the ZTLP SessionID
  - `reason` — termination reason (:timeout, :client_close, :backend_close, :error)
  - `duration_ms` — session duration in milliseconds
  - `bytes_in` — total bytes received from client
  - `bytes_out` — total bytes sent to client
  """
  @spec session_terminated(
          binary(),
          atom(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer()
        ) :: :ok
  def session_terminated(session_id, reason, duration_ms, bytes_in, bytes_out) do
    log(%{
      event: :session_terminated,
      session_id: session_id,
      reason: reason,
      duration_ms: duration_ms,
      bytes_in: bytes_in,
      bytes_out: bytes_out
    })
  end

  @doc """
  Log a policy denial event.

  ## Parameters
  - `remote_static` — the client's static public key (or nil if unknown)
  - `source` — `{ip, port}` of the client
  - `service` — requested service name
  - `reason` — denial reason atom
  """
  @spec policy_denied(binary() | nil, {tuple(), non_neg_integer()}, String.t(), atom()) :: :ok
  def policy_denied(remote_static, source, service, reason) do
    log(%{
      event: :policy_denied,
      remote_static: remote_static,
      source: source,
      service: service,
      reason: reason
    })
  end

  @doc """
  Get all audit events, newest first.

  Returns a list of event maps. Optional `limit` restricts the count.
  """
  @spec events(non_neg_integer() | :all) :: [map()]
  def events(limit \\ :all) do
    all =
      :ets.tab2list(@table)
      |> Enum.sort_by(fn {ts, _} -> ts end, :desc)
      |> Enum.map(fn {_ts, event} -> event end)

    case limit do
      :all -> all
      n when is_integer(n) -> Enum.take(all, n)
    end
  end

  # ---------------------------------------------------------------------------
  # TLS Audit Events
  # ---------------------------------------------------------------------------

  @doc """
  Log a TLS connection established event.

  ## Parameters
  - `hostname` — SNI hostname
  - `identity` — TLS identity map (from TlsIdentity)
  - `source` — `{ip, port}` of the client
  """
  @spec tls_connection_established(String.t(), map() | nil, {tuple(), non_neg_integer()} | nil) :: :ok
  def tls_connection_established(hostname, identity, source \\ nil) do
    log(%{
      event: :tls_connection_established,
      hostname: hostname,
      node_id: identity && Map.get(identity, :node_id),
      node_name: identity && Map.get(identity, :node_name),
      assurance: identity && Map.get(identity, :assurance),
      authenticated: identity != nil and Map.get(identity || %{}, :authenticated, false),
      source: source
    })
  end

  @doc """
  Log a TLS authentication failure event.

  ## Parameters
  - `hostname` — SNI hostname
  - `reason` — failure reason
  - `source` — `{ip, port}` of the client
  """
  @spec tls_auth_failed(String.t() | nil, atom() | String.t(), {tuple(), non_neg_integer()} | nil) :: :ok
  def tls_auth_failed(hostname, reason, source \\ nil) do
    log(%{
      event: :tls_auth_failed,
      hostname: hostname,
      reason: reason,
      source: source
    })
  end

  @doc """
  Log a certificate revocation check event.
  """
  @spec cert_revocation_checked(String.t(), boolean()) :: :ok
  def cert_revocation_checked(fingerprint, revoked) do
    log(%{
      event: :cert_revocation_checked,
      fingerprint: fingerprint,
      revoked: revoked
    })
  end

  @doc """
  Log a certificate revoked event.
  """
  @spec cert_revoked(String.t(), String.t()) :: :ok
  def cert_revoked(fingerprint, reason) do
    log(%{
      event: :cert_revoked,
      fingerprint: fingerprint,
      reason: reason
    })
  end

  @doc """
  Log an assurance level insufficient event.
  """
  @spec assurance_insufficient(String.t() | nil, atom(), atom(), String.t() | nil) :: :ok
  def assurance_insufficient(node_id, actual, required, service) do
    log(%{
      event: :assurance_insufficient,
      node_id: node_id,
      actual_assurance: actual,
      required_assurance: required,
      service: service
    })
  end

  @doc "Clear all audit events."
  @spec clear() :: :ok
  def clear do
    :ets.delete_all_objects(@table)
    :ok
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :ordered_set, :public, read_concurrency: true])
    {:ok, %{}}
  end

  # ---------------------------------------------------------------------------
  # Internal
  # ---------------------------------------------------------------------------

  defp log(event) do
    ts = System.monotonic_time(:nanosecond)
    wall = DateTime.utc_now() |> DateTime.to_iso8601()
    full_event = Map.merge(event, %{timestamp: ts, wall_clock: wall})
    :ets.insert(@table, {ts, full_event})
    :ok
  end
end
