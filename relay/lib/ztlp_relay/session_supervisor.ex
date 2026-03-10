defmodule ZtlpRelay.SessionSupervisor do
  @moduledoc """
  DynamicSupervisor for ZTLP session GenServers.

  Each active relay session gets its own `ZtlpRelay.Session` GenServer,
  started under this DynamicSupervisor.  The `:one_for_one` strategy
  ensures that if one session process crashes (e.g., unexpected error
  during packet forwarding), it is restarted independently without
  affecting any other active sessions.

  This provides fault isolation — a single misbehaving session cannot
  bring down the relay.  DynamicSupervisor (rather than a static
  Supervisor) is used because sessions are created and destroyed at
  runtime as peers connect and disconnect; we don't know the session
  list at boot time.

  Started as part of the OTP supervision tree in `ZtlpRelay.Application`.
  """

  @doc """
  Start a new session under the supervisor.

  Options are passed to `ZtlpRelay.Session.start_link/1`.
  """
  @spec start_session(keyword()) :: DynamicSupervisor.on_start_child()
  def start_session(opts) do
    DynamicSupervisor.start_child(
      ZtlpRelay.SessionSupervisor,
      {ZtlpRelay.Session, opts}
    )
  end

  @doc """
  Count active session processes.
  """
  @spec count_children() :: non_neg_integer()
  def count_children do
    %{active: active} = DynamicSupervisor.count_children(ZtlpRelay.SessionSupervisor)
    active
  end
end
