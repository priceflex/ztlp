defmodule ZtlpRelay.SessionSupervisor do
  @moduledoc """
  DynamicSupervisor for session GenServers.

  Uses `:one_for_one` strategy so crashed sessions don't affect others.
  Sessions are started on demand when new session registrations occur.
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
