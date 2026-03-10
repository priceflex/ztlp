defmodule ZtlpGateway.Config do
  @moduledoc """
  Runtime configuration for the ZTLP Gateway.

  Reads config values from the application environment at runtime
  (not compile-time module attributes). This allows config to be
  set differently for test vs production without recompilation.

  ## Configuration Keys

  - `:port` — UDP listen port (default: 23097, test: 0 for random)
  - `:backends` — list of backend service maps
  - `:policies` — list of access policy maps
  - `:session_timeout_ms` — idle timeout per session (default: 300,000ms)
  - `:max_sessions` — maximum concurrent sessions (default: 10,000)
  """

  @doc """
  Get a configuration value by key.

  Falls back to a default if not set in the application environment.
  """
  @spec get(atom()) :: term()
  def get(:port), do: Application.get_env(:ztlp_gateway, :port, 23097)
  def get(:backends), do: Application.get_env(:ztlp_gateway, :backends, [])
  def get(:policies), do: Application.get_env(:ztlp_gateway, :policies, [])
  def get(:session_timeout_ms), do: Application.get_env(:ztlp_gateway, :session_timeout_ms, 300_000)
  def get(:max_sessions), do: Application.get_env(:ztlp_gateway, :max_sessions, 10_000)
end
