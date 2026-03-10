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
  - `:ns_server_host` — ZTLP-NS server address tuple (default: `{127, 0, 0, 1}`)
  - `:ns_server_port` — ZTLP-NS server UDP port (default: 23096)
  - `:ns_query_timeout_ms` — timeout for NS queries in ms (default: 2000)
  """

  @doc """
  Get a configuration value by key.

  Falls back to a default if not set in the application environment.
  """
  @spec get(atom()) :: term()
  def get(:port) do
    case System.get_env("ZTLP_GATEWAY_PORT") do
      nil -> Application.get_env(:ztlp_gateway, :port, 23097)
      port -> String.to_integer(port)
    end
  end

  def get(:backends), do: Application.get_env(:ztlp_gateway, :backends, [])
  def get(:policies), do: Application.get_env(:ztlp_gateway, :policies, [])

  def get(:session_timeout_ms) do
    case System.get_env("ZTLP_GATEWAY_SESSION_TIMEOUT_MS") do
      nil -> Application.get_env(:ztlp_gateway, :session_timeout_ms, 300_000)
      ms -> String.to_integer(ms)
    end
  end

  def get(:max_sessions) do
    case System.get_env("ZTLP_GATEWAY_MAX_SESSIONS") do
      nil -> Application.get_env(:ztlp_gateway, :max_sessions, 10_000)
      n -> String.to_integer(n)
    end
  end

  def get(:ns_server_host), do: Application.get_env(:ztlp_gateway, :ns_server_host, {127, 0, 0, 1})
  def get(:ns_server_port), do: Application.get_env(:ztlp_gateway, :ns_server_port, 23096)
  def get(:ns_query_timeout_ms), do: Application.get_env(:ztlp_gateway, :ns_query_timeout_ms, 2000)

  @doc "NS host for service discovery. Only used in Docker/production."
  @spec ns_host() :: String.t() | nil
  def ns_host, do: System.get_env("ZTLP_GATEWAY_NS_HOST")

  @doc "NS port for service discovery. Only used in Docker/production."
  @spec ns_port() :: non_neg_integer() | nil
  def ns_port do
    case System.get_env("ZTLP_GATEWAY_NS_PORT") do
      nil -> nil
      port -> String.to_integer(port)
    end
  end
end
