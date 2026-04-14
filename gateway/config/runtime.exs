import Config

# Runtime configuration for ZTLP Gateway OTP releases.
#
# This file is evaluated at runtime (boot time), not at compile time.
# It is the OTP-standard way to configure releases from environment
# variables. Added in Elixir 1.11.
#
# Note: Most env var reads already happen at runtime in
# ZtlpGateway.Config — this file handles settings that must be
# configured before the application supervision tree starts
# (e.g., Logger format).

config :logger, level: String.to_atom(System.get_env("ZTLP_LOG_LEVEL", "info"))

if config_env() == :prod do
  # Parse ZTLP_NS_SERVER="host:port" into ns_server_host / ns_server_port
  ns_config =
    case System.get_env("ZTLP_NS_SERVER") do
      nil -> []
      "" -> []
      ns_str ->
        case String.split(ns_str, ":") do
          [host, port_str] ->
            case :inet.parse_address(String.to_charlist(host)) do
              {:ok, ip_tuple} ->
                [ns_server_host: ip_tuple,
                 ns_server_port: String.to_integer(port_str)]
              _ ->
                []
            end
          _ -> []
        end
    end

  config :ztlp_gateway,
    [{:port, String.to_integer(System.get_env("ZTLP_GATEWAY_PORT", "23097"))},
     {:session_timeout_ms, String.to_integer(System.get_env("ZTLP_GATEWAY_SESSION_TIMEOUT_MS", "300000"))},
     {:max_sessions, String.to_integer(System.get_env("ZTLP_GATEWAY_MAX_SESSIONS", "10000"))}
     | ns_config]
end
