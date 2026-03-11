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
  config :ztlp_gateway,
    port: String.to_integer(System.get_env("ZTLP_GATEWAY_PORT", "23097")),
    session_timeout_ms: String.to_integer(System.get_env("ZTLP_GATEWAY_SESSION_TIMEOUT_MS", "300000")),
    max_sessions: String.to_integer(System.get_env("ZTLP_GATEWAY_MAX_SESSIONS", "10000"))
end
