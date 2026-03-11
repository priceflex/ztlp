import Config

# Runtime configuration for ZTLP Relay OTP releases.
#
# This file is evaluated at runtime (boot time), not at compile time.
# It is the OTP-standard way to configure releases from environment
# variables. Added in Elixir 1.11.
#
# Note: Most env var reads already happen at runtime in
# ZtlpRelay.Config — this file handles settings that must be
# configured before the application supervision tree starts
# (e.g., Logger format, listen address).

config :logger, level: String.to_atom(System.get_env("ZTLP_LOG_LEVEL", "info"))

if config_env() == :prod do
  # Core relay settings — these feed into Application.get_env/3 which
  # ZtlpRelay.Config falls back on when env vars are not set.
  config :ztlp_relay,
    listen_port: String.to_integer(System.get_env("ZTLP_RELAY_PORT", "23095")),
    session_timeout_ms: String.to_integer(System.get_env("ZTLP_RELAY_SESSION_TIMEOUT_MS", "300000")),
    max_sessions: String.to_integer(System.get_env("ZTLP_RELAY_MAX_SESSIONS", "10000"))
end
