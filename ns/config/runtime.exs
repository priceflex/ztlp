import Config

# Runtime configuration for ZTLP-NS OTP releases.
#
# This file is evaluated at runtime (boot time), not at compile time.
# It is the OTP-standard way to configure releases from environment
# variables. Added in Elixir 1.11.
#
# Note: Most env var reads already happen at runtime in
# ZtlpNs.Config — this file handles settings that must be
# configured before the application supervision tree starts
# (e.g., Logger format, Mnesia directory).

config :logger, level: String.to_atom(System.get_env("ZTLP_LOG_LEVEL", "info"))

if config_env() == :prod do
  config :ztlp_ns,
    port: String.to_integer(System.get_env("ZTLP_NS_PORT", "23096")),
    max_records: String.to_integer(System.get_env("ZTLP_NS_MAX_RECORDS", "100000"))

  # Mnesia directory — must be set before Mnesia starts
  if mnesia_dir = System.get_env("ZTLP_NS_MNESIA_DIR") do
    config :mnesia, dir: String.to_charlist(mnesia_dir)
  end
end
