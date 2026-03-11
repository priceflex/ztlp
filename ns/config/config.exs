# General configuration for ZTLP-NS.
# Import environment-specific config at the bottom.
import Config

# Default UDP port for the namespace query server.
# Port 0 = OS-assigned (useful for testing).
# Production deployments should set this to a fixed port.
config :ztlp_ns, :port, 23096

# Logger configuration — use custom formatter for structured/JSON output.
# Format is controlled by ZTLP_LOG_FORMAT env var (console|structured|json).
config :logger, :console,
  format: {ZtlpNs.LogFormatter, :format},
  metadata: :all

# Import environment specific config
import_config "#{config_env()}.exs"
