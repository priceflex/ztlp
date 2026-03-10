# General configuration for ZTLP-NS.
# Import environment-specific config at the bottom.
import Config

# Default UDP port for the namespace query server.
# Port 0 = OS-assigned (useful for testing).
# Production deployments should set this to a fixed port.
config :ztlp_ns, :port, 23096

# Import environment specific config
import_config "#{config_env()}.exs"
