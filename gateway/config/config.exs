import Config

# Default UDP listen port for the ZTLP Gateway.
config :ztlp_gateway, :port, 23097

# Backend services the gateway can forward traffic to.
# Each backend is a map with :name (string), :host (tuple), :port (integer).
config :ztlp_gateway, :backends, [
  %{name: "web", host: {127, 0, 0, 1}, port: 8080},
  %{name: "ssh", host: {127, 0, 0, 1}, port: 22}
]

# Access control policies.
# :allow can be :all (any authenticated node) or a list of zone/node names.
# Wildcard "*.zone.ztlp" matches all names ending in ".zone.ztlp".
config :ztlp_gateway, :policies, [
  %{service: "web", allow: :all},
  %{service: "ssh", allow: ["admin.example.ztlp"]}
]

# Session idle timeout in milliseconds. Sessions with no traffic
# for this duration are automatically terminated.
config :ztlp_gateway, :session_timeout_ms, 300_000

# Maximum concurrent sessions. New handshakes are rejected when
# this limit is reached.
config :ztlp_gateway, :max_sessions, 10_000

# Import environment-specific config (must be last line).
import_config "#{config_env()}.exs"
