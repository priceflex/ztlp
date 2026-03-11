import Config

# Use port 0 to let the OS assign a random available port for tests
config :ztlp_relay,
  listen_port: 0,
  session_timeout_ms: 1_000,
  metrics_enabled: false
