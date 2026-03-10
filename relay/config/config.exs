import Config

config :ztlp_relay,
  listen_port: 23095,
  listen_address: {0, 0, 0, 0},
  session_timeout_ms: 300_000,
  max_sessions: 10_000

import_config "#{config_env()}.exs"
