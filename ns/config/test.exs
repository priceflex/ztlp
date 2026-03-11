import Config

# Tests always use OS-assigned port to avoid conflicts
config :ztlp_ns, :port, 0
config :ztlp_ns, :metrics_enabled, false

# Use RAM-only Mnesia tables in tests (no disk pollution, faster)
config :ztlp_ns, :storage_mode, :ram_copies
