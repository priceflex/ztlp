import Config

# Use port 0 so the OS assigns a random ephemeral port.
# This avoids port conflicts when running tests in parallel.
config :ztlp_gateway, :port, 0

# Short timeout for faster test teardown.
config :ztlp_gateway, :session_timeout_ms, 5_000

# ZTLP-NS: use ram_copies for Mnesia in tests (disc_copies requires distributed node)
config :ztlp_ns, :storage_mode, :ram_copies
