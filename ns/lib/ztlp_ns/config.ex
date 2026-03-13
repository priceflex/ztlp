defmodule ZtlpNs.Config do
  @moduledoc """
  Runtime configuration for ZTLP-NS.

  All configuration is read from application environment at runtime
  (not compile time) so it can be overridden in config files or at boot.

  ## Configuration Keys

  - `:port` — UDP port for the namespace query server (default: 23096).
    Use 0 for OS-assigned port (useful in tests and dev).
  - `:max_records` — Maximum records in the store (default: 100_000).
  - `:bootstrap_urls` — List of HTTPS URLs for bootstrap discovery.
  - `:storage_mode` — Mnesia storage mode (`:disc_copies` or `:ram_copies`).
  - `:mnesia_dir` — Directory for Mnesia data files.
  - `:identity_key_file` — Path for persisted NS signing key.
  - `:verify_trust_chain` — Enable full trust chain verification for lookups.
  - `:max_packet_size` — Maximum UDP packet size (default: 8192).
  - `:max_record_size` — Maximum encoded record size (default: 4096).
  - `:worker_pool_size` — Max concurrent query workers (default: 100).
  - `:name_suffix` — Required zone suffix for names (default: nil / no check).
  """

  @doc "UDP port for the namespace query server."
  @spec port() :: non_neg_integer()
  def port do
    case System.get_env("ZTLP_NS_PORT") do
      nil -> Application.get_env(:ztlp_ns, :port, 23096)
      port -> String.to_integer(port)
    end
  end

  @doc "Maximum records allowed in the store."
  @spec max_records() :: non_neg_integer()
  def max_records do
    case System.get_env("ZTLP_NS_MAX_RECORDS") do
      nil -> Application.get_env(:ztlp_ns, :max_records, 100_000)
      n -> String.to_integer(n)
    end
  end

  @doc """
  Mnesia storage mode for the record store.

  - `:disc_copies` (default) — RAM + disk persistence, survives restarts
  - `:ram_copies` — RAM only, faster but volatile (used in tests)

  Set via `ZTLP_NS_STORAGE_MODE=ram` or `ZTLP_NS_STORAGE_MODE=disc`,
  or `config :ztlp_ns, :storage_mode, :ram_copies`.
  """
  @spec storage_mode() :: :ram_copies | :disc_copies
  def storage_mode do
    case System.get_env("ZTLP_NS_STORAGE_MODE") do
      val when val in ["ram", "ram_copies"] -> :ram_copies
      val when val in ["disc", "disc_copies"] -> :disc_copies
      nil -> Application.get_env(:ztlp_ns, :storage_mode, :disc_copies)
      _ -> :disc_copies
    end
  end

  @doc """
  Directory where Mnesia stores its data files.

  Defaults to `Mnesia.nonode@nohost` (or equivalent) in the CWD.
  Override with `ZTLP_NS_MNESIA_DIR` env var.
  """
  @spec mnesia_dir() :: charlist() | nil
  def mnesia_dir do
    case System.get_env("ZTLP_NS_MNESIA_DIR") do
      nil -> Application.get_env(:ztlp_ns, :mnesia_dir, nil)
      dir -> String.to_charlist(dir)
    end
  end

  @doc "Per-IP query rate limit (queries per second)."
  @spec rate_limit_queries_per_second() :: non_neg_integer()
  def rate_limit_queries_per_second do
    case System.get_env("ZTLP_NS_RATE_LIMIT_PER_SEC") do
      nil -> Application.get_env(:ztlp_ns, :rate_limit_queries_per_second, 100)
      n -> String.to_integer(n)
    end
  end

  @doc "Rate limit burst allowance (max tokens per bucket)."
  @spec rate_limit_burst() :: non_neg_integer()
  def rate_limit_burst do
    case System.get_env("ZTLP_NS_RATE_LIMIT_BURST") do
      nil -> Application.get_env(:ztlp_ns, :rate_limit_burst, 200)
      n -> String.to_integer(n)
    end
  end

  @doc "HTTPS URLs for bootstrap relay discovery (Step 1 of NIP)."
  @spec bootstrap_urls() :: [String.t()]
  def bootstrap_urls do
    Application.get_env(:ztlp_ns, :bootstrap_urls, [
      "https://bootstrap.ztlp.org/.well-known/ztlp-relays.json"
    ])
  end

  @doc """
  Seed nodes for automatic cluster joining on startup.

  If configured, the node will attempt to join the first reachable
  seed node when the application starts. An empty list means
  standalone mode (default).

  Set via `ZTLP_NS_SEED_NODES` (comma-separated) or
  `config :ztlp_ns, :seed_nodes, [:"ns1@host1", :"ns2@host2"]`.
  """
  @spec seed_nodes() :: [atom()]
  def seed_nodes do
    case System.get_env("ZTLP_NS_SEED_NODES") do
      nil ->
        Application.get_env(:ztlp_ns, :seed_nodes, [])

      "" ->
        []

      nodes_str ->
        nodes_str
        |> String.split(",", trim: true)
        |> Enum.map(&String.trim/1)
        |> Enum.map(&String.to_atom/1)
    end
  end

  @doc "Path for the NS identity signing key file."
  @spec identity_key_file() :: String.t() | nil
  def identity_key_file do
    case System.get_env("ZTLP_NS_IDENTITY_KEY_FILE") do
      nil -> Application.get_env(:ztlp_ns, :identity_key_file)
      path -> path
    end
  end

  @doc "Whether to verify full trust chains on lookup (default: false)."
  @spec verify_trust_chain?() :: boolean()
  def verify_trust_chain? do
    Application.get_env(:ztlp_ns, :verify_trust_chain, false)
  end

  @doc "Maximum UDP packet size in bytes (default: 8192)."
  @spec max_packet_size() :: non_neg_integer()
  def max_packet_size do
    Application.get_env(:ztlp_ns, :max_packet_size, 8192)
  end

  @doc "Maximum encoded record size in bytes (default: 4096)."
  @spec max_record_size() :: non_neg_integer()
  def max_record_size do
    Application.get_env(:ztlp_ns, :max_record_size, 4096)
  end

  @doc "Maximum concurrent query workers (default: 100)."
  @spec worker_pool_size() :: non_neg_integer()
  def worker_pool_size do
    Application.get_env(:ztlp_ns, :worker_pool_size, 100)
  end

  @doc "Required zone suffix for names (nil = no suffix check)."
  @spec name_suffix() :: String.t() | nil
  def name_suffix do
    Application.get_env(:ztlp_ns, :name_suffix)
  end

  @doc """
  Whether to require Ed25519 signatures for registration requests.

  When `false` (dev/demo mode), the NS accepts unsigned registrations
  where the pubkey in the record data is used for authorization without
  signature verification. This allows clients with only X25519 keys
  (no Ed25519 signing keys) to register.

  Default: `true` (require signatures in production).
  Set `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false` for dev/demo.
  """
  @spec require_registration_auth?() :: boolean()
  def require_registration_auth? do
    case System.get_env("ZTLP_NS_REQUIRE_REGISTRATION_AUTH") do
      val when val in ["false", "0", "no"] -> false
      nil -> Application.get_env(:ztlp_ns, :require_registration_auth, true)
      _ -> true
    end
  end
end
