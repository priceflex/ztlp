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

  require Logger

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
  Amplification-truncation multiplier for UDP responses (anti-reflection
  defense — see server.ex's maybe_truncate_reply/3).

  A response is truncated once it exceeds `request_size * this value`
  bytes. Default 8 is deliberately generous for typical KEY/SVC lookups,
  but records with larger CBOR payloads (e.g. USER records carrying
  role+email+public_key, or GROUP records with many members) queried
  with a short name can legitimately exceed an 8x multiplier and get
  truncated even though nothing is actually being abused — the client
  then fails to parse the truncated wire format. Override via
  ZTLP_NS_AMPLIFICATION_THRESHOLD if your record payloads are larger
  than KEY records typically are.
  """
  @spec amplification_threshold() :: pos_integer()
  def amplification_threshold do
    case System.get_env("ZTLP_NS_AMPLIFICATION_THRESHOLD") do
      nil -> Application.get_env(:ztlp_ns, :amplification_threshold, 8)
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

  @doc """
  Directory for CA key/cert storage.

  Defaults to `~/.ztlp/ca`. Override with `ZTLP_CA_DATA_DIR` env var.
  For production Docker deployments, set to a path on a persistent volume
  (e.g., `/app/data/ca`) and mount with `-v ztlp-ns-data:/app/data`.
  """
  @spec ca_data_dir() :: String.t()
  def ca_data_dir do
    # ZTLP_CA_DIR takes priority over ZTLP_CA_DATA_DIR. This matches
    # cert_authority.ex's default_ca_dir/0 priority order — the two used
    # to disagree (this function checked ZTLP_CA_DATA_DIR first), which
    # meant CertAuthority and the NS registration-signing-key persistence
    # path (server.ex's get_registration_key/0, which calls this function)
    # could resolve to two DIFFERENT directories depending on which env
    # vars were set, silently splitting CA state across two locations.
    # Both now agree: ZTLP_CA_DIR wins if set, else ZTLP_CA_DATA_DIR, else
    # the Application-env override, else ~/.ztlp/ca.
    case System.get_env("ZTLP_CA_DIR") do
      nil ->
        case System.get_env("ZTLP_CA_DATA_DIR") do
          nil ->
            case Application.get_env(:ztlp_ns, :ca_data_dir) do
              nil ->
                home = System.user_home!()
                Path.join([home, ".ztlp", "ca"])
              dir -> dir
            end
          dir -> dir
        end
      dir -> dir
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

  @doc """
  Per-peer-IP rate limit for `/admin/records`.

  Returns `{count, window_seconds}` — i.e. `count` requests allowed per
  rolling `window_seconds` window. Defaults to `{12, 60}` (covers a
  5-minute cron with retry headroom).

  Override via `ZTLP_NS_ADMIN_API_RATE_LIMIT=N/W` (e.g. `"30/60"`).
  Invalid values fall back to the default.
  """
  @spec admin_api_rate_limit() :: {pos_integer(), pos_integer()}
  def admin_api_rate_limit do
    case System.get_env("ZTLP_NS_ADMIN_API_RATE_LIMIT") do
      nil ->
        # App-config fallback is also normalized — a bad value like {12, 0}
        # from a misconfigured deployment would otherwise cause div-by-zero
        # in AdminApiRateLimiter.do_check/1. CodeRabbit #97.
        normalize_rate_limit(Application.get_env(:ztlp_ns, :admin_api_rate_limit, {12, 60}))
      str ->
        case String.split(str, "/", parts: 2) do
          [c, w] ->
            case {Integer.parse(c), Integer.parse(w)} do
              {{count, ""}, {window, ""}} when count > 0 and window > 0 ->
                {count, window}
              _ -> {12, 60}
            end
          _ -> {12, 60}
        end
    end
  end

  defp normalize_rate_limit({count, window})
       when is_integer(count) and is_integer(window) and count > 0 and window > 0,
       do: {count, window}
  defp normalize_rate_limit(_invalid), do: {12, 60}

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

  @spec identity_key_file() :: String.t() | nil
  @doc """
  Path to the file backing NS's registration signing key.

  This is the Ed25519 keypair NS uses to sign every record it stores
  (see server.ex's ensure_registration_key/0 + Record.sign/2 call sites).
  Gateways verify these signatures against a configured trust anchor
  before accepting ANY record from NS — so this key MUST be stable
  across restarts, or every gateway's trust anchor goes stale the moment
  NS restarts and would otherwise pick a fresh random key each boot.

  Override with `ZTLP_NS_IDENTITY_KEY_FILE`. Defaults to
  `<ca_data_dir>/registration_signing.key` — i.e. the same durable
  volume already used for CA data, so a fresh deployment persists a
  stable key without requiring any extra env var or operator setup.
  """
  def identity_key_file do
    case System.get_env("ZTLP_NS_IDENTITY_KEY_FILE") do
      nil ->
        case Application.get_env(:ztlp_ns, :identity_key_file) do
          nil -> Path.join(ca_data_dir(), "registration_signing.key")
          path -> path
        end
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

  @doc """
  Whether PEER_ENDPOINTS (0x0A) and PUNCH_REPORT (0x0C) requests must
  carry a valid Ed25519 signature over the claimed node_id before their
  reported/learned endpoints are written to the EndpointStore.

  [CWE-284/irt-rwzo] Without this, any UDP sender can claim to BE any
  node_id (the requester_node_id in PEER_ENDPOINTS, the node_id in
  PUNCH_REPORT) with zero proof of ownership, and NS will happily
  associate the attacker's source address with a victim's node_id in
  the EndpointStore -- poisoning where future PUNCH_NOTIFY coordination
  gets sent for that node_id (endpoint-store poisoning / hole-punch
  hijack).

  When `true` (default), NS requires a valid Ed25519 signature (see
  `ZtlpNs.EndpointAuth`) before recording ANY reported/learned endpoint
  for a claimed node_id. Unsigned (legacy) PEER_ENDPOINTS requests are
  still answered (the read side was never the vulnerability -- you
  already need to know the target's node_id to ask), just without the
  tracking side effect. Unsigned PUNCH_REPORT requests are ACKed for
  backward-compat but silently dropped (no write).

  Set `ZTLP_NS_REQUIRE_ENDPOINT_AUTH=false` for dev/demo or for older
  clients that predate the signed wire format (mirrors
  `require_registration_auth?/0`'s pattern).
  """
  @spec require_endpoint_auth?() :: boolean()
  def require_endpoint_auth? do
    case System.get_env("ZTLP_NS_REQUIRE_ENDPOINT_AUTH") do
      val when val in ["false", "0", "no"] -> false
      nil -> Application.get_env(:ztlp_ns, :require_endpoint_auth, true)
      _ -> true
    end
  end

  @doc """
  Whether the PEER_ENDPOINTS (0x0A) serve path should prefer `:reported`
  endpoints over `:learned` when offering standalone dial candidates.

  When `true` (default), if a node has any `:reported` endpoint we return ONLY
  the reported set and suppress `:learned` (NS-observed control-plane source)
  candidates — they are transient outbound NAT mappings, not inbound listeners,
  and offering them as dial targets poisons the operator's bounded parallel-dial
  race (KELLYMANCINO-PC, 2026-06-15). When a node has NO reported endpoint we
  fall back to the full set so symmetric-NAT hole punching still has a hint.
  Bilateral PUNCH_NOTIFY coordination always uses the full set regardless.

  Set `ZTLP_NS_PEER_ENDPOINTS_PREFER_REPORTED=false` to restore the legacy
  "return everything" behavior at runtime.

  Default: `true`.
  """
  @spec peer_endpoints_prefer_reported?() :: boolean()
  def peer_endpoints_prefer_reported? do
    case System.get_env("ZTLP_NS_PEER_ENDPOINTS_PREFER_REPORTED") do
      val when val in ["false", "0", "no"] -> false
      nil -> Application.get_env(:ztlp_ns, :peer_endpoints_prefer_reported, true)
      _ -> true
    end
  end

  @doc """
  Load the admin-API HMAC secret from `ZTLP_NS_ADMIN_API_SECRET` and store
  it in `Application.get_env(:ztlp_ns, :admin_api_secret)` for runtime use
  by `ZtlpNs.AdminApi.verify_request/5`.

  Accepted forms:
  - 64-char lowercase or uppercase hex (decoded to 32 raw bytes)
  - 32 raw bytes (stored as-is)

  Anything else (missing, empty, malformed hex, wrong length) leaves the
  Application env at `nil` and logs a warning. The route returns 401 for
  every request when the secret is `nil`, so absence is fail-closed —
  there is no insecure default.
  """
  @spec load_admin_api_secret_from_env() :: :ok
  def load_admin_api_secret_from_env do
    case System.get_env("ZTLP_NS_ADMIN_API_SECRET") do
      nil ->
        Logger.info("[admin_api] secret not configured; /admin/records will reject all requests")
        Application.delete_env(:ztlp_ns, :admin_api_secret)

      "" ->
        Logger.info("[admin_api] secret env var is empty; /admin/records will reject all requests")
        Application.delete_env(:ztlp_ns, :admin_api_secret)

      raw when is_binary(raw) and byte_size(raw) == 32 ->
        Application.put_env(:ztlp_ns, :admin_api_secret, raw)
        Logger.info("[admin_api] secret loaded from env (32 raw bytes)")

      hex when is_binary(hex) and byte_size(hex) == 64 ->
        case Base.decode16(hex, case: :mixed) do
          {:ok, bytes} when byte_size(bytes) == 32 ->
            Application.put_env(:ztlp_ns, :admin_api_secret, bytes)
            Logger.info("[admin_api] secret loaded from env (64-char hex → 32 bytes)")

          _ ->
            Logger.warning("[admin_api] ZTLP_NS_ADMIN_API_SECRET looks 64 chars but isn't valid hex; /admin/records disabled")
            Application.delete_env(:ztlp_ns, :admin_api_secret)
        end

      other ->
        Logger.warning("[admin_api] ZTLP_NS_ADMIN_API_SECRET wrong length=#{byte_size(other)} (need 32 raw or 64 hex); /admin/records disabled")
        Application.delete_env(:ztlp_ns, :admin_api_secret)
    end

    :ok
  end
end
