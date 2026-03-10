defmodule ZtlpRelay.Config do
  @moduledoc """
  Runtime configuration helpers for the ZTLP Relay.

  Reads values from application environment with sensible defaults.
  Supports both single-node and mesh-mode operation.
  """

  @doc """
  UDP listen port. Default: 23095 (0x5A37).
  """
  @spec listen_port() :: non_neg_integer()
  def listen_port do
    case System.get_env("ZTLP_RELAY_PORT") do
      nil -> Application.get_env(:ztlp_relay, :listen_port, 23095)
      port -> String.to_integer(port)
    end
  end

  @doc """
  UDP listen address. Default: {0, 0, 0, 0} (all interfaces).
  """
  @spec listen_address() :: :inet.ip_address()
  def listen_address do
    Application.get_env(:ztlp_relay, :listen_address, {0, 0, 0, 0})
  end

  @doc """
  Session inactivity timeout in milliseconds. Default: 300_000 (5 minutes).
  """
  @spec session_timeout_ms() :: non_neg_integer()
  def session_timeout_ms do
    case System.get_env("ZTLP_RELAY_SESSION_TIMEOUT_MS") do
      nil -> Application.get_env(:ztlp_relay, :session_timeout_ms, 300_000)
      ms -> String.to_integer(ms)
    end
  end

  @doc """
  Maximum number of concurrent sessions. Default: 10_000.
  """
  @spec max_sessions() :: non_neg_integer()
  def max_sessions do
    case System.get_env("ZTLP_RELAY_MAX_SESSIONS") do
      nil -> Application.get_env(:ztlp_relay, :max_sessions, 10_000)
      n -> String.to_integer(n)
    end
  end

  # --- Mesh configuration ---

  @doc """
  Whether mesh mode is enabled. Default: false.

  When false, the relay operates as a standalone single-node forwarder.
  """
  @spec mesh_enabled?() :: boolean()
  def mesh_enabled? do
    case System.get_env("ZTLP_RELAY_MESH") do
      "true" -> true
      "1" -> true
      nil -> Application.get_env(:ztlp_relay, :mesh_enabled, false)
      _ -> false
    end
  end

  @doc """
  Mesh inter-relay UDP listen port. Default: 23096.

  Separate from the client-facing port to avoid protocol confusion.
  """
  @spec mesh_listen_port() :: non_neg_integer()
  def mesh_listen_port do
    case System.get_env("ZTLP_RELAY_MESH_PORT") do
      nil -> Application.get_env(:ztlp_relay, :mesh_listen_port, 23096)
      port -> String.to_integer(port)
    end
  end

  @doc """
  Bootstrap relay addresses for mesh discovery.

  List of "host:port" strings. Default: [].
  """
  @spec mesh_bootstrap_relays() :: [String.t()]
  def mesh_bootstrap_relays do
    case System.get_env("ZTLP_RELAY_MESH_BOOTSTRAP") do
      nil ->
        Application.get_env(:ztlp_relay, :mesh_bootstrap_relays, [])

      str ->
        str
        |> String.split(",", trim: true)
        |> Enum.map(&String.trim/1)
    end
  end

  @doc """
  This relay's 16-byte node ID.

  Generated randomly if not configured. Stable across restarts
  if configured via environment or application config.
  """
  @spec relay_node_id() :: binary()
  def relay_node_id do
    case System.get_env("ZTLP_RELAY_NODE_ID") do
      nil ->
        case Application.get_env(:ztlp_relay, :relay_node_id) do
          nil -> :crypto.strong_rand_bytes(16)
          id when byte_size(id) == 16 -> id
          _ -> :crypto.strong_rand_bytes(16)
        end

      hex_str ->
        case Base.decode16(hex_str, case: :mixed) do
          {:ok, <<id::binary-size(16)>>} -> id
          _ -> :crypto.strong_rand_bytes(16)
        end
    end
  end

  @doc """
  This relay's role in the mesh. Default: :all.

  Roles: :ingress, :transit, :service, :all
  """
  @spec relay_role() :: :ingress | :transit | :service | :all
  def relay_role do
    case System.get_env("ZTLP_RELAY_ROLE") do
      "ingress" -> :ingress
      "transit" -> :transit
      "service" -> :service
      nil -> Application.get_env(:ztlp_relay, :relay_role, :all)
      _ -> :all
    end
  end

  @doc """
  Number of virtual nodes per relay in the hash ring. Default: 128.
  """
  @spec hash_ring_vnodes() :: pos_integer()
  def hash_ring_vnodes do
    case System.get_env("ZTLP_RELAY_VNODES") do
      nil -> Application.get_env(:ztlp_relay, :hash_ring_vnodes, 128)
      n -> String.to_integer(n)
    end
  end

  @doc """
  Ping sweep interval in milliseconds. Default: 15_000 (15 seconds).
  """
  @spec ping_interval_ms() :: non_neg_integer()
  def ping_interval_ms do
    case System.get_env("ZTLP_RELAY_PING_INTERVAL_MS") do
      nil -> Application.get_env(:ztlp_relay, :ping_interval_ms, 15_000)
      ms -> String.to_integer(ms)
    end
  end

  @doc """
  Relay timeout in milliseconds. Default: 300_000 (5 minutes).

  Relays not seen for longer than this are removed from the registry.
  """
  @spec relay_timeout_ms() :: non_neg_integer()
  def relay_timeout_ms do
    case System.get_env("ZTLP_RELAY_TIMEOUT_MS") do
      nil -> Application.get_env(:ztlp_relay, :relay_timeout_ms, 300_000)
      ms -> String.to_integer(ms)
    end
  end

  # --- Admission configuration ---

  @doc """
  RAT signing secret key (32 bytes). Auto-generated if not configured.

  Set via `ZTLP_RELAY_RAT_SECRET` env var (hex-encoded) or application config.
  """
  @spec rat_secret() :: binary()
  def rat_secret do
    case System.get_env("ZTLP_RELAY_RAT_SECRET") do
      nil ->
        case Application.get_env(:ztlp_relay, :rat_secret) do
          nil ->
            secret = :crypto.strong_rand_bytes(32)
            Application.put_env(:ztlp_relay, :rat_secret, secret)
            secret

          secret ->
            secret
        end

      hex ->
        Base.decode16!(hex, case: :mixed)
    end
  end

  @doc """
  Previous RAT signing secret key for key rotation. Nil if not set.
  """
  @spec rat_secret_previous() :: binary() | nil
  def rat_secret_previous do
    case System.get_env("ZTLP_RELAY_RAT_SECRET_PREVIOUS") do
      nil -> Application.get_env(:ztlp_relay, :rat_secret_previous)
      hex -> Base.decode16!(hex, case: :mixed)
    end
  end

  @doc """
  RAT time-to-live in seconds. Default: 300 (5 minutes).
  """
  @spec rat_ttl_seconds() :: pos_integer()
  def rat_ttl_seconds do
    case System.get_env("ZTLP_RELAY_RAT_TTL_SECONDS") do
      nil -> Application.get_env(:ztlp_relay, :rat_ttl_seconds, 300)
      n -> String.to_integer(n)
    end
  end

  @doc """
  Ingress rate limit per IP address: max HELLO messages per minute. Default: 10.
  """
  @spec ingress_rate_limit_per_ip() :: pos_integer()
  def ingress_rate_limit_per_ip do
    Application.get_env(:ztlp_relay, :ingress_rate_limit_per_ip, 10)
  end

  @doc """
  Ingress rate limit per NodeID: max HELLO messages per minute. Default: 5.
  """
  @spec ingress_rate_limit_per_node() :: pos_integer()
  def ingress_rate_limit_per_node do
    Application.get_env(:ztlp_relay, :ingress_rate_limit_per_node, 5)
  end

  @doc """
  Stateless Admission Challenge load threshold (fraction of max_sessions). Default: 0.7.
  """
  @spec sac_load_threshold() :: float()
  def sac_load_threshold do
    Application.get_env(:ztlp_relay, :sac_load_threshold, 0.7)
  end

  # --- NS Discovery configuration ---

  @doc "NS server address. Returns `{host, port}` or `nil`."
  @spec ns_server() :: {:inet.ip_address() | String.t(), non_neg_integer()} | nil
  def ns_server do
    case System.get_env("ZTLP_RELAY_NS_SERVER") do
      nil -> Application.get_env(:ztlp_relay, :ns_server)
      str ->
        case String.split(str, ":") do
          [host, port_str] ->
            case Integer.parse(port_str) do
              {port, ""} -> {host, port}
              _ -> nil
            end
          _ -> nil
        end
    end
  end

  @doc "NS discovery zone. Default: \"relay.ztlp\"."
  @spec ns_discovery_zone() :: String.t()
  def ns_discovery_zone do
    case System.get_env("ZTLP_RELAY_NS_DISCOVERY_ZONE") do
      nil -> Application.get_env(:ztlp_relay, :ns_discovery_zone, "relay.ztlp")
      zone -> zone
    end
  end

  @doc "NS refresh interval in ms. Default: 60_000."
  @spec ns_refresh_interval_ms() :: non_neg_integer()
  def ns_refresh_interval_ms do
    case System.get_env("ZTLP_RELAY_NS_REFRESH_INTERVAL_MS") do
      nil -> Application.get_env(:ztlp_relay, :ns_refresh_interval_ms, 60_000)
      ms -> String.to_integer(ms)
    end
  end

  @doc "Relay region. Default: \"default\"."
  @spec relay_region() :: String.t()
  def relay_region do
    case System.get_env("ZTLP_RELAY_REGION") do
      nil -> Application.get_env(:ztlp_relay, :relay_region, "default")
      region -> region
    end
  end

end
