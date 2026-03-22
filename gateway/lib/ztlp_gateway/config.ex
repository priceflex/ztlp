defmodule ZtlpGateway.Config do
  @moduledoc """
  Runtime configuration for the ZTLP Gateway.

  Reads config values from the application environment at runtime
  (not compile-time module attributes). This allows config to be
  set differently for test vs production without recompilation.

  ## Configuration Keys

  - `:port` — UDP listen port (default: 23097, test: 0 for random)
  - `:backends` — list of backend service maps
  - `:policies` — list of access policy maps
  - `:session_timeout_ms` — idle timeout per session (default: 300,000ms)
  - `:max_sessions` — maximum concurrent sessions (default: 10,000)
  - `:ns_server_host` — ZTLP-NS server address tuple (default: `{127, 0, 0, 1}`)
  - `:ns_server_port` — ZTLP-NS server UDP port (default: 23096)
  - `:ns_query_timeout_ms` — timeout for NS queries in ms (default: 2000)

  ## Environment Variables

  - `ZTLP_GATEWAY_PORT` — override listen port
  - `ZTLP_GATEWAY_BACKENDS` — comma-separated `name:host:port` entries
    Example: `metrics:127.0.0.1:9103,api:10.0.0.1:8080`
  - `ZTLP_GATEWAY_POLICIES` — comma-separated `identity:service` entries
    Use `*` for wildcard (any authenticated client).
    Example: `*:metrics,admin.zone:api`
  - `ZTLP_GATEWAY_SESSION_TIMEOUT_MS` — idle timeout per session
  - `ZTLP_GATEWAY_MAX_SESSIONS` — max concurrent sessions
  """

  @doc """
  Get a configuration value by key.

  Falls back to a default if not set in the application environment.
  Supports env var overrides for `:port`, `:backends`, `:policies`,
  `:session_timeout_ms`, and `:max_sessions`.
  """
  @spec get(atom()) :: term()
  def get(key)

  def get(:port) do
    case System.get_env("ZTLP_GATEWAY_PORT") do
      nil -> Application.get_env(:ztlp_gateway, :port, 23097)
      port -> String.to_integer(port)
    end
  end

  def get(:backends) do
    case System.get_env("ZTLP_GATEWAY_BACKENDS") do
      nil ->
        Application.get_env(:ztlp_gateway, :backends, [])

      env ->
        env
        |> String.split(",", trim: true)
        |> Enum.map(fn entry ->
          case String.split(entry, ":", parts: 3) do
            [name, host, port] ->
              %{name: name, host: String.to_charlist(host), port: String.to_integer(port)}

            _ ->
              nil
          end
        end)
        |> Enum.reject(&is_nil/1)
    end
  end

  def get(:policies) do
    case System.get_env("ZTLP_GATEWAY_POLICIES") do
      nil ->
        Application.get_env(:ztlp_gateway, :policies, [])

      env ->
        # Parse entries and group by service
        entries =
          env
          |> String.split(",", trim: true)
          |> Enum.map(fn entry ->
            case String.split(entry, ":", parts: 2) do
              [identity, service] -> {service, identity}
              _ -> nil
            end
          end)
          |> Enum.reject(&is_nil/1)

        # Group by service and build policy rules
        entries
        |> Enum.group_by(fn {svc, _} -> svc end, fn {_, id} -> id end)
        |> Enum.map(fn {service, identities} ->
          allow =
            if Enum.member?(identities, "*") do
              :all
            else
              identities
            end

          %{service: service, allow: allow}
        end)
    end
  end

  def get(:session_timeout_ms) do
    case System.get_env("ZTLP_GATEWAY_SESSION_TIMEOUT_MS") do
      nil -> Application.get_env(:ztlp_gateway, :session_timeout_ms, 300_000)
      ms -> String.to_integer(ms)
    end
  end

  def get(:max_sessions) do
    case System.get_env("ZTLP_GATEWAY_MAX_SESSIONS") do
      nil -> Application.get_env(:ztlp_gateway, :max_sessions, 10_000)
      n -> String.to_integer(n)
    end
  end

  def get(:ns_server_host),
    do: Application.get_env(:ztlp_gateway, :ns_server_host, {127, 0, 0, 1})

  def get(:ns_server_port), do: Application.get_env(:ztlp_gateway, :ns_server_port, 23096)

  def get(:ns_query_timeout_ms),
    do: Application.get_env(:ztlp_gateway, :ns_query_timeout_ms, 2000)

  # ── TLS Configuration ───────────────────────────────────────────

  def get(:tls_enabled) do
    case System.get_env("ZTLP_GATEWAY_TLS_ENABLED") do
      nil -> Application.get_env(:ztlp_gateway, :tls_enabled, false)
      "true" -> true
      "1" -> true
      _ -> false
    end
  end

  def get(:tls_port) do
    case System.get_env("ZTLP_GATEWAY_TLS_PORT") do
      nil -> Application.get_env(:ztlp_gateway, :tls_port, 8443)
      port -> String.to_integer(port)
    end
  end

  def get(:tls_acceptors) do
    Application.get_env(:ztlp_gateway, :tls_acceptors, 10)
  end

  def get(:tls_mtls_required) do
    Application.get_env(:ztlp_gateway, :tls_mtls_required, false)
  end

  def get(:tls_mtls_optional) do
    Application.get_env(:ztlp_gateway, :tls_mtls_optional, true)
  end

  def get(:header_signing_enabled) do
    Application.get_env(:ztlp_gateway, :header_signing_enabled, false)
  end

  def get(:header_signing_secret) do
    # First check env var override, then direct config, then env var name from config
    case System.get_env("ZTLP_HEADER_HMAC_SECRET") do
      nil ->
        case Application.get_env(:ztlp_gateway, :header_signing_secret) do
          nil ->
            env_key = Application.get_env(:ztlp_gateway, :header_signing_secret_env)
            if env_key, do: System.get_env(env_key), else: nil
          secret -> secret
        end
      secret -> secret
    end
  end

  def get(:header_signing_timestamp_window) do
    Application.get_env(:ztlp_gateway, :header_signing_timestamp_window, 60)
  end

  # ── Relay Registration ─────────────────────────────────────────

  @doc """
  Relay server address for dynamic registration.

  Format: `ZTLP_RELAY_SERVER=host:port`
  Returns `{ip_tuple, port}` or nil if not set.
  """
  @spec relay_server() :: {:inet.ip_address(), non_neg_integer()} | nil
  def relay_server do
    case System.get_env("ZTLP_RELAY_SERVER") do
      nil ->
        Application.get_env(:ztlp_gateway, :relay_server)

      str ->
        case String.split(str, ":") do
          [host, port_str] ->
            case Integer.parse(port_str) do
              {port, ""} ->
                case :inet.parse_address(String.to_charlist(host)) do
                  {:ok, ip} -> {ip, port}
                  {:error, _} ->
                    # Try DNS resolution
                    case :inet.getaddr(String.to_charlist(host), :inet) do
                      {:ok, ip} -> {ip, port}
                      _ -> nil
                    end
                end

              _ ->
                nil
            end

          _ ->
            nil
        end
    end
  end

  @doc """
  Shared secret for relay registration HMAC.

  Set via `ZTLP_RELAY_REGISTRATION_SECRET` env var.
  Returns nil if not set (dev mode — sends registrations without HMAC).
  """
  @spec registration_secret() :: binary() | nil
  def registration_secret do
    case System.get_env("ZTLP_RELAY_REGISTRATION_SECRET") do
      nil -> Application.get_env(:ztlp_gateway, :registration_secret)
      secret -> secret
    end
  end

  @doc """
  Service names this gateway exposes. Used in relay registration packets.

  Format: `ZTLP_GATEWAY_SERVICE_NAMES=beta,api,metrics`
  Default: `["default"]`
  """
  @spec service_names() :: [String.t()]
  def service_names do
    case System.get_env("ZTLP_GATEWAY_SERVICE_NAMES") do
      nil ->
        Application.get_env(:ztlp_gateway, :service_names, ["default"])

      str ->
        str
        |> String.split(",", trim: true)
        |> Enum.map(&String.trim/1)
    end
  end

  @doc """
  Gateway node ID (16 bytes) for relay registration.

  Read from `ZTLP_GATEWAY_NODE_ID` env var (hex-encoded, 32 hex chars = 16 bytes).
  If not set, generates a random ID.
  """
  @spec node_id() :: binary()
  def node_id do
    case System.get_env("ZTLP_GATEWAY_NODE_ID") do
      nil ->
        case Application.get_env(:ztlp_gateway, :node_id) do
          nil ->
            id = :crypto.strong_rand_bytes(16)
            Application.put_env(:ztlp_gateway, :node_id, id)
            id

          id when byte_size(id) == 16 ->
            id

          _ ->
            id = :crypto.strong_rand_bytes(16)
            Application.put_env(:ztlp_gateway, :node_id, id)
            id
        end

      hex_str ->
        case Base.decode16(hex_str, case: :mixed) do
          {:ok, <<id::binary-size(16)>>} -> id
          _ ->
            id = :crypto.strong_rand_bytes(16)
            Application.put_env(:ztlp_gateway, :node_id, id)
            id
        end
    end
  end

  @doc "NS host for service discovery. Only used in Docker/production."
  @spec ns_host() :: String.t() | nil
  def ns_host, do: System.get_env("ZTLP_GATEWAY_NS_HOST")

  @doc "NS port for service discovery. Only used in Docker/production."
  @spec ns_port() :: non_neg_integer() | nil
  def ns_port do
    case System.get_env("ZTLP_GATEWAY_NS_PORT") do
      nil -> nil
      port -> String.to_integer(port)
    end
  end
end
