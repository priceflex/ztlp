defmodule ZtlpGateway.HttpHeaderInjector do
  @moduledoc """
  HTTP identity header injection for the ZTLP Gateway.

  When the gateway terminates TLS and proxies to backend services,
  it injects identity headers based on the mTLS client certificate.
  This enables passwordless authentication for backend services.

  ## Auth Modes

  - `:passthrough` — No headers injected, traffic passes through
  - `:identity` — Identity headers injected but not enforced;
    backend can use them for context
  - `:enforce` — Identity headers required; requests without valid
    mTLS cert are rejected with 401

  ## Identity Headers

  All 11 identity headers:

  | Header | Description |
  |--------|-------------|
  | `X-ZTLP-Node-ID` | 128-bit NodeID (hex) from cert SAN URI |
  | `X-ZTLP-Node-Name` | Node FQDN from cert CN |
  | `X-ZTLP-Zone` | Zone name from cert O |
  | `X-ZTLP-Authenticated` | "true" or "false" |
  | `X-ZTLP-Assurance` | Assurance level: "hardware", "device-bound", "software", "unknown" |
  | `X-ZTLP-Key-Source` | Key source: "yubikey", "tpm", "secure-enclave", etc. |
  | `X-ZTLP-Key-Attestation` | "verified" or "unverified" |
  | `X-ZTLP-Cert-Fingerprint` | SHA-256 fingerprint (hex) |
  | `X-ZTLP-Cert-Serial` | X.509 serial number |
  | `X-ZTLP-Timestamp` | ISO8601 timestamp of header injection |
  | `X-ZTLP-Signature` | HMAC-SHA256 signature of all other X-ZTLP headers |

  ## Anti-Forgery

  All client-provided `X-ZTLP-*` headers are stripped before injection
  to prevent clients from forging identity headers.
  """

  @ztlp_header_prefix "x-ztlp-"

  @doc """
  Inject identity headers into an HTTP request.

  ## Parameters
  - `data` — raw HTTP request bytes
  - `identity` — identity map from TlsIdentity
  - `service` — service name for route config lookup

  Returns the modified HTTP request bytes.
  """
  @spec inject(binary(), map() | nil, String.t() | nil) :: binary()
  def inject(data, identity, service) do
    route_config = get_route_config(service)
    auth_mode = Map.get(route_config, :auth_mode, :passthrough)

    case auth_mode do
      :passthrough ->
        data

      :identity ->
        inject_headers(data, identity)

      :enforce ->
        if identity && Map.get(identity, :authenticated, false) do
          min_assurance = Map.get(route_config, :min_assurance, :unknown)
          if ZtlpGateway.TlsIdentity.meets_assurance?(identity, min_assurance) do
            inject_headers(data, identity)
          else
            build_403_response("Insufficient assurance level")
          end
        else
          build_401_response()
        end
    end
  end

  @doc """
  Build identity headers from an identity map.

  Returns a list of `{header_name, header_value}` tuples.
  """
  @spec build_headers(map() | nil) :: [{String.t(), String.t()}]
  def build_headers(nil), do: build_headers(ZtlpGateway.TlsIdentity.anonymous_identity())
  def build_headers(identity) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    headers = [
      {"X-ZTLP-Node-ID", Map.get(identity, :node_id) || ""},
      {"X-ZTLP-Node-Name", Map.get(identity, :node_name) || ""},
      {"X-ZTLP-Zone", Map.get(identity, :zone) || ""},
      {"X-ZTLP-Authenticated", to_string(Map.get(identity, :authenticated, false))},
      {"X-ZTLP-Assurance", assurance_to_string(Map.get(identity, :assurance, :unknown))},
      {"X-ZTLP-Key-Source", Map.get(identity, :key_source) || "unknown"},
      {"X-ZTLP-Key-Attestation", if(Map.get(identity, :attestation_verified, false), do: "verified", else: "unverified")},
      {"X-ZTLP-Cert-Fingerprint", Map.get(identity, :cert_fingerprint) || ""},
      {"X-ZTLP-Cert-Serial", Map.get(identity, :cert_serial) || ""},
      {"X-ZTLP-Timestamp", now}
    ]

    # Add signature
    secret = ZtlpGateway.HeaderSigner.default_secret()
    sig = ZtlpGateway.HeaderSigner.sign(headers, secret)
    headers ++ [{"X-ZTLP-Signature", sig}]
  end

  @doc """
  Strip all X-ZTLP-* headers from HTTP request data.

  This prevents clients from forging identity headers.
  """
  @spec strip_ztlp_headers(binary()) :: binary()
  def strip_ztlp_headers(data) do
    case split_http_request(data) do
      {:ok, request_line, headers, body} ->
        filtered = Enum.reject(headers, fn {name, _} ->
          String.starts_with?(String.downcase(name), @ztlp_header_prefix)
        end)
        rebuild_http_request(request_line, filtered, body)
      _ -> data
    end
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp inject_headers(data, identity) do
    case split_http_request(data) do
      {:ok, request_line, headers, body} ->
        # Strip existing X-ZTLP-* headers (anti-forgery)
        filtered = Enum.reject(headers, fn {name, _} ->
          String.starts_with?(String.downcase(name), @ztlp_header_prefix)
        end)

        # Add identity headers
        identity_headers = build_headers(identity)
        all_headers = filtered ++ identity_headers

        rebuild_http_request(request_line, all_headers, body)
      _ -> data
    end
  end

  defp split_http_request(data) do
    case :binary.split(data, "\r\n") do
      [request_line, rest] ->
        case :binary.split(rest, "\r\n\r\n") do
          [header_block, body] ->
            headers = parse_headers(header_block)
            {:ok, request_line, headers, body}
          [header_block] ->
            headers = parse_headers(header_block)
            {:ok, request_line, headers, ""}
        end
      _ -> :error
    end
  end

  defp parse_headers(header_block) do
    header_block
    |> String.split("\r\n")
    |> Enum.flat_map(fn line ->
      case String.split(line, ": ", parts: 2) do
        [name, value] -> [{name, value}]
        _ -> []
      end
    end)
  end

  defp rebuild_http_request(request_line, headers, body) do
    header_lines = Enum.map(headers, fn {name, value} -> "#{name}: #{value}" end)
    [request_line | header_lines]
    |> Enum.join("\r\n")
    |> Kernel.<>("\r\n\r\n")
    |> Kernel.<>(body)
  end

  defp build_401_response do
    "HTTP/1.1 401 Unauthorized\r\n" <>
    "Content-Type: text/plain\r\n" <>
    "Content-Length: 24\r\n" <>
    "Connection: close\r\n" <>
    "\r\n" <>
    "Client cert required.\r\n"
  end

  defp build_403_response(reason) do
    body = reason <> "\r\n"
    "HTTP/1.1 403 Forbidden\r\n" <>
    "Content-Type: text/plain\r\n" <>
    "Content-Length: #{byte_size(body)}\r\n" <>
    "Connection: close\r\n" <>
    "\r\n" <>
    body
  end

  defp get_route_config(nil), do: %{auth_mode: :passthrough}
  defp get_route_config(service) do
    case ZtlpGateway.SniRouter.get_route(service) do
      {:ok, route} -> route
      _ -> %{auth_mode: :passthrough}
    end
  end

  defp assurance_to_string(:hardware), do: "hardware"
  defp assurance_to_string(:device_bound), do: "device-bound"
  defp assurance_to_string(:software), do: "software"
  defp assurance_to_string(:unknown), do: "unknown"
  defp assurance_to_string(_), do: "unknown"
end
