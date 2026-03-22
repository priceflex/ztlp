defmodule ZtlpGateway.TlsIdentity do
  @moduledoc """
  mTLS identity extraction for the ZTLP Gateway.

  Extracts identity information from client TLS certificates:
  - NodeID from SAN URI (`ztlp://node/<hex>`)
  - Subject CN (node name)
  - Organization (zone)
  - ZTLP assurance level, key source, and attestation status
  - Certificate fingerprint and serial number

  This module is used by the TLS listener to populate identity
  headers for backend services.
  """

  require Logger

  @ztlp_assurance_oid {1, 3, 6, 1, 4, 1, 59999, 1}
  @ztlp_key_source_oid {1, 3, 6, 1, 4, 1, 59999, 2}
  @ztlp_attestation_oid {1, 3, 6, 1, 4, 1, 59999, 3}

  @type identity :: %{
    node_id: String.t() | nil,
    node_name: String.t() | nil,
    zone: String.t() | nil,
    assurance: atom(),
    key_source: String.t(),
    attestation_verified: boolean(),
    cert_fingerprint: String.t() | nil,
    cert_serial: String.t() | nil,
    authenticated: boolean()
  }

  @doc """
  Extract identity from an SSL socket's peer certificate.

  Returns an identity map or nil if no peer cert is available.
  """
  @spec extract_from_socket(term()) :: identity() | nil
  def extract_from_socket(ssl_socket) do
    case :ssl.peercert(ssl_socket) do
      {:ok, der} -> extract_from_der(der)
      {:error, :no_peercert} -> nil
      {:error, _reason} -> nil
    end
  end

  @doc """
  Extract identity from a DER-encoded certificate.
  """
  @spec extract_from_der(binary()) :: identity()
  def extract_from_der(der) when is_binary(der) do
    try do
      otp_cert = :public_key.pkix_decode_cert(der, :otp)
      {:OTPCertificate, tbs, _, _} = otp_cert
      {:OTPTBSCertificate, _, serial, _, _, _, subject, _, _, _, extensions} = tbs

      subject_info = parse_rdn(subject)
      extensions = extensions || []

      # Extract SAN URIs
      san_uris = extract_san_uris(extensions)

      # Extract NodeID from ztlp:// URI
      node_id = extract_node_id(san_uris)

      # Extract ZTLP extensions
      assurance = extract_assurance(extensions)
      key_source = extract_key_source(extensions)
      attestation = extract_attestation(extensions)

      # Certificate fingerprint
      fingerprint = :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)

      %{
        node_id: node_id,
        node_name: Map.get(subject_info, :cn),
        zone: Map.get(subject_info, :o),
        assurance: assurance,
        key_source: key_source,
        attestation_verified: attestation,
        cert_fingerprint: fingerprint,
        cert_serial: to_string(serial),
        authenticated: true
      }
    rescue
      _ -> anonymous_identity()
    catch
      _, _ -> anonymous_identity()
    end
  end

  @doc "Create an anonymous (unauthenticated) identity."
  @spec anonymous_identity() :: identity()
  def anonymous_identity do
    %{
      node_id: nil,
      node_name: nil,
      zone: nil,
      assurance: :unknown,
      key_source: "unknown",
      attestation_verified: false,
      cert_fingerprint: nil,
      cert_serial: nil,
      authenticated: false
    }
  end

  @doc """
  Check if an identity meets a minimum assurance level.
  """
  @spec meets_assurance?(identity(), atom()) :: boolean()
  def meets_assurance?(%{assurance: actual}, required) do
    assurance_value(actual) >= assurance_value(required)
  end

  @doc """
  Check if an identity is authenticated (has a valid cert).
  """
  @spec authenticated?(identity() | nil) :: boolean()
  def authenticated?(nil), do: false
  def authenticated?(%{authenticated: auth}), do: auth

  # ── Internal ───────────────────────────────────────────────────────

  defp assurance_value(:hardware), do: 4
  defp assurance_value(:device_bound), do: 3
  defp assurance_value(:software), do: 2
  defp assurance_value(:unknown), do: 1
  defp assurance_value(_), do: 0

  defp parse_rdn({:rdnSequence, rdns}) do
    Enum.reduce(rdns, %{}, fn rdn_set, acc ->
      Enum.reduce(rdn_set, acc, fn
        {:AttributeTypeAndValue, {2, 5, 4, 3}, value}, acc ->
          Map.put(acc, :cn, extract_string(value))
        {:AttributeTypeAndValue, {2, 5, 4, 10}, value}, acc ->
          Map.put(acc, :o, extract_string(value))
        _, acc -> acc
      end)
    end)
  end
  defp parse_rdn(_), do: %{}

  defp extract_string({:utf8String, s}), do: to_string(s)
  defp extract_string({:printableString, s}), do: to_string(s)
  defp extract_string(s) when is_binary(s), do: s
  defp extract_string(s) when is_list(s), do: to_string(s)
  defp extract_string(_), do: ""

  defp extract_san_uris(extensions) do
    case find_extension(extensions, {2, 5, 29, 17}) do
      nil -> []
      {:Extension, _, _, value} ->
        parse_san(value)
        |> Enum.flat_map(fn
          {:uniformResourceIdentifier, uri} -> [to_string(uri)]
          _ -> []
        end)
    end
  end

  defp extract_node_id(san_uris) do
    Enum.find_value(san_uris, fn uri ->
      case uri do
        "ztlp://node/" <> hex -> hex
        _ -> nil
      end
    end)
  end

  defp extract_assurance(extensions) do
    case find_extension(extensions, @ztlp_assurance_oid) do
      {:Extension, _, _, <<2, 1, n>>} ->
        case n do
          4 -> :hardware
          3 -> :device_bound
          2 -> :software
          _ -> :unknown
        end
      {:Extension, _, _, value} when is_binary(value) ->
        case value do
          <<_tag, _len, n>> ->
            case n do
              4 -> :hardware
              3 -> :device_bound
              2 -> :software
              _ -> :unknown
            end
          _ -> :unknown
        end
      _ -> :unknown
    end
  end

  defp extract_key_source(extensions) do
    case find_extension(extensions, @ztlp_key_source_oid) do
      {:Extension, _, _, <<12, len::8, source::binary-size(len)>>} -> source
      {:Extension, _, _, value} when is_binary(value) ->
        case value do
          <<_tag, len::8, s::binary-size(len)>> -> s
          _ -> "unknown"
        end
      _ -> "unknown"
    end
  end

  defp extract_attestation(extensions) do
    case find_extension(extensions, @ztlp_attestation_oid) do
      {:Extension, _, _, <<1, 1, 0xFF>>} -> true
      {:Extension, _, _, <<1, 1, 0x00>>} -> false
      _ -> false
    end
  end

  defp find_extension(extensions, oid) when is_list(extensions) do
    Enum.find(extensions, fn
      {:Extension, ^oid, _, _} -> true
      _ -> false
    end)
  end
  defp find_extension(_, _), do: nil

  defp parse_san(value) when is_binary(value) do
    try do
      :public_key.der_decode(:SubjectAltName, value)
    rescue
      _ -> decode_san_manual(value)
    catch
      _, _ -> decode_san_manual(value)
    end
  end
  defp parse_san(entries) when is_list(entries), do: entries
  defp parse_san(_), do: []

  defp decode_san_manual(<<0x30, _len, rest::binary>>) do
    decode_san_entries(rest, [])
  end
  defp decode_san_manual(_), do: []

  defp decode_san_entries(<<>>, acc), do: Enum.reverse(acc)
  defp decode_san_entries(<<0x86, len::8, uri::binary-size(len), rest::binary>>, acc) do
    decode_san_entries(rest, [{:uniformResourceIdentifier, uri} | acc])
  end
  defp decode_san_entries(<<0x82, len::8, name::binary-size(len), rest::binary>>, acc) do
    decode_san_entries(rest, [{:dNSName, name} | acc])
  end
  defp decode_san_entries(<<_tag, len::8, _::binary-size(len), rest::binary>>, acc) do
    decode_san_entries(rest, acc)
  end
  defp decode_san_entries(_, acc), do: Enum.reverse(acc)
end
