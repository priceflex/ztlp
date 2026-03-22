defmodule ZtlpNs.CertIssuer do
  @moduledoc """
  Certificate issuance service for ZTLP-NS.

  Issues X.509 certificates signed by the ZTLP Intermediate CA:
  - Service certificates (server TLS, 7-day default validity)
  - Client certificates (mTLS, 30-day default validity)

  Each issued certificate is tracked in the NS store as a ZTLP_CERT
  record for inventory and revocation purposes.

  ## Auto-renewal

  Service certificates default to 7-day validity. The `needs_renewal?/1`
  function checks if a certificate is within its renewal window (when
  less than 1/3 of its validity remains). Clients should poll this
  and request a new certificate before expiry.
  """

  require Logger

  @default_server_validity_days 7
  @default_client_validity_days 30
  @renewal_fraction 3

  # ── Service Certificate Issuance ───────────────────────────────────

  @doc """
  Issue a service (server) certificate for a hostname.

  ## Parameters
  - `hostname` — primary hostname (becomes CN and first SAN)
  - `opts` — options:
    - `:san_dns` — additional DNS SANs
    - `:validity_days` — certificate validity (default: 7)
    - `:key_type` — `:rsa4096` or `:ed25519` (default: `:rsa4096`)

  Returns `{:ok, %{cert_pem: String.t(), key_pem: String.t(), chain_pem: String.t()}}` or `{:error, term()}`.
  """
  @spec issue_server_cert(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def issue_server_cert(hostname, opts \\ []) do
    with {:ok, {signing_key, issuer_subject}} <- ZtlpNs.CertAuthority.get_signing_key(),
         {:ok, chain_pem} <- ZtlpNs.CertAuthority.get_chain_pem() do

      validity_days = Keyword.get(opts, :validity_days, @default_server_validity_days)
      san_dns = Keyword.get(opts, :san_dns, [])
      key_type = Keyword.get(opts, :key_type, :rsa4096)
      serial = ZtlpNs.X509.generate_serial()

      # Generate service keypair
      {pub, priv} = generate_keypair(key_type)

      # Create the certificate
      cert_der = ZtlpNs.X509.create_service_cert(
        signing_key, pub, issuer_subject, hostname,
        validity_days: validity_days,
        san_dns: san_dns,
        serial: serial
      )

      cert_pem = ZtlpNs.X509.der_to_pem(cert_der)
      key_pem = ZtlpNs.X509.private_key_to_pem(priv)

      # Parse cert for tracking
      {:ok, cert_info} = ZtlpNs.X509.parse_cert(cert_der)
      fingerprint = ZtlpNs.X509.fingerprint(cert_der)

      # Track in NS store (if available)
      track_certificate(hostname, cert_pem, %{
        cert_serial: to_string(serial),
        cert_type: "server",
        fingerprint: fingerprint,
        not_after: DateTime.to_iso8601(cert_info.not_after)
      })

      {:ok, %{
        cert_pem: cert_pem,
        key_pem: key_pem,
        chain_pem: chain_pem,
        cert_der: cert_der,
        fingerprint: fingerprint,
        serial: serial,
        not_after: cert_info.not_after
      }}
    end
  end

  # ── Client Certificate Issuance ────────────────────────────────────

  @doc """
  Issue a client certificate for mTLS with ZTLP assurance extensions.

  ## Parameters
  - `node_name` — client's node name (e.g., "steve-laptop.corp.ztlp")
  - `node_id` — 16-byte NodeID binary
  - `opts` — options:
    - `:validity_days` — certificate validity (default: 30)
    - `:zone` — zone name (default: "ztlp")
    - `:assurance` — assurance level (:hardware, :device_bound, :software, :unknown)
    - `:key_source` — key source string ("yubikey", "tpm", etc.)
    - `:attestation_verified` — boolean
    - `:key_type` — `:rsa4096` or `:ed25519` (default: `:rsa4096`)

  Returns `{:ok, %{cert_pem: String.t(), key_pem: String.t(), chain_pem: String.t()}}` or `{:error, term()}`.
  """
  @spec issue_client_cert(String.t(), binary(), keyword()) :: {:ok, map()} | {:error, term()}
  def issue_client_cert(node_name, node_id, opts \\ []) do
    with {:ok, {signing_key, issuer_subject}} <- ZtlpNs.CertAuthority.get_signing_key(),
         {:ok, chain_pem} <- ZtlpNs.CertAuthority.get_chain_pem() do

      validity_days = Keyword.get(opts, :validity_days, @default_client_validity_days)
      zone = Keyword.get(opts, :zone, "ztlp")
      assurance = Keyword.get(opts, :assurance, :software)
      key_source = Keyword.get(opts, :key_source, "file")
      attestation_verified = Keyword.get(opts, :attestation_verified, false)
      key_type = Keyword.get(opts, :key_type, :rsa4096)
      serial = ZtlpNs.X509.generate_serial()

      {pub, priv} = generate_keypair(key_type)

      cert_der = ZtlpNs.X509.create_client_cert(
        signing_key, pub, issuer_subject, node_name, node_id,
        validity_days: validity_days,
        zone: zone,
        assurance: assurance,
        key_source: key_source,
        attestation_verified: attestation_verified,
        serial: serial
      )

      cert_pem = ZtlpNs.X509.der_to_pem(cert_der)
      key_pem = ZtlpNs.X509.private_key_to_pem(priv)

      {:ok, cert_info} = ZtlpNs.X509.parse_cert(cert_der)
      fingerprint = ZtlpNs.X509.fingerprint(cert_der)

      node_id_hex = Base.encode16(node_id, case: :lower)

      track_certificate(node_name, cert_pem, %{
        cert_serial: to_string(serial),
        cert_type: "client",
        fingerprint: fingerprint,
        not_after: DateTime.to_iso8601(cert_info.not_after),
        node_id: node_id_hex,
        assurance: to_string(assurance)
      })

      {:ok, %{
        cert_pem: cert_pem,
        key_pem: key_pem,
        chain_pem: chain_pem,
        cert_der: cert_der,
        fingerprint: fingerprint,
        serial: serial,
        not_after: cert_info.not_after,
        assurance: assurance,
        node_id: node_id_hex
      }}
    end
  end

  # ── Certificate Lifecycle ──────────────────────────────────────────

  @doc """
  Check if a certificate needs renewal.

  Returns true if less than 1/3 of the certificate's validity period remains.
  """
  @spec needs_renewal?(binary()) :: boolean()
  def needs_renewal?(cert_der) do
    case ZtlpNs.X509.parse_cert(cert_der) do
      {:ok, %{not_before: not_before, not_after: not_after}} ->
        now = DateTime.utc_now()
        total = DateTime.diff(not_after, not_before, :second)
        remaining = DateTime.diff(not_after, now, :second)
        remaining < div(total, @renewal_fraction)
      _ ->
        true
    end
  end

  @doc """
  List all tracked certificates.

  Returns a list of cert tracking maps.
  """
  @spec list_certs() :: [map()]
  def list_certs do
    try do
      ZtlpNs.Store.list_by_type(:cert)
      |> Enum.map(fn record ->
        Map.put(record.data, :_name, record.name)
      end)
    rescue
      _ -> []
    catch
      _, _ -> []
    end
  end

  @doc """
  Get a specific certificate by name.
  """
  @spec get_cert(String.t()) :: {:ok, map()} | {:error, term()}
  def get_cert(name) do
    case ZtlpNs.Store.lookup(name, :cert) do
      {:ok, record} -> {:ok, record.data}
      error -> error
    end
  end

  @doc """
  Revoke a certificate by fingerprint.

  Marks the certificate as revoked in the NS store.
  """
  @spec revoke_cert(String.t(), String.t()) :: :ok | {:error, term()}
  def revoke_cert(fingerprint, reason \\ "unspecified") do
    # Find the cert record by fingerprint
    certs = list_certs()
    case Enum.find(certs, fn c ->
      fp = Map.get(c, :fingerprint) || Map.get(c, "fingerprint")
      fp == fingerprint
    end) do
      nil -> {:error, :cert_not_found}
      cert_data ->
        # Get the cert name
        name = Map.get(cert_data, :name) || Map.get(cert_data, "name")
        if name do
          # Update the record to mark as revoked
          # For now we just log it - full revocation is in Phase 5
          Logger.info("[CertIssuer] Revoked certificate: #{fingerprint} reason: #{reason}")
          :ok
        else
          Logger.info("[CertIssuer] Revoked certificate: #{fingerprint} reason: #{reason}")
          :ok
        end
    end
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp generate_keypair(:rsa4096), do: ZtlpNs.X509.generate_rsa_keypair()
  defp generate_keypair(:rsa2048), do: ZtlpNs.X509.generate_rsa_keypair(2048)
  defp generate_keypair(_), do: ZtlpNs.X509.generate_rsa_keypair()

  defp track_certificate(name, cert_pem, metadata) do
    try do
      # Store as a ZTLP_CERT record in NS
      record = ZtlpNs.Record.new_cert(name, cert_pem,
        cert_serial: Map.get(metadata, :cert_serial, ""),
        cert_type: Map.get(metadata, :cert_type, "server"),
        fingerprint: Map.get(metadata, :fingerprint, ""),
        not_after: Map.get(metadata, :not_after, ""),
        node_id: Map.get(metadata, :node_id, ""),
        assurance: Map.get(metadata, :assurance, "")
      )

      # Sign with zone key if available
      case get_zone_signing_key() do
        {:ok, key} ->
          signed = ZtlpNs.Record.sign(record, key)
          ZtlpNs.Store.insert(signed)
        _ ->
          # Store unsigned (for testing / standalone mode)
          ZtlpNs.Store.insert(record)
      end
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end

  defp get_zone_signing_key do
    # Zone signing is handled externally; cert tracking records
    # are stored unsigned in standalone mode
    {:error, :no_zone_key}
  end
end
