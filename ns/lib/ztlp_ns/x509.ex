defmodule ZtlpNs.X509 do
  @moduledoc """
  X.509 certificate builder using Erlang's `:public_key` module.

  Provides functions to create self-signed root CA certificates,
  intermediate CA certificates, service certificates (server), and
  client certificates (for mTLS). All certificate generation uses
  RSA or Ed25519 keys (via Erlang `:public_key`) with no external deps.

  ## OIDs for ZTLP Extensions

  ZTLP uses private OIDs under the arc 1.3.6.1.4.1.59999:
  - `.1` — Assurance level (integer: 4=hardware, 3=device-bound, 2=software, 1=unknown)
  - `.2` — Key source (UTF8String)
  - `.3` — Attestation verified (boolean)
  """

  import Bitwise

  # ZTLP private enterprise number OID arc
  @ztlp_oid_base {1, 3, 6, 1, 4, 1, 59999}
  @ztlp_assurance_oid {1, 3, 6, 1, 4, 1, 59999, 1}
  @ztlp_key_source_oid {1, 3, 6, 1, 4, 1, 59999, 2}
  @ztlp_attestation_oid {1, 3, 6, 1, 4, 1, 59999, 3}

  @assurance_levels %{hardware: 4, device_bound: 3, software: 2, unknown: 1}
  @assurance_values %{4 => :hardware, 3 => :device_bound, 2 => :software, 1 => :unknown}

  # RSA SHA-256 with RSA
  @rsa_sha256_oid {1, 2, 840, 113549, 1, 1, 11}
  @rsa_oid {1, 2, 840, 113549, 1, 1, 1}
  # DER-encoded NULL
  @der_null <<5, 0>>

  # Accessor functions for OIDs
  def ztlp_oid_base, do: @ztlp_oid_base
  def ztlp_assurance_oid, do: @ztlp_assurance_oid
  def ztlp_key_source_oid, do: @ztlp_key_source_oid
  def ztlp_attestation_oid, do: @ztlp_attestation_oid

  def assurance_to_int(level), do: Map.fetch!(@assurance_levels, level)
  def int_to_assurance(n), do: Map.get(@assurance_values, n, :unknown)

  # ── Key Generation ─────────────────────────────────────────────────

  @doc "Generate an RSA-4096 keypair."
  @spec generate_rsa_keypair() :: {tuple(), tuple()}
  def generate_rsa_keypair do
    private_key = :public_key.generate_key({:rsa, 4096, 65537})
    {:RSAPrivateKey, _, modulus, public_exponent, _, _, _, _, _, _, _} = private_key
    public_key = {:RSAPublicKey, modulus, public_exponent}
    {public_key, private_key}
  end

  @doc "Generate a smaller RSA keypair (for tests)."
  @spec generate_rsa_keypair(non_neg_integer()) :: {tuple(), tuple()}
  def generate_rsa_keypair(bits) do
    private_key = :public_key.generate_key({:rsa, bits, 65537})
    {:RSAPrivateKey, _, modulus, public_exponent, _, _, _, _, _, _, _} = private_key
    public_key = {:RSAPublicKey, modulus, public_exponent}
    {public_key, private_key}
  end

  # ── Certificate Creation ───────────────────────────────────────────

  @doc """
  Create a self-signed Root CA certificate.
  Returns DER-encoded certificate binary.
  """
  @spec create_root_ca(term(), map(), keyword()) :: binary()
  def create_root_ca(private_key, subject, opts \\ []) do
    validity_years = Keyword.get(opts, :validity_years, 10)
    serial = Keyword.get(opts, :serial, generate_serial())

    {:RSAPrivateKey, _, modulus, public_exponent, _, _, _, _, _, _, _} = private_key
    public_key = {:RSAPublicKey, modulus, public_exponent}

    subject_rdn = build_rdn(subject)
    validity = build_validity(validity_years * 365)
    sig_alg = {:AlgorithmIdentifier, @rsa_sha256_oid, @der_null}
    pub_key_info = build_spki(public_key)

    extensions = [
      basic_constraints_ext(true, :asn1_NOVALUE, true),
      key_usage_ext([:keyCertSign, :cRLSign]),
      ski_ext(public_key)
    ]

    tbs = {:TBSCertificate, :v3, serial, sig_alg, subject_rdn,
           validity, subject_rdn, pub_key_info,
           :asn1_NOVALUE, :asn1_NOVALUE, extensions}

    sign_and_encode(tbs, sig_alg, private_key)
  end

  @doc """
  Create an Intermediate CA certificate signed by the root CA.
  Returns DER-encoded certificate binary.
  """
  @spec create_intermediate_ca(term(), term(), map(), map(), keyword()) :: binary()
  def create_intermediate_ca(issuer_private_key, subject_public_key, issuer_subject, subject, opts \\ []) do
    validity_years = Keyword.get(opts, :validity_years, 3)
    serial = Keyword.get(opts, :serial, generate_serial())

    {:RSAPrivateKey, _, mod, pub_exp, _, _, _, _, _, _, _} = issuer_private_key
    issuer_pub = {:RSAPublicKey, mod, pub_exp}

    issuer_rdn = build_rdn(issuer_subject)
    subject_rdn = build_rdn(subject)
    validity = build_validity(validity_years * 365)
    sig_alg = {:AlgorithmIdentifier, @rsa_sha256_oid, @der_null}
    pub_key_info = build_spki(subject_public_key)

    extensions = [
      basic_constraints_ext(true, 0, true),
      key_usage_ext([:keyCertSign, :cRLSign]),
      ski_ext(subject_public_key),
      aki_ext(issuer_pub)
    ]

    tbs = {:TBSCertificate, :v3, serial, sig_alg, issuer_rdn,
           validity, subject_rdn, pub_key_info,
           :asn1_NOVALUE, :asn1_NOVALUE, extensions}

    sign_and_encode(tbs, sig_alg, issuer_private_key)
  end

  @doc """
  Create a service (server) certificate signed by the intermediate CA.
  Returns DER-encoded certificate binary.
  """
  @spec create_service_cert(term(), term(), map(), String.t(), keyword()) :: binary()
  def create_service_cert(issuer_private_key, subject_public_key, issuer_subject, hostname, opts \\ []) do
    validity_days = Keyword.get(opts, :validity_days, 7)
    san_dns = Keyword.get(opts, :san_dns, [])
    serial = Keyword.get(opts, :serial, generate_serial())

    {:RSAPrivateKey, _, mod, pub_exp, _, _, _, _, _, _, _} = issuer_private_key
    issuer_pub = {:RSAPublicKey, mod, pub_exp}

    issuer_rdn = build_rdn(issuer_subject)
    subject_rdn = build_rdn(%{cn: hostname})
    validity = build_validity(validity_days)
    sig_alg = {:AlgorithmIdentifier, @rsa_sha256_oid, @der_null}
    pub_key_info = build_spki(subject_public_key)

    all_dns = Enum.uniq([hostname | san_dns])

    extensions = [
      basic_constraints_ext(false, :asn1_NOVALUE, false),
      key_usage_ext([:digitalSignature, :keyEncipherment]),
      eku_ext([:serverAuth]),
      san_dns_ext(all_dns),
      ski_ext(subject_public_key),
      aki_ext(issuer_pub)
    ]

    tbs = {:TBSCertificate, :v3, serial, sig_alg, issuer_rdn,
           validity, subject_rdn, pub_key_info,
           :asn1_NOVALUE, :asn1_NOVALUE, extensions}

    sign_and_encode(tbs, sig_alg, issuer_private_key)
  end

  @doc """
  Create a client certificate for mTLS, with ZTLP assurance extensions.
  Returns DER-encoded certificate binary.
  """
  @spec create_client_cert(term(), term(), map(), String.t(), binary(), keyword()) :: binary()
  def create_client_cert(issuer_private_key, subject_public_key, issuer_subject, node_name, node_id, opts \\ []) do
    validity_days = Keyword.get(opts, :validity_days, 30)
    zone = Keyword.get(opts, :zone, "ztlp")
    assurance = Keyword.get(opts, :assurance, :software)
    key_source = Keyword.get(opts, :key_source, "file")
    attestation_verified = Keyword.get(opts, :attestation_verified, false)
    serial = Keyword.get(opts, :serial, generate_serial())

    {:RSAPrivateKey, _, mod, pub_exp, _, _, _, _, _, _, _} = issuer_private_key
    issuer_pub = {:RSAPublicKey, mod, pub_exp}

    issuer_rdn = build_rdn(issuer_subject)
    subject_rdn = build_rdn(%{cn: node_name, o: zone})
    validity = build_validity(validity_days)
    sig_alg = {:AlgorithmIdentifier, @rsa_sha256_oid, @der_null}
    pub_key_info = build_spki(subject_public_key)

    node_id_hex = Base.encode16(node_id, case: :lower)
    san_uri = "ztlp://node/#{node_id_hex}"

    extensions = [
      basic_constraints_ext(false, :asn1_NOVALUE, false),
      key_usage_ext([:digitalSignature]),
      eku_ext([:clientAuth]),
      san_uri_ext([san_uri]),
      ski_ext(subject_public_key),
      aki_ext(issuer_pub),
      ztlp_assurance_ext(assurance),
      ztlp_key_source_ext(key_source),
      ztlp_attestation_ext(attestation_verified)
    ]

    tbs = {:TBSCertificate, :v3, serial, sig_alg, issuer_rdn,
           validity, subject_rdn, pub_key_info,
           :asn1_NOVALUE, :asn1_NOVALUE, extensions}

    sign_and_encode(tbs, sig_alg, issuer_private_key)
  end

  # ── Certificate Parsing ────────────────────────────────────────────

  @doc """
  Parse a DER-encoded certificate and return a map of key fields.
  """
  @spec parse_cert(binary()) :: {:ok, map()} | {:error, term()}
  def parse_cert(der) when is_binary(der) do
    try do
      otp_cert = :public_key.pkix_decode_cert(der, :otp)
      {:OTPCertificate, tbs, _sig_alg, _sig} = otp_cert
      {:OTPTBSCertificate, _ver, serial, _sig_alg2, issuer, validity, subject,
       _pub_key_info, _issuer_uid, _subject_uid, extensions} = tbs

      {:ok, %{
        serial: serial,
        subject: parse_rdn(subject),
        issuer: parse_rdn(issuer),
        not_before: parse_validity_time(elem(validity, 1)),
        not_after: parse_validity_time(elem(validity, 2)),
        san_dns: extract_san_dns(extensions),
        san_uri: extract_san_uri(extensions),
        is_ca: extract_is_ca(extensions),
        assurance: extract_ztlp_assurance(extensions),
        extensions: extensions
      }}
    rescue
      e -> {:error, {:parse_failed, e}}
    catch
      kind, value -> {:error, {kind, value}}
    end
  end

  @doc "Encode a DER certificate to PEM format."
  @spec der_to_pem(binary()) :: String.t()
  def der_to_pem(der) do
    b64 = Base.encode64(der)
    lines = chunk_string(b64, 64)
    "-----BEGIN CERTIFICATE-----\n" <>
    Enum.join(lines, "\n") <>
    "\n-----END CERTIFICATE-----\n"
  end

  @doc "Decode a PEM-encoded certificate to DER."
  @spec pem_to_der(String.t()) :: {:ok, binary()} | {:error, term()}
  def pem_to_der(pem) do
    case :public_key.pem_decode(pem) do
      [{:Certificate, der, :not_encrypted}] -> {:ok, der}
      [_ | _] = entries ->
        case Enum.find(entries, fn {type, _, _} -> type == :Certificate end) do
          {:Certificate, der, :not_encrypted} -> {:ok, der}
          nil -> {:error, :no_certificate_found}
        end
      [] -> {:error, :empty_pem}
    end
  end

  @doc "Encode a private key to PEM format."
  @spec private_key_to_pem(term()) :: String.t()
  def private_key_to_pem(key) do
    entry = :public_key.pem_entry_encode(:RSAPrivateKey, key)
    :public_key.pem_encode([entry])
  end

  @doc "Decode a PEM-encoded private key."
  @spec pem_to_private_key(String.t()) :: {:ok, term()} | {:error, term()}
  def pem_to_private_key(pem) do
    case :public_key.pem_decode(pem) do
      [{type, der, :not_encrypted}] ->
        {:ok, :public_key.pem_entry_decode({type, der, :not_encrypted})}
      [] -> {:error, :empty_pem}
      _ -> {:error, :unsupported_key_format}
    end
  end

  @doc "Verify a certificate was signed by the given CA certificate."
  @spec verify_cert(binary(), binary()) :: boolean()
  def verify_cert(cert_der, ca_cert_der) do
    try do
      ca_otp = :public_key.pkix_decode_cert(ca_cert_der, :otp)
      {:OTPCertificate, ca_tbs, _, _} = ca_otp
      {:OTPTBSCertificate, _, _, _, _, _, _, ca_pub_info, _, _, _} = ca_tbs
      {:OTPSubjectPublicKeyInfo, _, ca_pub_key} = ca_pub_info

      # Get the TBS DER and signature from the cert
      cert_record = :public_key.pkix_decode_cert(cert_der, :plain)
      {:Certificate, tbs_cert, alg_record, sig_bits} = cert_record
      tbs_der = :public_key.der_encode(:TBSCertificate, tbs_cert)
      {:AlgorithmIdentifier, alg_oid, _params} = alg_record

      :public_key.verify(tbs_der, digest_for_oid(alg_oid), sig_bits, ca_pub_key)
    rescue
      _ -> false
    catch
      _, _ -> false
    end
  end

  @doc "Get the fingerprint (SHA-256) of a DER-encoded certificate."
  @spec fingerprint(binary()) :: String.t()
  def fingerprint(der) do
    :crypto.hash(:sha256, der) |> Base.encode16(case: :lower)
  end

  @doc "Generate a random serial number (positive, up to 16 bytes)."
  @spec generate_serial() :: non_neg_integer()
  def generate_serial do
    :crypto.strong_rand_bytes(16)
    |> :binary.decode_unsigned()
    |> band(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    |> max(1)
  end

  @doc "Extract ZTLP assurance information from certificate extensions."
  @spec extract_ztlp_assurance(list() | nil) :: map() | nil
  def extract_ztlp_assurance(extensions) when is_list(extensions) do
    assurance_ext = find_extension(extensions, @ztlp_assurance_oid)
    key_source_ext = find_extension(extensions, @ztlp_key_source_oid)
    attestation_ext = find_extension(extensions, @ztlp_attestation_oid)

    if assurance_ext do
      level = decode_assurance_value(assurance_ext)
      key_source = decode_key_source_value(key_source_ext)
      attestation = decode_attestation_value(attestation_ext)

      %{level: level, key_source: key_source, attestation_verified: attestation}
    else
      nil
    end
  end
  def extract_ztlp_assurance(_), do: nil

  # ── Internal: Signing ──────────────────────────────────────────────

  defp sign_and_encode(tbs, sig_alg, private_key) do
    tbs_der = :public_key.der_encode(:TBSCertificate, tbs)
    signature = :public_key.sign(tbs_der, :sha256, private_key)
    cert = {:Certificate, tbs, sig_alg, signature}
    :public_key.der_encode(:Certificate, cert)
  end

  # ── Internal: RDN Building ─────────────────────────────────────────

  defp build_rdn(attrs) do
    rdns = []
    rdns = if Map.has_key?(attrs, :cn), do: rdns ++ [[attr_tv({2,5,4,3}, attrs.cn)]], else: rdns
    rdns = if Map.has_key?(attrs, :o), do: rdns ++ [[attr_tv({2,5,4,10}, attrs.o)]], else: rdns
    rdns = if Map.has_key?(attrs, :ou), do: rdns ++ [[attr_tv({2,5,4,11}, attrs.ou)]], else: rdns
    rdns = if Map.has_key?(attrs, :c), do: rdns ++ [[attr_tv({2,5,4,6}, attrs.c)]], else: rdns
    {:rdnSequence, rdns}
  end

  defp attr_tv(oid, value) do
    # Value must be DER-encoded for TBSCertificate
    value_bin = to_string(value)
    value_der = encode_utf8string(value_bin)
    {:AttributeTypeAndValue, oid, value_der}
  end

  defp encode_utf8string(s) do
    bin = :erlang.iolist_to_binary(s)
    <<12>> <> encode_asn1_length(byte_size(bin)) <> bin
  end

  defp parse_rdn({:rdnSequence, rdns}) do
    Enum.reduce(rdns, %{}, fn rdn_set, acc ->
      Enum.reduce(rdn_set, acc, fn
        {:AttributeTypeAndValue, {2, 5, 4, 3}, value}, acc -> Map.put(acc, :cn, extract_string(value))
        {:AttributeTypeAndValue, {2, 5, 4, 10}, value}, acc -> Map.put(acc, :o, extract_string(value))
        {:AttributeTypeAndValue, {2, 5, 4, 11}, value}, acc -> Map.put(acc, :ou, extract_string(value))
        {:AttributeTypeAndValue, {2, 5, 4, 6}, value}, acc -> Map.put(acc, :c, extract_string(value))
        _, acc -> acc
      end)
    end)
  end

  defp extract_string({:utf8String, s}), do: to_string(s)
  defp extract_string({:printableString, s}), do: to_string(s)
  defp extract_string({:ia5String, s}), do: to_string(s)
  defp extract_string(s) when is_binary(s), do: s
  defp extract_string(s) when is_list(s), do: to_string(s)
  defp extract_string(_), do: ""

  # ── Internal: SubjectPublicKeyInfo ─────────────────────────────────

  defp build_spki({:RSAPublicKey, _, _} = pub) do
    pub_der = :public_key.der_encode(:RSAPublicKey, pub)
    alg = {:AlgorithmIdentifier, @rsa_oid, @der_null}
    {:SubjectPublicKeyInfo, alg, pub_der}
  end

  # ── Internal: Validity ─────────────────────────────────────────────

  defp build_validity(days) do
    now = :calendar.universal_time()
    not_before = format_generalized_time(now)
    not_after = format_generalized_time(add_days(now, days))
    {:Validity, {:generalTime, not_before}, {:generalTime, not_after}}
  end

  defp format_generalized_time({{year, month, day}, {hour, min, sec}}) do
    :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
      [year, month, day, hour, min, sec])
    |> to_string()
    |> to_charlist()
  end

  defp add_days({{year, month, day}, time}, days) do
    greg_days = :calendar.date_to_gregorian_days(year, month, day) + days
    {:calendar.gregorian_days_to_date(greg_days), time}
  end

  defp parse_validity_time({:utcTime, time}) do
    time_str = to_string(time)
    <<yy::binary-2, mm::binary-2, dd::binary-2, hh::binary-2, min::binary-2, ss::binary-2, _::binary>> = time_str
    year = String.to_integer(yy)
    year = if year >= 50, do: 1900 + year, else: 2000 + year
    {:ok, dt} = NaiveDateTime.new(year, String.to_integer(mm), String.to_integer(dd),
      String.to_integer(hh), String.to_integer(min), String.to_integer(ss))
    DateTime.from_naive!(dt, "Etc/UTC")
  end

  defp parse_validity_time({:generalTime, time}) do
    time_str = to_string(time)
    <<yyyy::binary-4, mm::binary-2, dd::binary-2, hh::binary-2, min::binary-2, ss::binary-2, _::binary>> = time_str
    {:ok, dt} = NaiveDateTime.new(String.to_integer(yyyy), String.to_integer(mm),
      String.to_integer(dd), String.to_integer(hh), String.to_integer(min), String.to_integer(ss))
    DateTime.from_naive!(dt, "Etc/UTC")
  end

  # ── Internal: Extension Building ───────────────────────────────────

  defp basic_constraints_ext(is_ca, path_len, critical) do
    der = :public_key.der_encode(:BasicConstraints, {:BasicConstraints, is_ca, path_len})
    {:Extension, {2, 5, 29, 19}, critical, der}
  end

  defp key_usage_ext(usages) do
    bits = Enum.reduce(usages, 0, fn
      :digitalSignature, acc -> acc ||| 0x80
      :keyEncipherment, acc -> acc ||| 0x20
      :keyCertSign, acc -> acc ||| 0x04
      :cRLSign, acc -> acc ||| 0x02
      _, acc -> acc
    end)
    unused = count_trailing_zeros(bits)
    der = <<3, 2, unused, bits>>
    {:Extension, {2, 5, 29, 15}, true, der}
  end

  defp count_trailing_zeros(0), do: 7
  defp count_trailing_zeros(n) do
    Enum.find(0..7, fn i -> (n >>> i &&& 1) == 1 end)
  end

  defp eku_ext(usages) do
    oid_map = %{
      serverAuth: {1, 3, 6, 1, 5, 5, 7, 3, 1},
      clientAuth: {1, 3, 6, 1, 5, 5, 7, 3, 2}
    }
    oids = Enum.map(usages, &Map.fetch!(oid_map, &1))
    encoded_oids = Enum.map(oids, &encode_oid/1) |> IO.iodata_to_binary()
    der = <<0x30>> <> encode_asn1_length(byte_size(encoded_oids)) <> encoded_oids
    {:Extension, {2, 5, 29, 37}, false, der}
  end

  defp san_dns_ext(dns_names) do
    entries = Enum.map(dns_names, fn name ->
      bin = :erlang.iolist_to_binary(name)
      <<0x82>> <> encode_asn1_length(byte_size(bin)) <> bin
    end) |> IO.iodata_to_binary()
    der = <<0x30>> <> encode_asn1_length(byte_size(entries)) <> entries
    {:Extension, {2, 5, 29, 17}, false, der}
  end

  defp san_uri_ext(uris) do
    entries = Enum.map(uris, fn uri ->
      bin = :erlang.iolist_to_binary(uri)
      <<0x86>> <> encode_asn1_length(byte_size(bin)) <> bin
    end) |> IO.iodata_to_binary()
    der = <<0x30>> <> encode_asn1_length(byte_size(entries)) <> entries
    {:Extension, {2, 5, 29, 17}, false, der}
  end

  defp ski_ext(public_key) do
    key_bytes = extract_public_key_bytes(public_key)
    hash = :crypto.hash(:sha, key_bytes)
    der = <<4>> <> encode_asn1_length(byte_size(hash)) <> hash
    {:Extension, {2, 5, 29, 14}, false, der}
  end

  defp aki_ext(issuer_public_key) do
    key_bytes = extract_public_key_bytes(issuer_public_key)
    hash = :crypto.hash(:sha, key_bytes)
    inner = <<0x80>> <> encode_asn1_length(byte_size(hash)) <> hash
    der = <<0x30>> <> encode_asn1_length(byte_size(inner)) <> inner
    {:Extension, {2, 5, 29, 35}, false, der}
  end

  defp ztlp_assurance_ext(assurance) do
    level = Map.get(@assurance_levels, assurance, 1)
    der = <<2, 1, level>>
    {:Extension, @ztlp_assurance_oid, false, der}
  end

  defp ztlp_key_source_ext(source) do
    bin = to_string(source)
    der = <<12>> <> encode_asn1_length(byte_size(bin)) <> bin
    {:Extension, @ztlp_key_source_oid, false, der}
  end

  defp ztlp_attestation_ext(true), do: {:Extension, @ztlp_attestation_oid, false, <<1, 1, 0xFF>>}
  defp ztlp_attestation_ext(false), do: {:Extension, @ztlp_attestation_oid, false, <<1, 1, 0x00>>}

  defp extract_public_key_bytes({:RSAPublicKey, _, _} = pub) do
    :public_key.der_encode(:RSAPublicKey, pub)
  end

  # ── Internal: Extension Extraction ─────────────────────────────────

  defp extract_san_dns(extensions) when is_list(extensions) do
    case find_extension(extensions, {2, 5, 29, 17}) do
      nil -> []
      {:Extension, _, _, value} ->
        parse_san_entries(value)
        |> Enum.flat_map(fn
          {:dNSName, name} -> [to_string(name)]
          _ -> []
        end)
    end
  end
  defp extract_san_dns(_), do: []

  defp extract_san_uri(extensions) when is_list(extensions) do
    case find_extension(extensions, {2, 5, 29, 17}) do
      nil -> []
      {:Extension, _, _, value} ->
        parse_san_entries(value)
        |> Enum.flat_map(fn
          {:uniformResourceIdentifier, uri} -> [to_string(uri)]
          _ -> []
        end)
    end
  end
  defp extract_san_uri(_), do: []

  defp extract_is_ca(extensions) when is_list(extensions) do
    case find_extension(extensions, {2, 5, 29, 19}) do
      nil -> false
      {:Extension, _, _, value} ->
        case value do
          {:BasicConstraints, ca, _} -> ca == true
          _ when is_binary(value) ->
            case :public_key.der_decode(:BasicConstraints, value) do
              {:BasicConstraints, true, _} -> true
              _ -> false
            end
          _ -> false
        end
    end
  end
  defp extract_is_ca(_), do: false

  defp decode_assurance_value({:Extension, _, _, <<2, 1, n>>}), do: int_to_assurance(n)
  defp decode_assurance_value({:Extension, _, _, value}) when is_binary(value) do
    case value do
      <<_tag, _len, n>> -> int_to_assurance(n)
      _ -> :unknown
    end
  end
  defp decode_assurance_value(_), do: :unknown

  defp decode_key_source_value(nil), do: "unknown"
  defp decode_key_source_value({:Extension, _, _, <<12, len::8, source::binary-size(len)>>}), do: source
  defp decode_key_source_value({:Extension, _, _, value}) when is_binary(value) do
    case value do
      <<_tag, len::8, s::binary-size(len)>> -> s
      _ -> "unknown"
    end
  end
  defp decode_key_source_value(_), do: "unknown"

  defp decode_attestation_value(nil), do: false
  defp decode_attestation_value({:Extension, _, _, <<1, 1, 0xFF>>}), do: true
  defp decode_attestation_value({:Extension, _, _, <<1, 1, 0x00>>}), do: false
  defp decode_attestation_value(_), do: false

  defp find_extension(extensions, target_oid) do
    Enum.find(extensions, fn
      {:Extension, oid, _, _} -> oid == target_oid
      _ -> false
    end)
  end

  defp parse_san_entries(value) when is_binary(value) do
    try do
      :public_key.der_decode(:SubjectAltName, value)
    rescue
      _ -> decode_san_manual(value)
    catch
      _, _ -> decode_san_manual(value)
    end
  end
  defp parse_san_entries(entries) when is_list(entries), do: entries
  defp parse_san_entries(_), do: []

  defp decode_san_manual(<<0x30, rest::binary>>) do
    {_len, entries_bin} = decode_length(rest)
    decode_san_sequence(entries_bin, [])
  end
  defp decode_san_manual(_), do: []

  defp decode_san_sequence(<<>>, acc), do: Enum.reverse(acc)
  defp decode_san_sequence(<<0x82, rest::binary>>, acc) do
    {len, rest2} = decode_length(rest)
    <<name::binary-size(len), rest3::binary>> = rest2
    decode_san_sequence(rest3, [{:dNSName, name} | acc])
  end
  defp decode_san_sequence(<<0x86, rest::binary>>, acc) do
    {len, rest2} = decode_length(rest)
    <<uri::binary-size(len), rest3::binary>> = rest2
    decode_san_sequence(rest3, [{:uniformResourceIdentifier, uri} | acc])
  end
  defp decode_san_sequence(<<_tag, rest::binary>>, acc) do
    {len, rest2} = decode_length(rest)
    <<_::binary-size(len), rest3::binary>> = rest2
    decode_san_sequence(rest3, acc)
  end
  defp decode_san_sequence(_, acc), do: Enum.reverse(acc)

  defp decode_length(<<len::8, rest::binary>>) when len < 128, do: {len, rest}
  defp decode_length(<<0x81, len::8, rest::binary>>), do: {len, rest}
  defp decode_length(<<0x82, len::16, rest::binary>>), do: {len, rest}
  defp decode_length(rest), do: {0, rest}

  # ── Internal: ASN.1 Encoding Helpers ───────────────────────────────

  defp encode_asn1_length(len) when len < 128, do: <<len>>
  defp encode_asn1_length(len) when len < 256, do: <<0x81, len>>
  defp encode_asn1_length(len), do: <<0x82, len::16>>

  defp encode_oid(oid_tuple) do
    [first, second | rest] = Tuple.to_list(oid_tuple)
    first_byte = 40 * first + second
    rest_bytes = Enum.map(rest, &encode_oid_component/1) |> IO.iodata_to_binary()
    content = <<first_byte>> <> rest_bytes
    <<6>> <> encode_asn1_length(byte_size(content)) <> content
  end

  defp encode_oid_component(n) when n < 128, do: <<n>>
  defp encode_oid_component(n), do: encode_oid_vlq(n, [])

  defp encode_oid_vlq(0, [last | rest]) do
    :erlang.list_to_binary(Enum.reverse([last | Enum.map(rest, fn b -> b ||| 0x80 end)]))
  end
  defp encode_oid_vlq(n, acc), do: encode_oid_vlq(div(n, 128), [rem(n, 128) | acc])

  defp chunk_string(string, size) do
    string
    |> String.graphemes()
    |> Enum.chunk_every(size)
    |> Enum.map(&Enum.join/1)
  end

  defp digest_for_oid({1, 2, 840, 113549, 1, 1, 11}), do: :sha256
  defp digest_for_oid(_), do: :sha256
end
