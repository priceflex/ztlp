defmodule ZtlpGateway.TlsTestHelper do
  @moduledoc """
  Test helper for generating TLS certificates and setting up TLS test infrastructure.

  Uses Erlang's :public_key to generate RSA keys and X.509 certificates
  for testing TLS listener, sessions, and mTLS authentication.
  """

  import Bitwise

  @rsa_sha256_oid {1, 2, 840, 113549, 1, 1, 11}
  @der_null <<5, 0>>

  @ztlp_assurance_oid {1, 3, 6, 1, 4, 1, 59999, 1}
  @ztlp_key_source_oid {1, 3, 6, 1, 4, 1, 59999, 2}
  @ztlp_attestation_oid {1, 3, 6, 1, 4, 1, 59999, 3}

  @assurance_values %{hardware: 4, device_bound: 3, software: 2, unknown: 1}

  @doc """
  Generate a full TLS PKI for testing: root CA, server cert, and optionally client cert.

  Returns a map with file paths to PEM-encoded certs/keys written to a temp directory.
  """
  def generate_test_pki(opts \\ []) do
    dir = create_temp_dir()

    # Generate CA keypair (small for speed)
    {ca_pub, ca_priv} = generate_rsa_keypair(2048)

    # Create self-signed root CA
    ca_der = create_root_ca(ca_priv, %{cn: "ZTLP Test CA", o: "ztlp-test"})
    ca_cert_pem = der_to_pem(ca_der, :certificate)
    ca_key_pem = rsa_key_to_pem(ca_priv)

    ca_cert_file = Path.join(dir, "ca.pem")
    ca_key_file = Path.join(dir, "ca-key.pem")
    File.write!(ca_cert_file, ca_cert_pem)
    File.write!(ca_key_file, ca_key_pem)

    # Generate server keypair
    hostname = Keyword.get(opts, :hostname, "localhost")
    {srv_pub, srv_priv} = generate_rsa_keypair(2048)

    # Create server certificate signed by CA
    srv_der =
      create_server_cert(ca_priv, srv_pub, %{cn: "ZTLP Test CA", o: "ztlp-test"}, hostname)

    srv_cert_pem = der_to_pem(srv_der, :certificate)
    srv_key_pem = rsa_key_to_pem(srv_priv)

    srv_cert_file = Path.join(dir, "server.pem")
    srv_key_file = Path.join(dir, "server-key.pem")
    File.write!(srv_cert_file, srv_cert_pem)
    File.write!(srv_key_file, srv_key_pem)

    result = %{
      dir: dir,
      ca_cert_file: ca_cert_file,
      ca_key_file: ca_key_file,
      ca_cert_der: ca_der,
      ca_priv: ca_priv,
      ca_pub: ca_pub,
      server_cert_file: srv_cert_file,
      server_key_file: srv_key_file,
      server_cert_der: srv_der,
      server_priv: srv_priv,
      server_pub: srv_pub,
      hostname: hostname
    }

    # Optionally generate client cert
    if Keyword.get(opts, :client_cert, false) do
      Map.merge(result, generate_client_cert(result, opts))
    else
      result
    end
  end

  @doc """
  Generate a client certificate for mTLS testing.
  """
  def generate_client_cert(pki, opts \\ []) do
    node_name = Keyword.get(opts, :node_name, "test-node.corp.ztlp")
    node_id = Keyword.get(opts, :node_id, :crypto.strong_rand_bytes(16))
    zone = Keyword.get(opts, :zone, "corp.ztlp")
    assurance = Keyword.get(opts, :assurance, :software)
    key_source = Keyword.get(opts, :key_source, "file")
    attestation = Keyword.get(opts, :attestation_verified, false)

    {client_pub, client_priv} = generate_rsa_keypair(2048)

    client_der =
      create_client_cert(
        pki.ca_priv,
        client_pub,
        %{cn: "ZTLP Test CA", o: "ztlp-test"},
        node_name,
        node_id,
        zone: zone,
        assurance: assurance,
        key_source: key_source,
        attestation_verified: attestation
      )

    client_cert_pem = der_to_pem(client_der, :certificate)
    client_key_pem = rsa_key_to_pem(client_priv)

    client_cert_file = Path.join(pki.dir, "client.pem")
    client_key_file = Path.join(pki.dir, "client-key.pem")
    File.write!(client_cert_file, client_cert_pem)
    File.write!(client_key_file, client_key_pem)

    %{
      client_cert_file: client_cert_file,
      client_key_file: client_key_file,
      client_cert_der: client_der,
      client_priv: client_priv,
      client_pub: client_pub,
      node_name: node_name,
      node_id: node_id
    }
  end

  @doc """
  Start a simple TCP echo server that echoes back received data.
  Returns {:ok, port} where port is the listening port.
  """
  def start_echo_backend(opts \\ []) do
    prefix = Keyword.get(opts, :prefix, "")
    parent = self()

    {:ok, listen_socket} =
      :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])

    {:ok, {_, port}} = :inet.sockname(listen_socket)

    pid =
      spawn_link(fn ->
        echo_accept_loop(listen_socket, prefix, parent)
      end)

    # Wait for the backend to be ready
    receive do
      :backend_ready -> :ok
    after
      1000 -> :ok
    end

    {:ok, port, pid, listen_socket}
  end

  @doc """
  Start a TCP backend that sends a fixed response to any received data.
  """
  def start_fixed_response_backend(response) do
    parent = self()

    {:ok, listen_socket} =
      :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])

    {:ok, {_, port}} = :inet.sockname(listen_socket)

    pid =
      spawn_link(fn ->
        fixed_response_accept_loop(listen_socket, response, parent)
      end)

    receive do
      :backend_ready -> :ok
    after
      1000 -> :ok
    end

    {:ok, port, pid, listen_socket}
  end

  @doc "Connect to a TLS server as a client, returning the SSL socket."
  def tls_connect(port, opts \\ []) do
    hostname = Keyword.get(opts, :hostname, ~c"localhost")
    cacertfile = Keyword.get(opts, :cacertfile)
    certfile = Keyword.get(opts, :certfile)
    keyfile = Keyword.get(opts, :keyfile)

    ssl_opts = [
      :binary,
      {:active, false},
      {:packet, :raw},
      {:verify, :verify_none},
      {:versions, [:"tlsv1.2", :"tlsv1.3"]},
      {:server_name_indication, hostname}
    ]

    ssl_opts = if cacertfile, do: [{:cacertfile, to_charlist(cacertfile)} | ssl_opts], else: ssl_opts
    ssl_opts = if certfile, do: [{:certfile, to_charlist(certfile)} | ssl_opts], else: ssl_opts
    ssl_opts = if keyfile, do: [{:keyfile, to_charlist(keyfile)} | ssl_opts], else: ssl_opts

    :ssl.connect(~c"127.0.0.1", port, ssl_opts, 5000)
  end

  @doc "Clean up temp directory."
  def cleanup_pki(pki) do
    if pki[:dir] && File.exists?(pki.dir) do
      File.rm_rf!(pki.dir)
    end
  end

  # ── Internal: Key Generation ─────────────────────────────────────

  defp generate_rsa_keypair(bits) do
    priv = :public_key.generate_key({:rsa, bits, 65537})
    {:RSAPrivateKey, _, modulus, pub_exp, _, _, _, _, _, _, _} = priv
    pub = {:RSAPublicKey, modulus, pub_exp}
    {pub, priv}
  end

  # ── Internal: Certificate Creation ──────────────────────────────

  defp create_root_ca(priv_key, subject) do
    {:RSAPrivateKey, _, modulus, pub_exp, _, _, _, _, _, _, _} = priv_key
    pub_key = {:RSAPublicKey, modulus, pub_exp}

    subject_rdn = build_rdn(subject)
    validity = build_validity(365)
    sig_alg = {:AlgorithmIdentifier, @rsa_sha256_oid, @der_null}
    pub_key_info = build_spki(pub_key)
    serial = generate_serial()

    extensions = [
      basic_constraints_ext(true),
      key_usage_ext([:keyCertSign, :cRLSign])
    ]

    tbs =
      {:TBSCertificate, :v3, serial, sig_alg, subject_rdn, validity, subject_rdn, pub_key_info,
       :asn1_NOVALUE, :asn1_NOVALUE, extensions}

    sign_and_encode(tbs, sig_alg, priv_key)
  end

  defp create_server_cert(ca_priv, srv_pub, issuer_subject, hostname) do
    issuer_rdn = build_rdn(issuer_subject)
    subject_rdn = build_rdn(%{cn: hostname})
    validity = build_validity(365)
    sig_alg = {:AlgorithmIdentifier, @rsa_sha256_oid, @der_null}
    pub_key_info = build_spki(srv_pub)
    serial = generate_serial()

    san_ext = san_dns_ext([hostname])

    extensions = [
      basic_constraints_ext(false),
      key_usage_ext([:digitalSignature, :keyEncipherment]),
      eku_ext([:serverAuth]),
      san_ext
    ]

    tbs =
      {:TBSCertificate, :v3, serial, sig_alg, issuer_rdn, validity, subject_rdn, pub_key_info,
       :asn1_NOVALUE, :asn1_NOVALUE, extensions}

    sign_and_encode(tbs, sig_alg, ca_priv)
  end

  defp create_client_cert(ca_priv, client_pub, issuer_subject, node_name, node_id, opts) do
    zone = Keyword.get(opts, :zone, "ztlp")
    assurance = Keyword.get(opts, :assurance, :software)
    key_source = Keyword.get(opts, :key_source, "file")
    attestation = Keyword.get(opts, :attestation_verified, false)

    issuer_rdn = build_rdn(issuer_subject)
    subject_rdn = build_rdn(%{cn: node_name, o: zone})
    validity = build_validity(30)
    sig_alg = {:AlgorithmIdentifier, @rsa_sha256_oid, @der_null}
    pub_key_info = build_spki(client_pub)
    serial = generate_serial()

    node_id_hex = Base.encode16(node_id, case: :lower)
    san_uri = "ztlp://node/#{node_id_hex}"

    extensions = [
      basic_constraints_ext(false),
      key_usage_ext([:digitalSignature]),
      eku_ext([:clientAuth]),
      san_uri_ext([san_uri]),
      ztlp_assurance_ext(assurance),
      ztlp_key_source_ext(key_source),
      ztlp_attestation_ext(attestation)
    ]

    tbs =
      {:TBSCertificate, :v3, serial, sig_alg, issuer_rdn, validity, subject_rdn, pub_key_info,
       :asn1_NOVALUE, :asn1_NOVALUE, extensions}

    sign_and_encode(tbs, sig_alg, ca_priv)
  end

  # ── Internal: X.509 Helpers ────────────────────────────────────

  defp build_rdn(subject) do
    entries =
      Enum.flat_map(subject, fn
        {:cn, val} -> [[{:AttributeTypeAndValue, {2, 5, 4, 3}, encode_utf8string(val)}]]
        {:o, val} -> [[{:AttributeTypeAndValue, {2, 5, 4, 10}, encode_utf8string(val)}]]
        _ -> []
      end)

    {:rdnSequence, entries}
  end

  defp encode_utf8string(s) do
    bin = :erlang.iolist_to_binary(to_string(s))
    <<12>> <> encode_asn1_length(byte_size(bin)) <> bin
  end

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

  defp build_validity(days) do
    now = :calendar.universal_time()
    not_before = format_generalized_time(now)

    not_after =
      now
      |> :calendar.datetime_to_gregorian_seconds()
      |> Kernel.+(days * 86400)
      |> :calendar.gregorian_seconds_to_datetime()
      |> format_generalized_time()

    {:Validity, {:generalTime, not_before}, {:generalTime, not_after}}
  end

  defp format_generalized_time({{y, m, d}, {h, min, s}}) do
    :io_lib.format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ", [y, m, d, h, min, s])
    |> IO.iodata_to_binary()
    |> to_charlist()
  end

  defp build_spki(pub_key) do
    pub_der = :public_key.der_encode(:RSAPublicKey, pub_key)
    algo = {:AlgorithmIdentifier, {1, 2, 840, 113549, 1, 1, 1}, @der_null}
    {:SubjectPublicKeyInfo, algo, pub_der}
  end

  defp generate_serial do
    <<n::unsigned-64>> = :crypto.strong_rand_bytes(8)
    n
  end

  defp sign_and_encode(tbs, sig_alg, priv_key) do
    tbs_der = :public_key.der_encode(:TBSCertificate, tbs)
    signature = :public_key.sign(tbs_der, :sha256, priv_key)
    cert = {:Certificate, tbs, sig_alg, signature}
    :public_key.der_encode(:Certificate, cert)
  end

  defp basic_constraints_ext(is_ca) do
    value = :public_key.der_encode(:BasicConstraints, {:BasicConstraints, is_ca, :asn1_NOVALUE})
    {:Extension, {2, 5, 29, 19}, true, value}
  end

  defp key_usage_ext(usages) do
    # Manually encode KeyUsage bitstring
    bits = Enum.reduce(usages, 0, fn
      :digitalSignature, acc -> acc ||| 0x80
      :keyEncipherment, acc -> acc ||| 0x20
      :keyCertSign, acc -> acc ||| 0x04
      :cRLSign, acc -> acc ||| 0x02
      _, acc -> acc
    end)

    # Encode as DER BIT STRING: tag 03, length, unused bits, value byte(s)
    value = <<3, 3, 0, bits::8, 0>>
    {:Extension, {2, 5, 29, 15}, true, value}
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

  defp san_dns_ext(hostnames) do
    entries =
      Enum.map(hostnames, fn h ->
        bin = :erlang.iolist_to_binary(to_string(h))
        <<0x82>> <> encode_asn1_length(byte_size(bin)) <> bin
      end)
      |> IO.iodata_to_binary()

    der = <<0x30>> <> encode_asn1_length(byte_size(entries)) <> entries
    {:Extension, {2, 5, 29, 17}, false, der}
  end

  defp san_uri_ext(uris) do
    entries =
      Enum.map(uris, fn u ->
        bin = :erlang.iolist_to_binary(to_string(u))
        <<0x86>> <> encode_asn1_length(byte_size(bin)) <> bin
      end)
      |> IO.iodata_to_binary()

    der = <<0x30>> <> encode_asn1_length(byte_size(entries)) <> entries
    {:Extension, {2, 5, 29, 17}, false, der}
  end

  defp ztlp_assurance_ext(assurance) do
    level = Map.get(@assurance_values, assurance, 1)
    value = <<2, 1, level>>
    {:Extension, @ztlp_assurance_oid, false, value}
  end

  defp ztlp_key_source_ext(source) do
    bin = to_string(source)
    value = <<12, byte_size(bin)::8>> <> bin
    {:Extension, @ztlp_key_source_oid, false, value}
  end

  defp ztlp_attestation_ext(verified) do
    flag = if verified, do: 0xFF, else: 0x00
    value = <<1, 1, flag>>
    {:Extension, @ztlp_attestation_oid, false, value}
  end

  # ── Internal: PEM Encoding ─────────────────────────────────────

  defp der_to_pem(der, :certificate) do
    b64 = Base.encode64(der)
    lines = chunk_string(b64, 64)

    "-----BEGIN CERTIFICATE-----\n" <>
      Enum.join(lines, "\n") <>
      "\n-----END CERTIFICATE-----\n"
  end

  defp rsa_key_to_pem(priv_key) do
    der = :public_key.der_encode(:RSAPrivateKey, priv_key)
    b64 = Base.encode64(der)
    lines = chunk_string(b64, 64)

    "-----BEGIN RSA PRIVATE KEY-----\n" <>
      Enum.join(lines, "\n") <>
      "\n-----END RSA PRIVATE KEY-----\n"
  end

  defp chunk_string(str, size) do
    str
    |> String.graphemes()
    |> Enum.chunk_every(size)
    |> Enum.map(&Enum.join/1)
  end

  # ── Internal: Backend Helpers ──────────────────────────────────

  defp echo_accept_loop(listen_socket, prefix, parent) do
    send(parent, :backend_ready)

    case :gen_tcp.accept(listen_socket, 10_000) do
      {:ok, socket} ->
        spawn_link(fn -> echo_recv_loop(socket, prefix) end)
        echo_accept_loop(listen_socket, prefix, parent)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        :ok
    end
  end

  defp echo_recv_loop(socket, prefix) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} ->
        :gen_tcp.send(socket, prefix <> data)
        echo_recv_loop(socket, prefix)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        :ok
    end
  end

  defp fixed_response_accept_loop(listen_socket, response, parent) do
    send(parent, :backend_ready)

    case :gen_tcp.accept(listen_socket, 10_000) do
      {:ok, socket} ->
        spawn_link(fn ->
          case :gen_tcp.recv(socket, 0, 5_000) do
            {:ok, _data} ->
              :gen_tcp.send(socket, response)
            _ ->
              :ok
          end
        end)

        fixed_response_accept_loop(listen_socket, response, parent)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        :ok
    end
  end

  # ── Internal: Temp Directory ───────────────────────────────────

  defp create_temp_dir do
    dir = Path.join(System.tmp_dir!(), "ztlp_test_#{:rand.uniform(999_999)}")
    File.mkdir_p!(dir)
    dir
  end
end
