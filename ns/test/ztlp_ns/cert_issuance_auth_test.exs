defmodule ZtlpNs.CertIssuanceAuthTest do
  @moduledoc """
  Regression tests for the CA certificate-issuance authorization path (opcode
  `0x14 0x03`).

  Regression pin for the SAST CRITICAL finding
  "Unauthenticated certificate issuance exposes private keys"
  (report wle-gdez-wfc, `ztlp/ns/lib/ztlp_ns/server.ex`).

  Historical vulnerability: the `0x14 0x03` handler took an attacker-supplied
  hostname straight to `CertIssuer.issue_server_cert/2` with ZERO auth — a
  single UDP packet with an arbitrary hostname returned a valid CA-signed
  cert + private key. Fixed by `[SAST: oql-hvmv]` so issuance now requires a
  request signed by an Ed25519 key present on the component-auth allowlist
  (`ComponentAuth.allowed_keys/0`); unsigned/legacy requests are rejected
  outright, and if component auth is not configured, issuance is refused
  (fail closed).

  These tests drive the opcode through the real NS Server GenServer over UDP
  (dispatch -> process_query -> verify_cert_issuance_auth), using the
  already-running NS Server + the already-initialized test CA (same pattern as
  `admin_test.exs` for the 0x13 admin-path removal regression). They pin:
    1. unauthenticated (unsigned) request   -> rejected (0x03)
    2. malformed / mismatched signature      -> rejected (0x03)
    3. valid signature but unauthorized key  -> rejected (0x03)
    4. valid signature + authorized key      -> issued (0x00, cert + key)
    5. component auth not configured         -> refused (0x03)

  RESIDUAL TRUST BOUNDARY (documented per triage): the allowlist authenticates
  the requesting COMPONENT and binds its signature to the hostname, but it does
  NOT independently establish hostname ownership — `ComponentAuth.allowed_keys/0`
  is a flat list of pubkeys with no per-hostname binding. So any allowlisted
  component may request a cert for ANY hostname. This is secure only if every
  allowlisted component is trusted to request certs for any permitted hostname.
  If components should be restricted to specific names/namespaces, add an
  `allowed_component_key -> permitted hostname patterns` authorization check
  before calling `issue_server_cert/2`. (Recommended follow-up for 0.36.0 —
  a config/protocol schema change, out of scope for the 0.35.4 patch.)
  """
  use ExUnit.Case, async: false

  alias ZtlpNs.Server

  # The NS app (Server + CertAuthority) is auto-started by the supervisor.
  # Use the same clean stop/restart-via-Application pattern as admin_test.exs
  # so the happy-path test has a live CA (and the other tests a live Server).
  setup do
    # Fresh CA dir + clean app restart (stops the supervisor-managed children
    # cleanly instead of fighting the supervisor).
    test_dir = Path.join(System.tmp_dir!(), "ztlp_ca_certiss_#{:rand.uniform(1_000_000)}")
    File.mkdir_p!(test_dir)

    prev_enabled = Application.get_env(:ztlp_ns, :component_auth_enabled)
    prev_keys = Application.get_env(:ztlp_ns, :component_auth_allowed_keys)

    Application.stop(:ztlp_ns)
    Application.put_env(:ztlp_ns, :ca_dir, test_dir)
    Application.put_env(:ztlp_ns, :component_auth_enabled, true)
    Application.put_env(:ztlp_ns, :component_auth_allowed_keys, [])
    Application.ensure_all_started(:ztlp_ns)
    Process.sleep(50)

    # Initialize the CA (idempotent).
    case ZtlpNs.CertAuthority.init_ca(passphrase: "certiss-auth-test-pass") do
      {:ok, _} -> :ok
      {:error, :already_initialized} -> :ok
      other -> flunk("CA init failed: #{inspect(other)}")
    end

    port = ZtlpNs.Server.port()

    on_exit(fn ->
      Application.put_env(:ztlp_ns, :component_auth_enabled, prev_enabled)
      Application.put_env(:ztlp_ns, :component_auth_allowed_keys, prev_keys)
      Application.stop(:ztlp_ns)
      Application.ensure_all_started(:ztlp_ns)
      File.rm_rf!(test_dir)
    end)

    {:ok, port: port}
  end

  # Helper: sign a hostname with `priv` and build a signed 0x14 0x03 request
  # presenting `pub`.
  defp signed_request(hostname, priv, pub) do
    sig = :crypto.sign(:eddsa, :none, hostname, [priv, :ed25519])

    <<0x14, 0x03,
      byte_size(hostname)::unsigned-big-16, hostname::binary,
      byte_size(sig)::unsigned-big-16, sig::binary,
      byte_size(pub)::unsigned-big-16, pub::binary>>
  end

  # The pre-fix format: hostname only, no signature/pubkey.
  defp unsigned_legacy_request(hostname) do
    <<0x14, 0x03, byte_size(hostname)::unsigned-big-16, hostname::binary>>
  end

  # Send a raw packet to the server's UDP port and read the reply.
  defp send_and_recv(port, packet) do
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    :ok = :gen_udp.send(sock, ~c"127.0.0.1", port, packet)

    result =
      case :gen_udp.recv(sock, 0, 2000) do
        {:ok, {_ip, _port, reply}} -> reply
        what -> {:no_reply, what}
      end

    :gen_udp.close(sock)
    result
  end

  # Parse the reply: <<0x14, 0x03, status, rest>>
  defp parse_status(reply) do
    <<0x14, 0x03, status, _rest::binary>> = reply
    status
  end

  # ── Tests ───────────────────────────────────────────────────────────

  test "unsigned/legacy cert-issuance request is rejected (no private key leaked)", %{port: port} do
    # The unsigned/legacy format is unconditionally rejected (server.ex:534-536
    # clause) regardless of component-auth config.
    Application.put_env(:ztlp_ns, :component_auth_enabled, true)
    Application.put_env(:ztlp_ns, :component_auth_allowed_keys, [])

    reply = send_and_recv(port, unsigned_legacy_request("svc.attacker.ztlp"))
    assert is_binary(reply), "expected a UDP reply, got #{inspect(reply)}"
    assert parse_status(reply) == 0x03,
           "unsigned cert-issuance request must be rejected (0x03), got #{inspect(reply)}"
  end

  test "mismatched signature is rejected (presented key != signing key)", %{port: port} do
    {presented_pub, _presented_priv} = :crypto.generate_key(:eddsa, :ed25519)
    {_signer_pub, signer_priv} = :crypto.generate_key(:eddsa, :ed25519)

    # presented_pub is allowlisted, but the request is SIGNED by a different
    # key -> the Ed25519 verify over the hostname bytes must fail.
    Application.put_env(:ztlp_ns, :component_auth_enabled, true)
    Application.put_env(:ztlp_ns, :component_auth_allowed_keys, [presented_pub])

    reply = send_and_recv(port, signed_request("svc.evil.ztlp", signer_priv, presented_pub))
    assert is_binary(reply)
    assert parse_status(reply) == 0x03,
           "mismatched signature must be rejected (0x03), got #{inspect(reply)}"
  end

  test "valid signature but unauthorized key is rejected", %{port: port} do
    {allowed_pub, _allowed_priv} = :crypto.generate_key(:eddsa, :ed25519)
    {unauth_pub, unauth_priv} = :crypto.generate_key(:eddsa, :ed25519)

    # unauth_pub signs a VALID signature but is NOT on the allowlist.
    Application.put_env(:ztlp_ns, :component_auth_enabled, true)
    Application.put_env(:ztlp_ns, :component_auth_allowed_keys, [allowed_pub])

    reply = send_and_recv(port, signed_request("svc.unauthed.ztlp", unauth_priv, unauth_pub))
    assert is_binary(reply)
    assert parse_status(reply) == 0x03,
           "signature from a non-allowlisted key must be rejected (0x03), got #{inspect(reply)}"
  end

  test "valid signature + authorized key issues a cert (happy path)", %{port: port} do
    {allowed_pub, allowed_priv} = :crypto.generate_key(:eddsa, :ed25519)

    Application.put_env(:ztlp_ns, :component_auth_enabled, true)
    Application.put_env(:ztlp_ns, :component_auth_allowed_keys, [allowed_pub])

    reply = send_and_recv(port, signed_request("svc.legit.ztlp", allowed_priv, allowed_pub))
    assert is_binary(reply), "expected a UDP reply, got #{inspect(reply)}"

    # Success: status 0x00 followed by cert/key/chain lengths + PEM bodies.
    assert <<0x14, 0x03, 0x00, cert_len::unsigned-big-32, _key_len::unsigned-big-32,
            _chain_len::unsigned-big-32, _rest::binary>> = reply,
           "expected success (0x00) with cert/key/chain lengths, got #{inspect(reply)}"

    # The privileged payload (previously leaked unauthenticated) is present.
    assert cert_len > 100, "issued cert should be substantial (got #{cert_len}B)"
    assert byte_size(reply) > cert_len + 100, "response should carry key + chain too"
  end

  test "component auth not configured refuses issuance (fail closed)", %{port: port} do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)

    # Even with a correctly-formed + signed request, if component auth is
    # disabled the NS must refuse rather than silently issue (no allowlist).
    Application.put_env(:ztlp_ns, :component_auth_enabled, false)
    Application.put_env(:ztlp_ns, :component_auth_allowed_keys, [pub])

    reply = send_and_recv(port, signed_request("svc.disabled.ztlp", priv, pub))
    assert is_binary(reply)
    assert parse_status(reply) == 0x03,
           "issuance must be refused when component auth is unconfigured (0x03), got #{inspect(reply)}"
  end
end
