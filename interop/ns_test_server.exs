#!/usr/bin/env elixir
# ZTLP NS Test Server
#
# Starts the full ZTLP-NS OTP application with pre-seeded records,
# plus a control channel for the Rust test client.
#
# The NS server uses the standard ZTLP-NS wire protocol (type 0x01 query,
# 0x02 found, 0x03 not_found, 0x05 pubkey query, etc.).
# The control channel is for test setup commands (GET_SEEDED_PUBKEY, etc.).
#
# Usage: elixir ns_test_server.exs [port]

# We need to start the NS application. The NS app expects its code to be
# available, so we start it as a script that loads the NS project.
# Since we're running as a standalone script, we use Mix to compile and load.

defmodule NsTestServer do
  @type_bytes %{key: 1, svc: 2, relay: 3, policy: 4, revoke: 5, bootstrap: 6}

  def start(control_port \\ 0) do
    # Start the NS application
    IO.puts("[ns-test] Starting ZTLP-NS application...")

    # The NS application should already be started by Mix
    # Let's get the NS server port
    ns_port = ZtlpNs.Server.port()
    IO.puts("[ns-test] NS server listening on port #{ns_port}")

    # Open control channel
    {:ok, control_socket} = :gen_udp.open(control_port, [:binary, {:active, false}, {:recbuf, 65535}])
    {:ok, actual_control_port} = :inet.port(control_socket)
    IO.puts("NS_CONTROL_PORT=#{actual_control_port}")
    IO.puts("NS_SERVER_PORT=#{ns_port}")

    # Generate signing keypair and seed records
    {signing_pub, signing_priv} = :crypto.generate_key(:eddsa, :ed25519)
    IO.puts("[ns-test] Signing keypair generated: pub=#{Base.encode16(signing_pub, case: :lower) |> binary_part(0, 16)}...")

    # Add as trust anchor
    ZtlpNs.TrustAnchor.add("test-root", signing_pub)

    # Seed records
    seed_records(signing_pub, signing_priv)

    state = %{
      control_socket: control_socket,
      ns_port: ns_port,
      signing_pub: signing_pub,
      signing_priv: signing_priv
    }

    loop(state)
  end

  defp seed_records(signing_pub, signing_priv) do
    # Generate a node keypair (the identity being registered)
    node_id = :crypto.strong_rand_bytes(16)
    {node_pub, _node_priv} = :crypto.generate_key(:eddsa, :ed25519)

    # Seed a KEY record
    key_record = %ZtlpNs.Record{
      name: "node1.test.ztlp",
      type: :key,
      data: %{
        node_id: Base.encode16(node_id, case: :lower),
        public_key: Base.encode16(node_pub, case: :lower),
        algorithm: "Ed25519"
      },
      created_at: System.system_time(:second),
      ttl: 86400,
      serial: 1,
      signature: nil,
      signer_public_key: nil
    }

    # Sign and insert
    signed_key = sign_record(key_record, signing_pub, signing_priv)
    case ZtlpNs.Store.insert(signed_key) do
      :ok -> IO.puts("[ns-test] Seeded KEY record for 'node1.test.ztlp'")
      {:error, reason} -> IO.puts("[ns-test] ERROR seeding KEY record: #{inspect(reason)}")
    end

    # Seed a SVC record
    svc_record = %ZtlpNs.Record{
      name: "web.test.ztlp",
      type: :svc,
      data: %{
        service_id: Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
        allowed_node_ids: [Base.encode16(node_id, case: :lower)],
        policy_ref: "default"
      },
      created_at: System.system_time(:second),
      ttl: 86400,
      serial: 1,
      signature: nil,
      signer_public_key: nil
    }

    signed_svc = sign_record(svc_record, signing_pub, signing_priv)
    case ZtlpNs.Store.insert(signed_svc) do
      :ok -> IO.puts("[ns-test] Seeded SVC record for 'web.test.ztlp'")
      {:error, reason} -> IO.puts("[ns-test] ERROR seeding SVC record: #{inspect(reason)}")
    end

    # Seed a revoked name
    revoke_record = %ZtlpNs.Record{
      name: "revoked.test.ztlp",
      type: :revoke,
      data: %{
        revoked_ids: ["revoked.test.ztlp"],
        reason: "compromised",
        effective_at: "2024-01-01T00:00:00Z"
      },
      created_at: System.system_time(:second),
      ttl: 0,
      serial: 1,
      signature: nil,
      signer_public_key: nil
    }

    signed_revoke = sign_record(revoke_record, signing_pub, signing_priv)
    case ZtlpNs.Store.insert(signed_revoke) do
      :ok -> IO.puts("[ns-test] Seeded REVOKE record for 'revoked.test.ztlp'")
      {:error, reason} -> IO.puts("[ns-test] ERROR seeding REVOKE record: #{inspect(reason)}")
    end

    # Store the node pubkey hex for the pubkey query test
    Process.put(:seeded_node_pub_hex, Base.encode16(node_pub, case: :lower))
  end

  defp sign_record(record, signing_pub, signing_priv) do
    canonical = ZtlpNs.Record.serialize(record)
    signature = :crypto.sign(:eddsa, :none, canonical, [signing_priv, :ed25519])
    %{record | signature: signature, signer_public_key: signing_pub}
  end

  defp loop(state) do
    case :gen_udp.recv(state.control_socket, 0, 30_000) do
      {:ok, {ip, port, data}} ->
        state = handle_control(state, ip, port, data)
        loop(state)
      {:error, :timeout} ->
        IO.puts("[ns-test] Control channel timeout, exiting")
    end
  end

  defp handle_control(state, ip, port, "GET_SEEDED_PUBKEY") do
    pubkey_hex = Process.get(:seeded_node_pub_hex, "")
    IO.puts("[ns-test] Sending seeded pubkey hex: #{binary_part(pubkey_hex, 0, min(byte_size(pubkey_hex), 16))}...")
    :gen_udp.send(state.control_socket, ip, port, pubkey_hex)
    state
  end

  defp handle_control(state, ip, port, "GET_SIGNED_MESSAGE") do
    # Sign a test message and send message + signature + public key
    message = "ZTLP interop test message #{System.system_time(:millisecond)}"
    signature = :crypto.sign(:eddsa, :none, message, [state.signing_priv, :ed25519])
    msg_len = byte_size(message)

    response = <<msg_len::16, message::binary, signature::binary, state.signing_pub::binary>>
    IO.puts("[ns-test] Sending signed message (#{byte_size(response)} bytes)")
    :gen_udp.send(state.control_socket, ip, port, response)
    state
  end

  defp handle_control(state, ip, port, data) do
    IO.puts("[ns-test] Unknown control command: #{inspect(binary_part(data, 0, min(byte_size(data), 30)))}")
    :gen_udp.send(state.control_socket, ip, port, <<0xFF>>)
    state
  end
end

# Start the NS application
port = case System.argv() do
  [p | _] -> String.to_integer(p)
  [] -> 0
end

NsTestServer.start(port)
