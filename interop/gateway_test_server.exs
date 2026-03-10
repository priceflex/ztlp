#!/usr/bin/env elixir
# ZTLP Gateway E2E Test Server
#
# Uses the REAL ZtlpGateway.Handshake module for Noise_XX handshake,
# wraps a TCP echo backend, and tests policy enforcement.
#
# Must be run within the gateway Mix project:
#   cd gateway && mix run ../interop/gateway_test_server.exs [port]

defmodule GatewayE2EServer do
  alias ZtlpGateway.Handshake
  alias ZtlpGateway.Crypto

  @policies %{
    "web" => :all,
    "ssh" => ["admin.ztlp", "*.ops.ztlp"],
    "internal" => ["internal.corp.ztlp"]
  }

  def start(port \\ 0) do
    {:ok, socket} = :gen_udp.open(port, [:binary, {:active, false}, {:recbuf, 65535}])
    {:ok, actual_port} = :inet.port(socket)
    IO.puts("GATEWAY_TEST_PORT=#{actual_port}")

    {static_pub, static_priv} = Crypto.generate_keypair()
    IO.puts("[gw] Static pub: #{Base.encode16(static_pub, case: :lower) |> binary_part(0, 16)}...")

    # Start TCP echo backend
    {:ok, tcp_listener} = :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])
    {:ok, tcp_port} = :inet.port(tcp_listener)
    IO.puts("[gw] TCP echo backend on port #{tcp_port}")
    spawn(fn -> tcp_accept_loop(tcp_listener) end)

    state = %{
      socket: socket,
      static_pub: static_pub,
      static_priv: static_priv,
      tcp_port: tcp_port,
      hs_state: nil,
      i2r_key: nil,
      r2i_key: nil
    }

    loop(state)
  end

  defp tcp_accept_loop(listener) do
    case :gen_tcp.accept(listener, 5000) do
      {:ok, client} ->
        spawn(fn -> tcp_echo(client) end)
        tcp_accept_loop(listener)
      {:error, :timeout} ->
        tcp_accept_loop(listener)
      {:error, _reason} -> :ok
    end
  end

  defp tcp_echo(client) do
    case :gen_tcp.recv(client, 0, 5000) do
      {:ok, data} ->
        :gen_tcp.send(client, data)
        tcp_echo(client)
      {:error, _} -> :ok
    end
  end

  defp loop(state) do
    case :gen_udp.recv(state.socket, 0, 30_000) do
      {:ok, {ip, port, data}} ->
        state = handle_message(state, ip, port, data)
        loop(state)
      {:error, :timeout} ->
        IO.puts("[gw] Timeout, exiting")
    end
  end

  defp handle_message(state, ip, port, <<"GATEWAY_E2E_START", _client_pub::binary-size(32)>>) do
    IO.puts("[gw] Starting gateway E2E test")
    hs = Handshake.init_responder(state.static_pub, state.static_priv)
    :gen_udp.send(state.socket, ip, port, state.static_pub)
    %{state | hs_state: hs, i2r_key: nil, r2i_key: nil}
  end

  defp handle_message(state, ip, port, <<"GW_NOISE_MSG1", msg1::binary>>) do
    IO.puts("[gw] Received msg1 (#{byte_size(msg1)} bytes)")
    case Handshake.handle_msg1(state.hs_state, msg1) do
      {hs, _} ->
        {hs, msg2} = Handshake.create_msg2(hs)
        IO.puts("[gw] Sending msg2 (#{byte_size(msg2)} bytes)")
        :gen_udp.send(state.socket, ip, port, msg2)
        %{state | hs_state: hs}
      {:error, reason} ->
        IO.puts("[gw] msg1 error: #{inspect(reason)}")
        :gen_udp.send(state.socket, ip, port, "ERROR:#{inspect(reason)}")
        state
    end
  end

  defp handle_message(state, ip, port, <<"GW_NOISE_MSG3", msg3::binary>>) do
    IO.puts("[gw] Received msg3 (#{byte_size(msg3)} bytes)")
    case Handshake.handle_msg3(state.hs_state, msg3) do
      {hs, _} ->
        case Handshake.split(hs) do
          {:ok, %{i2r_key: i2r, r2i_key: r2i}} ->
            IO.puts("[gw] Handshake complete, sending keys")
            :gen_udp.send(state.socket, ip, port, "HANDSHAKE_OK" <> i2r <> r2i)
            %{state | hs_state: hs, i2r_key: i2r, r2i_key: r2i}
          {:error, reason} ->
            :gen_udp.send(state.socket, ip, port, "HANDSHAKE_FAILED:#{inspect(reason)}")
            state
        end
      {:error, reason} ->
        IO.puts("[gw] msg3 error: #{inspect(reason)}")
        :gen_udp.send(state.socket, ip, port, "HANDSHAKE_FAILED:#{inspect(reason)}")
        state
    end
  end

  defp handle_message(state, ip, port, <<"GW_ENCRYPTED_DATA", nonce::binary-size(12), ciphertext_and_tag::binary>>) do
    IO.puts("[gw] Received encrypted data (#{byte_size(ciphertext_and_tag)} bytes)")
    if state.i2r_key do
      ct_len = byte_size(ciphertext_and_tag) - 16
      <<ct::binary-size(ct_len), tag::binary-size(16)>> = ciphertext_and_tag
      case Crypto.decrypt(state.i2r_key, nonce, ct, <<>>, tag) do
        :error ->
          IO.puts("[gw] Decryption failed")
          :gen_udp.send(state.socket, ip, port, "DECRYPT_FAILED")
        plaintext ->
          IO.puts("[gw] Decrypted: '#{plaintext}'")
          # Forward to TCP backend
          backend_response = forward_to_backend(state.tcp_port, plaintext)
          # Encrypt response with r2i key
          resp_nonce = <<0::32, 1::unsigned-little-64>>
          {resp_ct, resp_tag} = Crypto.encrypt(state.r2i_key, resp_nonce, backend_response, <<>>)
          :gen_udp.send(state.socket, ip, port, "GW_ECHO_DATA" <> resp_nonce <> resp_ct <> resp_tag)
      end
    else
      :gen_udp.send(state.socket, ip, port, "NO_KEYS")
    end
    state
  end

  defp handle_message(state, ip, port, "GW_SEND_TO_CLIENT") do
    if state.r2i_key do
      nonce = <<0::32, 2::unsigned-little-64>>
      plaintext = "hello from gateway backend"
      {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, plaintext, <<>>)
      :gen_udp.send(state.socket, ip, port, "GW_R2I_DATA" <> nonce <> ct <> tag)
    else
      :gen_udp.send(state.socket, ip, port, "BIDIR_OK")
    end
    state
  end

  defp handle_message(state, ip, port, "GW_POLICY_DENIED") do
    identity = "evil.hacker.ztlp"
    if policy_check(identity, "internal") do
      :gen_udp.send(state.socket, ip, port, "POLICY_ALLOWED")
    else
      :gen_udp.send(state.socket, ip, port, "POLICY_DENIED")
    end
    state
  end

  defp handle_message(state, ip, port, "GW_POLICY_ALLOWED") do
    identity = "admin.ztlp"
    if policy_check(identity, "web") do
      :gen_udp.send(state.socket, ip, port, "POLICY_ALLOWED")
    else
      :gen_udp.send(state.socket, ip, port, "POLICY_DENIED")
    end
    state
  end

  defp handle_message(state, ip, port, data) do
    IO.puts("[gw] Unknown: #{inspect(binary_part(data, 0, min(byte_size(data), 30)))}")
    :gen_udp.send(state.socket, ip, port, "UNKNOWN_CMD")
    state
  end

  defp forward_to_backend(tcp_port, data) do
    case :gen_tcp.connect({127, 0, 0, 1}, tcp_port, [:binary, {:active, false}], 2000) do
      {:ok, sock} ->
        :gen_tcp.send(sock, data)
        case :gen_tcp.recv(sock, 0, 2000) do
          {:ok, response} -> :gen_tcp.close(sock); response
          {:error, _} -> :gen_tcp.close(sock); data
        end
      {:error, _} -> data
    end
  end

  defp policy_check(identity, service) do
    case Map.get(@policies, service) do
      :all -> true
      nil -> false
      patterns when is_list(patterns) ->
        Enum.any?(patterns, fn
          ^identity -> true
          <<"*.", suffix::binary>> -> String.ends_with?(identity, "." <> suffix)
          _ -> false
        end)
    end
  end
end

port = case System.argv() do
  [p | _] -> String.to_integer(p)
  [] -> 0
end

GatewayE2EServer.start(port)
