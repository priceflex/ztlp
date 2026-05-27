defmodule ZtlpNs.ListRelaysProtocolTest do
  use ExUnit.Case

  @moduledoc """
  Tests for the LIST_RELAYS (0x0D) wire protocol handled by the NS server.

  Wire format:

  REQUEST:  <<0x0D, requester_node_id::binary-16, zone_len::8, zone::binary-zone_len>>
  RESPONSE: <<0x0D, count::8, [<<addr_family::8, addr::binary-4or16, port::16,
                                  region_len::8, region::binary-region_len>>]*>>
  """

  setup do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
    on_exit(fn -> :gen_udp.close(socket) end)
    {:ok, socket: socket, ns_port: ZtlpNs.Server.port()}
  end

  describe "LIST_RELAYS (0x0D)" do
    test "returns empty list when no relays registered for an unknown zone",
         %{socket: socket, ns_port: ns_port} do
      requester_id = :crypto.strong_rand_bytes(16)
      zone = "us-west-2"
      zone_len = byte_size(zone)

      req = <<0x0D, requester_id::binary-size(16), zone_len::8, zone::binary>>
      :ok = :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x0D, 0::8>> = response
    end

    test "empty zone request (zone_len=0) also returns empty list",
         %{socket: socket, ns_port: ns_port} do
      requester_id = :crypto.strong_rand_bytes(16)

      req = <<0x0D, requester_id::binary-size(16), 0::8>>
      :ok = :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x0D, 0::8>> = response
    end

    test "response format begins with 0x0D and a count byte",
         %{socket: socket, ns_port: ns_port} do
      requester_id = :crypto.strong_rand_bytes(16)
      zone = "any"

      req = <<0x0D, requester_id::binary-size(16), byte_size(zone)::8, zone::binary>>
      :ok = :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x0D, count::8, _rest::binary>> = response
      assert is_integer(count)
      assert count >= 0 and count <= 32
    end

    test "handles malformed (short) request gracefully — NS still responds",
         %{socket: socket, ns_port: ns_port} do
      # Just the type byte, no node_id — server must not crash.
      req = <<0x0D>>
      :ok = :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      # Either gets an error/invalid response (0xFF) or no response.
      # The important guarantee: NS keeps serving subsequent requests.
      _ = :gen_udp.recv(socket, 0, 500)

      # Liveness check: a well-formed request still gets a response.
      requester_id = :crypto.strong_rand_bytes(16)
      good_req = <<0x0D, requester_id::binary-size(16), 0::8>>
      :ok = :gen_udp.send(socket, ~c"127.0.0.1", ns_port, good_req)
      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x0D, 0::8>> = response
    end
  end
end
