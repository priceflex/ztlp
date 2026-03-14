defmodule ZtlpNs.PunchProtocolTest do
  use ExUnit.Case

  alias ZtlpNs.EndpointStore

  @moduledoc """
  Tests for the PEER_ENDPOINTS (0x0A) and PUNCH_NOTIFY (0x0B) wire protocol
  handled by the NS server.
  """

  setup do
    # Ensure EndpointStore is running
    case Process.whereis(EndpointStore) do
      nil ->
        {:ok, _pid} = EndpointStore.start_link([])
        :ok

      _pid ->
        :ok
    end

    EndpointStore.clear_all()
    :ok
  end

  describe "PEER_ENDPOINTS (0x0A) query" do
    test "returns empty list for unknown target" do
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, port} = :inet.port(socket)

      ns_port = ZtlpNs.Server.port()

      requester_id = :crypto.strong_rand_bytes(16)
      target_id = :crypto.strong_rand_bytes(16)

      # Build PEER_ENDPOINTS request with 0 reported endpoints
      req = <<0x0A, requester_id::binary-size(16), target_id::binary-size(16), 0::8>>
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      # Should be 0x0A response with 0 endpoints
      assert <<0x0A, 0::8>> = response

      :gen_udp.close(socket)
    end

    test "returns known endpoints for target" do
      target_id = :crypto.strong_rand_bytes(16)

      # Pre-populate target's endpoints
      EndpointStore.record_endpoint(target_id, {203, 0, 113, 42}, 3478, :learned)
      EndpointStore.record_endpoint(target_id, {10, 0, 0, 1}, 5000, :reported)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      requester_id = :crypto.strong_rand_bytes(16)

      req = <<0x0A, requester_id::binary-size(16), target_id::binary-size(16), 0::8>>
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)

      # Should have 2 endpoints (deduplicated by ip:port)
      <<0x0A, count::8, addrs::binary>> = response
      assert count == 2

      # Parse the addresses
      parsed = parse_addr_list(addrs, count)
      assert length(parsed) == 2

      :gen_udp.close(socket)
    end

    test "records requester's reported endpoints" do
      requester_id = :crypto.strong_rand_bytes(16)
      target_id = :crypto.strong_rand_bytes(16)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      # Build request with 1 reported IPv4 endpoint
      reported_addr = <<4::8, 198::8, 51::8, 100::8, 25::8, 19302::16>>
      req = <<0x0A, requester_id::binary-size(16), target_id::binary-size(16),
              1::8, reported_addr::binary>>
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, _response}} = :gen_udp.recv(socket, 0, 2000)

      # Check that the reported endpoint was stored
      # Small delay to let the async handler run
      Process.sleep(50)
      endpoints = EndpointStore.get_endpoints(requester_id)

      # Should have at least the reported address and the learned (source) address
      reported = Enum.filter(endpoints, fn {type, _, _} -> type == :reported end)
      assert length(reported) >= 1

      :gen_udp.close(socket)
    end

    test "tracks requester's source address as learned endpoint" do
      requester_id = :crypto.strong_rand_bytes(16)
      target_id = :crypto.strong_rand_bytes(16)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      req = <<0x0A, requester_id::binary-size(16), target_id::binary-size(16), 0::8>>
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, _response}} = :gen_udp.recv(socket, 0, 2000)
      Process.sleep(50)

      endpoints = EndpointStore.get_endpoints(requester_id)
      learned = Enum.filter(endpoints, fn {type, _, _} -> type == :learned end)
      # Should have learned the source address (127.0.0.1:something)
      assert length(learned) >= 1

      :gen_udp.close(socket)
    end
  end

  describe "PUNCH_NOTIFY (0x0B) side-effect" do
    test "sends PUNCH_NOTIFY to target when target has known address" do
      target_id = :crypto.strong_rand_bytes(16)
      requester_id = :crypto.strong_rand_bytes(16)

      # Set up a "target" socket that will receive the PUNCH_NOTIFY
      {:ok, target_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, target_port} = :inet.port(target_socket)

      # Register target's address so NS knows where to send PUNCH_NOTIFY
      EndpointStore.record_endpoint(target_id, {127, 0, 0, 1}, target_port, :learned)

      # Register requester's endpoints too
      EndpointStore.record_endpoint(requester_id, {198, 51, 100, 25}, 19302, :reported)

      # Now send PEER_ENDPOINTS from requester
      {:ok, req_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      req = <<0x0A, requester_id::binary-size(16), target_id::binary-size(16), 0::8>>
      :gen_udp.send(req_socket, ~c"127.0.0.1", ns_port, req)

      # Requester gets their response
      {:ok, {_ip, _port, _response}} = :gen_udp.recv(req_socket, 0, 2000)

      # Target should receive PUNCH_NOTIFY
      case :gen_udp.recv(target_socket, 0, 2000) do
        {:ok, {_ip, _port, notify_data}} ->
          <<0x0B, recv_requester_id::binary-size(16), count::8, _addrs::binary>> = notify_data
          assert recv_requester_id == requester_id
          assert count >= 1  # At least the requester's reported endpoint

        {:error, :timeout} ->
          flunk("Expected PUNCH_NOTIFY but timed out")
      end

      :gen_udp.close(target_socket)
      :gen_udp.close(req_socket)
    end
  end

  describe "PUNCH_REPORT (0x0C)" do
    test "records endpoints and returns ACK" do
      node_id = :crypto.strong_rand_bytes(16)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      reported_addr = <<4::8, 203::8, 0::8, 113::8, 42::8, 3478::16>>
      req = <<0x0C, node_id::binary-size(16), 1::8, reported_addr::binary>>
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x06>> = response

      Process.sleep(50)

      endpoints = EndpointStore.get_endpoints(node_id)
      reported = Enum.filter(endpoints, fn {type, _, _} -> type == :reported end)
      assert length(reported) >= 1

      :gen_udp.close(socket)
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────

  defp parse_addr_list(<<>>, 0), do: []
  defp parse_addr_list(_data, 0), do: []

  defp parse_addr_list(<<4::8, a::8, b::8, c::8, d::8, port::16, rest::binary>>, count) do
    [{{a, b, c, d}, port} | parse_addr_list(rest, count - 1)]
  end

  defp parse_addr_list(<<6::8, addr::binary-size(16), port::16, rest::binary>>, count) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = addr
    [{{a, b, c, d, e, f, g, h}, port} | parse_addr_list(rest, count - 1)]
  end

  defp parse_addr_list(_, _), do: []
end
