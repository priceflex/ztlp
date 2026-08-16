defmodule ZtlpNs.PunchProtocolTest do
  use ExUnit.Case

  alias ZtlpNs.{Crypto, EndpointStore}

  @moduledoc """
  Tests for the PEER_ENDPOINTS (0x0A) and PUNCH_NOTIFY (0x0B) wire protocol
  handled by the NS server.

  [irt-rwzo] Since the Ed25519 endpoint-auth fix, any test that expects
  a PEER_ENDPOINTS/PUNCH_REPORT request to actually WRITE to the
  EndpointStore must send a properly signed v2 packet (see
  `build_v2_peer_endpoints_request/4` and `build_v2_punch_report/3`
  below) -- an unsigned (v1) request is still answered but is no
  longer tracked by default. Tests that only exercise the READ side
  (pre-populating EndpointStore directly, then querying) are unaffected
  and still use plain v1 requests.
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
    ZtlpNs.EndpointAuth.clear_pins()
    :ok
  end

  # ── Signed (v2) wire-format helpers ─────────────────────────────────

  defp gen_identity do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    {pub, priv}
  end

  defp sign_endpoint_claim(node_id, timestamp, priv) do
    message = <<node_id::binary-size(16), timestamp::unsigned-big-64>>
    Crypto.sign(message, priv)
  end

  defp build_v2_peer_endpoints_request(requester_id, target_id, {pub, priv}, reported \\ <<0::8>>) do
    timestamp = System.system_time(:second)
    sig = sign_endpoint_claim(requester_id, timestamp, priv)

    <<0x0A, requester_id::binary-size(16), target_id::binary-size(16),
      timestamp::unsigned-big-64, sig::binary-size(64), pub::binary-size(32),
      reported::binary>>
  end

  defp build_v2_punch_report(node_id, {pub, priv}, reported \\ <<0::8>>) do
    timestamp = System.system_time(:second)
    sig = sign_endpoint_claim(node_id, timestamp, priv)

    <<0x0C, node_id::binary-size(16), timestamp::unsigned-big-64,
      sig::binary-size(64), pub::binary-size(32), reported::binary>>
  end

  describe "PEER_ENDPOINTS (0x0A) query" do
    test "returns empty list for unknown target" do
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, _port} = :inet.port(socket)

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

      # v0.35.2: the serve path now PREFERS :reported and suppresses :learned
      # when any :reported endpoint exists (ZtlpNs.Server.response_endpoints/1).
      # A :learned endpoint is the NS-observed control-plane source — a transient
      # outbound NAT mapping, not an inbound listener — so offering it as a dial
      # candidate alongside the real reported address poisoned the operator's
      # parallel-dial race (KELLYMANCINO-PC, 2026-06-15). With 1 learned + 1
      # reported pre-populated, the response now carries ONLY the reported one.
      # (Bilateral PUNCH_NOTIFY coordination still uses the full set.)
      <<0x0A, count::8, addrs::binary>> = response
      assert count == 1

      # Parse the addresses — must be exactly the reported endpoint.
      parsed = parse_addr_list(addrs, count)
      assert parsed == [{{10, 0, 0, 1}, 5000}]

      :gen_udp.close(socket)
    end

    test "records requester's reported endpoints" do
      requester_id = :crypto.strong_rand_bytes(16)
      target_id = :crypto.strong_rand_bytes(16)
      identity = gen_identity()

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      # Build request with 1 reported IPv4 endpoint
      reported_addr = <<4::8, 198::8, 51::8, 100::8, 25::8, 19302::16>>
      reported = <<1::8, reported_addr::binary>>

      req = build_v2_peer_endpoints_request(requester_id, target_id, identity, reported)

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
      identity = gen_identity()

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      req = build_v2_peer_endpoints_request(requester_id, target_id, identity)
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
          # At least the requester's reported endpoint
          assert count >= 1

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
      identity = gen_identity()

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      reported_addr = <<4::8, 203::8, 0::8, 113::8, 42::8, 3478::16>>
      reported = <<1::8, reported_addr::binary>>
      req = build_v2_punch_report(node_id, identity, reported)
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x06>> = response

      Process.sleep(50)

      endpoints = EndpointStore.get_endpoints(node_id)
      reported = Enum.filter(endpoints, fn {type, _, _} -> type == :reported end)
      assert length(reported) >= 1

      :gen_udp.close(socket)
    end

    test "stores 3 IPv4 reported endpoints from a single PUNCH_REPORT" do
      node_id = :crypto.strong_rand_bytes(16)
      identity = gen_identity()

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      e1 = <<4::8, 10::8, 0::8, 0::8, 1::8, 23_095::16>>
      e2 = <<4::8, 192::8, 168::8, 1::8, 5::8, 23_095::16>>
      e3 = <<4::8, 172::8, 17::8, 0::8, 1::8, 23_095::16>>

      reported = <<3::8, e1::binary, e2::binary, e3::binary>>
      req = build_v2_punch_report(node_id, identity, reported)
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x06>> = response

      Process.sleep(50)

      reported =
        node_id
        |> EndpointStore.get_endpoints()
        |> Enum.filter(fn {type, _, _} -> type == :reported end)
        |> Enum.map(fn {_, ip, port} -> {ip, port} end)

      assert {{10, 0, 0, 1}, 23_095} in reported
      assert {{192, 168, 1, 5}, 23_095} in reported
      assert {{172, 17, 0, 1}, 23_095} in reported
      assert length(reported) == 3

      :gen_udp.close(socket)
    end

    test "stores mixed IPv4 + IPv6 reported endpoints in a single PUNCH_REPORT" do
      node_id = :crypto.strong_rand_bytes(16)
      identity = gen_identity()

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      v4a = <<4::8, 10::8, 0::8, 0::8, 1::8, 23_095::16>>
      v4b = <<4::8, 192::8, 168::8, 1::8, 5::8, 23_095::16>>

      # fd12:3456::1 → 16 bytes
      v6_addr = <<0xFD12::16, 0x3456::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0x0001::16>>

      v6_entry = <<6::8, v6_addr::binary, 23_095::16>>

      reported = <<3::8, v4a::binary, v4b::binary, v6_entry::binary>>
      req = build_v2_punch_report(node_id, identity, reported)

      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x06>> = response

      Process.sleep(50)

      reported =
        node_id
        |> EndpointStore.get_endpoints()
        |> Enum.filter(fn {type, _, _} -> type == :reported end)
        |> Enum.map(fn {_, ip, port} -> {ip, port} end)

      assert {{10, 0, 0, 1}, 23_095} in reported
      assert {{192, 168, 1, 5}, 23_095} in reported
      assert {{0xFD12, 0x3456, 0, 0, 0, 0, 0, 0x0001}, 23_095} in reported

      v4_count = Enum.count(reported, fn {ip, _} -> tuple_size(ip) == 4 end)

      v6_count = Enum.count(reported, fn {ip, _} -> tuple_size(ip) == 8 end)

      assert v4_count == 2
      assert v6_count == 1

      :gen_udp.close(socket)
    end

    test "stores 8 reported endpoints (matches v0.32 hard cap)" do
      node_id = :crypto.strong_rand_bytes(16)
      identity = gen_identity()

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      entries =
        for i <- 1..8 do
          <<4::8, 10::8, 0::8, 0::8, i::8, 23_095::16>>
        end

      reported = <<8::8, IO.iodata_to_binary(entries)::binary>>
      req = build_v2_punch_report(node_id, identity, reported)

      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x06>> = response

      Process.sleep(50)

      reported =
        node_id
        |> EndpointStore.get_endpoints()
        |> Enum.filter(fn {type, _, _} -> type == :reported end)

      assert length(reported) >= 8

      :gen_udp.close(socket)
    end

    test "tolerates malformed PUNCH_REPORT without crash" do
      node_id = :crypto.strong_rand_bytes(16)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      ns_port = ZtlpNs.Server.port()

      # count says 3, but the body is truncated garbage that cannot decode.
      # Sent as an unsigned (v1) request -- this test is about crash safety
      # in the wire-format parser, not endpoint auth, and a v1 request is
      # still ACKed unconditionally per the module doc above.
      garbage = "xy"
      req = <<0x0C, node_id::binary-size(16), 3::8, garbage::binary>>
      :gen_udp.send(socket, ~c"127.0.0.1", ns_port, req)

      # Server must not crash; it must still ACK
      {:ok, {_ip, _port, response}} = :gen_udp.recv(socket, 0, 2000)
      assert <<0x06>> = response

      :gen_udp.close(socket)
    end
  end

  describe "PEER_ENDPOINTS (0x0A) — roundtrip" do
    test "response includes all reported endpoints from prior PUNCH_REPORT" do
      target_id = :crypto.strong_rand_bytes(16)
      requester_id = :crypto.strong_rand_bytes(16)
      target_identity = gen_identity()

      ns_port = ZtlpNs.Server.port()

      # Step A: target sends PUNCH_REPORT with 3 IPv4 reported endpoints.
      # Use a dedicated socket so the learned (source) endpoint is distinct
      # from the requester's socket below.
      {:ok, target_socket} = :gen_udp.open(0, [:binary, {:active, false}])

      r1 = <<4::8, 10::8, 0::8, 0::8, 1::8, 23_095::16>>
      r2 = <<4::8, 192::8, 168::8, 1::8, 5::8, 23_095::16>>
      r3 = <<4::8, 172::8, 17::8, 0::8, 1::8, 23_095::16>>

      reported = <<3::8, r1::binary, r2::binary, r3::binary>>
      report = build_v2_punch_report(target_id, target_identity, reported)

      :gen_udp.send(target_socket, ~c"127.0.0.1", ns_port, report)
      {:ok, {_ip, _port, <<0x06>>}} = :gen_udp.recv(target_socket, 0, 2000)

      Process.sleep(50)

      # Step B: requester queries PEER_ENDPOINTS for the target
      {:ok, req_socket} = :gen_udp.open(0, [:binary, {:active, false}])

      req = <<0x0A, requester_id::binary-size(16), target_id::binary-size(16), 0::8>>

      :gen_udp.send(req_socket, ~c"127.0.0.1", ns_port, req)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(req_socket, 0, 2000)

      <<0x0A, count::8, addrs::binary>> = response
      parsed = parse_addr_list(addrs, count)

      # v0.35.2: with :reported endpoints present, the serve path suppresses the
      # :learned (target_socket source) endpoint — see response_endpoints/1 and
      # the KELLYMANCINO-PC rationale. So the response is exactly the 3 reported
      # endpoints from the PUNCH_REPORT, NOT 3 reported + 1 learned.
      assert count == 3
      assert length(parsed) == 3

      assert {{10, 0, 0, 1}, 23_095} in parsed
      assert {{192, 168, 1, 5}, 23_095} in parsed
      assert {{172, 17, 0, 1}, 23_095} in parsed

      :gen_udp.close(target_socket)
      :gen_udp.close(req_socket)
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
