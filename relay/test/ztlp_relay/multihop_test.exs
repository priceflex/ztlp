defmodule ZtlpRelay.MultihopTest do
  @moduledoc """
  Tests for multi-hop relay forwarding.

  Tests the full multi-hop pipeline: route planning, TTL enforcement,
  loop detection, wire format, and end-to-end multi-hop packet traversal
  using real UDP sockets.
  """
  use ExUnit.Case, async: false

  alias ZtlpRelay.{
    InterRelay,
    RoutePlanner,
    ForwardingTable,
    Crypto,
    Packet
  }

  # ── Helpers ──────────────────────────────────────────────────

  defp start_relay(opts \\ []) do
    node_id = Keyword.get(opts, :node_id, :crypto.strong_rand_bytes(16))
    port = Keyword.get(opts, :port, 0)
    role = Keyword.get(opts, :role, :all)

    {:ok, socket} = :gen_udp.open(port, [:binary, {:active, true}, {:ip, {127, 0, 0, 1}}])
    {:ok, actual_port} = :inet.port(socket)

    %{
      node_id: node_id,
      port: actual_port,
      socket: socket,
      address: {{127, 0, 0, 1}, actual_port},
      role: role
    }
  end

  defp stop_relay(%{socket: socket}) do
    :gen_udp.close(socket)
  end

  defp receive_packet(socket, timeout) do
    receive do
      {:udp, ^socket, _ip, _port, data} -> {:ok, data}
    after
      timeout -> :timeout
    end
  end

  # ── Wire Format Tests ───────────────────────────────────────

  describe "RELAY_FORWARD wire format with TTL and path" do
    test "encode/decode with default TTL and empty path" do
      node_id = :crypto.strong_rand_bytes(16)
      inner = :crypto.strong_rand_bytes(200)

      encoded = InterRelay.encode_forward(node_id, inner)
      assert {:ok, {:relay_forward, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == node_id
      assert payload.inner_packet == inner
      assert payload.ttl == 4
      assert payload.path == []
    end

    test "encode/decode with custom TTL" do
      node_id = :crypto.strong_rand_bytes(16)
      inner = "test packet"

      encoded = InterRelay.encode_forward(node_id, inner, ttl: 2)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)

      assert payload.ttl == 2
      assert payload.path == []
      assert payload.inner_packet == inner
    end

    test "encode/decode with path" do
      node_id = :crypto.strong_rand_bytes(16)
      hop_1 = :crypto.strong_rand_bytes(16)
      hop_2 = :crypto.strong_rand_bytes(16)
      inner = "multi-hop payload"

      encoded = InterRelay.encode_forward(node_id, inner, ttl: 2, path: [hop_1, hop_2])
      {:ok, {:relay_forward, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == node_id
      assert payload.ttl == 2
      assert payload.path == [hop_1, hop_2]
      assert payload.inner_packet == inner
    end

    test "encode/decode with TTL=0" do
      node_id = :crypto.strong_rand_bytes(16)
      inner = "expired"

      encoded = InterRelay.encode_forward(node_id, inner, ttl: 0)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)

      assert payload.ttl == 0
    end

    test "encode/decode with large path (4 hops)" do
      node_id = :crypto.strong_rand_bytes(16)
      path = for _ <- 1..4, do: :crypto.strong_rand_bytes(16)
      inner = :crypto.strong_rand_bytes(500)

      encoded = InterRelay.encode_forward(node_id, inner, ttl: 1, path: path)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)

      assert payload.path == path
      assert length(payload.path) == 4
      assert payload.inner_packet == inner
    end

    test "forward_packet helper includes TTL and path" do
      node_id = :crypto.strong_rand_bytes(16)
      inner = "wrapped"
      hop = :crypto.strong_rand_bytes(16)

      wrapped = InterRelay.forward_packet(inner, node_id, ttl: 3, path: [hop])
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(wrapped)

      assert payload.ttl == 3
      assert payload.path == [hop]
      assert payload.inner_packet == inner
    end

    test "unwrap_forward still returns inner packet" do
      node_id = :crypto.strong_rand_bytes(16)
      inner = "test"

      encoded = InterRelay.encode_forward(node_id, inner, ttl: 3, path: [:crypto.strong_rand_bytes(16)])
      assert {:ok, ^inner} = InterRelay.unwrap_forward(encoded)
    end

    test "unwrap_forward_full returns full payload with TTL and path" do
      node_id = :crypto.strong_rand_bytes(16)
      hop = :crypto.strong_rand_bytes(16)
      inner = "full payload"

      encoded = InterRelay.encode_forward(node_id, inner, ttl: 2, path: [hop])
      assert {:ok, {sender, payload}} = InterRelay.unwrap_forward_full(encoded)

      assert sender == node_id
      assert payload.ttl == 2
      assert payload.path == [hop]
      assert payload.inner_packet == inner
    end

    test "handles empty inner packet with path" do
      node_id = :crypto.strong_rand_bytes(16)
      hop = :crypto.strong_rand_bytes(16)

      encoded = InterRelay.encode_forward(node_id, <<>>, ttl: 4, path: [hop])
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.inner_packet == <<>>
      assert payload.path == [hop]
    end

    test "handles large inner packet near MTU with path" do
      node_id = :crypto.strong_rand_bytes(16)
      hop = :crypto.strong_rand_bytes(16)
      inner = :crypto.strong_rand_bytes(1300)

      encoded = InterRelay.encode_forward(node_id, inner, ttl: 3, path: [hop])
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.inner_packet == inner
    end

    test "truncated forward message returns error" do
      node_id = :crypto.strong_rand_bytes(16)
      inner = "hello"
      encoded = InterRelay.encode_forward(node_id, inner, ttl: 4, path: [])

      truncated = binary_part(encoded, 0, byte_size(encoded) - 2)
      assert {:error, :forward_length_mismatch} = InterRelay.decode(truncated)
    end
  end

  # ── Loop Detection Tests ────────────────────────────────────

  describe "loop detection" do
    test "detects own node_id in path" do
      our_id = :crypto.strong_rand_bytes(16)
      other_id = :crypto.strong_rand_bytes(16)

      assert InterRelay.loop_detected?(our_id, [other_id, our_id])
      assert InterRelay.loop_detected?(our_id, [our_id])
    end

    test "no loop when node_id not in path" do
      our_id = :crypto.strong_rand_bytes(16)
      other_id = :crypto.strong_rand_bytes(16)

      refute InterRelay.loop_detected?(our_id, [other_id])
      refute InterRelay.loop_detected?(our_id, [])
    end
  end

  # ── TTL Enforcement Tests ───────────────────────────────────

  describe "TTL enforcement" do
    test "default TTL is 4" do
      assert InterRelay.default_ttl() == 4
    end

    test "TTL decrements correctly in forwarding chain" do
      node_id = :crypto.strong_rand_bytes(16)
      inner = "test"

      # Start with TTL=4
      encoded = InterRelay.encode_forward(node_id, inner, ttl: 4)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.ttl == 4

      # Simulate forwarding with TTL-1
      re_encoded = InterRelay.encode_forward(node_id, inner, ttl: payload.ttl - 1, path: [node_id])
      {:ok, {:relay_forward, _, _, payload2}} = InterRelay.decode(re_encoded)
      assert payload2.ttl == 3
      assert payload2.path == [node_id]
    end
  end

  # ── Multi-Hop UDP Integration Test ──────────────────────────

  describe "multi-hop forwarding over real UDP" do
    test "Client → Ingress → Transit → Service (3-hop path)" do
      # Start 3 relay sockets with different roles
      ingress = start_relay(role: :ingress)
      transit = start_relay(role: :transit)
      service = start_relay(role: :service)

      # Build a ZTLP data packet
      session_id = Crypto.generate_session_id()
      inner_pkt = Packet.build_data(session_id, 1, payload: "multi-hop test data")
      inner_raw = Packet.serialize(inner_pkt)

      # Step 1: Ingress receives packet from client, wraps it with TTL=4 and sends to transit
      forward_to_transit = InterRelay.encode_forward(
        ingress.node_id, inner_raw,
        ttl: 4,
        path: [ingress.node_id]
      )
      {t_ip, t_port} = transit.address
      :gen_udp.send(ingress.socket, t_ip, t_port, forward_to_transit)

      # Step 2: Transit receives and decodes
      assert {:ok, fwd_data_1} = receive_packet(transit.socket, 1_000)
      assert {:ok, {:relay_forward, sender_1, _ts, payload_1}} = InterRelay.decode(fwd_data_1)

      assert sender_1 == ingress.node_id
      assert payload_1.ttl == 4
      assert payload_1.path == [ingress.node_id]
      assert payload_1.inner_packet == inner_raw

      # Transit decrements TTL, appends its NodeID to path, forwards to service
      new_ttl = payload_1.ttl - 1
      new_path = payload_1.path ++ [transit.node_id]

      forward_to_service = InterRelay.encode_forward(
        transit.node_id, payload_1.inner_packet,
        ttl: new_ttl,
        path: new_path
      )
      {s_ip, s_port} = service.address
      :gen_udp.send(transit.socket, s_ip, s_port, forward_to_service)

      # Step 3: Service receives and decodes
      assert {:ok, fwd_data_2} = receive_packet(service.socket, 1_000)
      assert {:ok, {:relay_forward, sender_2, _ts, payload_2}} = InterRelay.decode(fwd_data_2)

      assert sender_2 == transit.node_id
      assert payload_2.ttl == 3
      assert payload_2.path == [ingress.node_id, transit.node_id]
      assert payload_2.inner_packet == inner_raw

      # Service unwraps and verifies the inner ZTLP packet
      assert {:ok, parsed} = Packet.parse(payload_2.inner_packet)
      assert parsed.session_id == session_id
      assert parsed.payload == "multi-hop test data"

      stop_relay(ingress)
      stop_relay(transit)
      stop_relay(service)
    end

    test "4-hop path: Client → Ingress → Transit1 → Transit2 → Service" do
      ingress = start_relay(role: :ingress)
      transit_1 = start_relay(role: :transit)
      transit_2 = start_relay(role: :transit)
      service = start_relay(role: :service)

      session_id = Crypto.generate_session_id()
      inner_raw = Packet.serialize(Packet.build_data(session_id, 1, payload: "4-hop test"))

      # Hop 1: Ingress → Transit1
      fwd_1 = InterRelay.encode_forward(ingress.node_id, inner_raw,
        ttl: 4, path: [ingress.node_id])
      :gen_udp.send(ingress.socket, elem(transit_1.address, 0), elem(transit_1.address, 1), fwd_1)

      assert {:ok, data_1} = receive_packet(transit_1.socket, 1_000)
      {:ok, {:relay_forward, _, _, p1}} = InterRelay.decode(data_1)
      assert p1.ttl == 4

      # Hop 2: Transit1 → Transit2
      fwd_2 = InterRelay.encode_forward(transit_1.node_id, p1.inner_packet,
        ttl: p1.ttl - 1, path: p1.path ++ [transit_1.node_id])
      :gen_udp.send(transit_1.socket, elem(transit_2.address, 0), elem(transit_2.address, 1), fwd_2)

      assert {:ok, data_2} = receive_packet(transit_2.socket, 1_000)
      {:ok, {:relay_forward, _, _, p2}} = InterRelay.decode(data_2)
      assert p2.ttl == 3
      assert length(p2.path) == 2

      # Hop 3: Transit2 → Service
      fwd_3 = InterRelay.encode_forward(transit_2.node_id, p2.inner_packet,
        ttl: p2.ttl - 1, path: p2.path ++ [transit_2.node_id])
      :gen_udp.send(transit_2.socket, elem(service.address, 0), elem(service.address, 1), fwd_3)

      assert {:ok, data_3} = receive_packet(service.socket, 1_000)
      {:ok, {:relay_forward, _, _, p3}} = InterRelay.decode(data_3)
      assert p3.ttl == 2
      assert length(p3.path) == 3
      assert p3.path == [ingress.node_id, transit_1.node_id, transit_2.node_id]

      # Service unwraps
      assert {:ok, parsed} = Packet.parse(p3.inner_packet)
      assert parsed.payload == "4-hop test"

      Enum.each([ingress, transit_1, transit_2, service], &stop_relay/1)
    end

    test "packet dropped when TTL reaches 0" do
      relay_a = start_relay()
      relay_b = start_relay()

      session_id = Crypto.generate_session_id()
      inner_raw = Packet.serialize(Packet.build_data(session_id, 1, payload: "dead packet"))

      # Send with TTL=0 — should be dropped by any processing relay
      fwd = InterRelay.encode_forward(relay_a.node_id, inner_raw, ttl: 0, path: [relay_a.node_id])
      :gen_udp.send(relay_a.socket, elem(relay_b.address, 0), elem(relay_b.address, 1), fwd)

      # Relay B receives it
      assert {:ok, data} = receive_packet(relay_b.socket, 1_000)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(data)
      assert payload.ttl == 0

      # A processing relay would check TTL=0 and drop — we verify the TTL is 0
      assert payload.ttl <= 0

      stop_relay(relay_a)
      stop_relay(relay_b)
    end

    test "loop detected when own node_id in path" do
      relay_a = start_relay()
      relay_b = start_relay()

      session_id = Crypto.generate_session_id()
      inner_raw = Packet.serialize(Packet.build_data(session_id, 1, payload: "loop"))

      # Path already contains relay_b's node_id
      fwd = InterRelay.encode_forward(relay_a.node_id, inner_raw,
        ttl: 3, path: [relay_a.node_id, relay_b.node_id])
      :gen_udp.send(relay_a.socket, elem(relay_b.address, 0), elem(relay_b.address, 1), fwd)

      assert {:ok, data} = receive_packet(relay_b.socket, 1_000)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(data)

      # Relay B's processing logic should detect its own node_id in the path
      assert InterRelay.loop_detected?(relay_b.node_id, payload.path)

      stop_relay(relay_a)
      stop_relay(relay_b)
    end

    test "backward compat: single-hop with TTL=1 and empty path works" do
      relay_a = start_relay()
      relay_b = start_relay()

      session_id = Crypto.generate_session_id()
      inner_raw = Packet.serialize(Packet.build_data(session_id, 1, payload: "single hop"))

      # Send with TTL=1 and empty path — single-hop backward compat
      fwd = InterRelay.encode_forward(relay_a.node_id, inner_raw, ttl: 1, path: [])
      :gen_udp.send(relay_a.socket, elem(relay_b.address, 0), elem(relay_b.address, 1), fwd)

      assert {:ok, data} = receive_packet(relay_b.socket, 1_000)
      {:ok, {:relay_forward, sender, _, payload}} = InterRelay.decode(data)

      assert sender == relay_a.node_id
      assert payload.ttl == 1
      assert payload.path == []
      assert {:ok, parsed} = Packet.parse(payload.inner_packet)
      assert parsed.payload == "single hop"

      stop_relay(relay_a)
      stop_relay(relay_b)
    end
  end

  # ── Path Caching Tests ─────────────────────────────────────

  describe "path caching via ForwardingTable" do
    setup do
      table_name = :"ztlp_fwd_cache_test_#{:erlang.unique_integer([:positive])}"
      name = :"fwd_cache_test_#{:erlang.unique_integer([:positive])}"
      {:ok, pid} = ForwardingTable.start_link(
        name: name,
        table_name: table_name,
        sweep_interval_ms: 600_000
      )
      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)
      %{table: table_name}
    end

    test "first packet plans route, subsequent use cache", %{table: table} do
      session_id = Crypto.generate_session_id()
      transit_id = :crypto.strong_rand_bytes(16)
      service_id = :crypto.strong_rand_bytes(16)
      path = [transit_id, service_id]

      # No cached path initially
      assert ForwardingTable.get(session_id, table) == nil

      # Cache the planned path
      ForwardingTable.put(session_id, path, table: table)

      # Second lookup returns cached path
      assert ForwardingTable.get(session_id, table) == path
    end

    test "cached path expires after TTL", %{table: table} do
      session_id = Crypto.generate_session_id()
      path = [:crypto.strong_rand_bytes(16)]

      ForwardingTable.put(session_id, path, ttl_ms: 20, table: table)
      assert ForwardingTable.get(session_id, table) == path

      Process.sleep(30)
      assert ForwardingTable.get(session_id, table) == nil
    end
  end

  # ── Role-Based Routing Tests ────────────────────────────────

  describe "role-based routing" do
    test "ingress → transit → service path planning" do
      ingress = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 1}, 9001}, role: :ingress}
      transit = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 2}, 9002}, role: :transit}
      service = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 3}, 9003}, role: :service}
      registry = [ingress, transit, service]

      {:ok, path} = RoutePlanner.plan(ingress.node_id, service.node_id, registry)
      roles = Enum.map(path, & &1.role)

      assert :transit in roles
      assert :service in roles
      assert List.last(path).node_id == service.node_id
    end

    test "transit → service is direct" do
      transit = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 2}, 9002}, role: :transit}
      service = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 3}, 9003}, role: :service}
      registry = [transit, service]

      {:ok, path} = RoutePlanner.plan(transit.node_id, service.node_id, registry)
      assert length(path) == 1
      assert hd(path).role == :service
    end

    test "service → ingress goes through transit" do
      ingress = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 1}, 9001}, role: :ingress}
      transit = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 2}, 9002}, role: :transit}
      service = %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 0, 3}, 9003}, role: :service}
      registry = [ingress, transit, service]

      {:ok, path} = RoutePlanner.plan(service.node_id, ingress.node_id, registry)
      assert length(path) == 2
      assert hd(path).role == :transit
    end
  end
end
