defmodule ZtlpRelay.MeshIntegrationTest do
  @moduledoc """
  Integration tests for the relay mesh.

  Tests multi-relay behavior: mesh formation, consistent hash routing,
  failover, PathScore selection, admission tokens, rate limiting,
  session sync, and graceful departure.

  These tests run multiple relay-like nodes in the same BEAM VM using
  raw UDP sockets and the mesh modules (HashRing, InterRelay, etc.).
  """
  use ExUnit.Case, async: false

  alias ZtlpRelay.{
    HashRing,
    PathScore,
    InterRelay,
    RelayRegistry,
    AdmissionToken,
    RateLimiter,
    SessionRegistry,
    Crypto,
    Packet
  }

  # ── Test Helpers ──────────────────────────────────────────────

  # Start a lightweight relay node: a UDP socket + node metadata.
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

  # Stop a relay by closing its socket.
  defp stop_relay(%{socket: socket}) do
    :gen_udp.close(socket)
  end

  # Build and send a ZTLP data packet via a socket.
  defp send_packet(socket, {ip, port}, session_id, payload) do
    pkt = Packet.build_data(session_id, 1, payload: payload)
    raw = Packet.serialize(pkt)
    :gen_udp.send(socket, ip, port, raw)
    raw
  end

  # Receive and return a raw UDP packet within timeout.
  defp receive_packet(socket, timeout) do
    receive do
      {:udp, ^socket, _ip, _port, data} -> {:ok, data}
    after
      timeout -> :timeout
    end
  end

  # Build a hash ring from relay node maps.
  defp build_ring(relays) do
    ring_nodes =
      Enum.map(relays, fn r ->
        %{node_id: r.node_id, address: r.address}
      end)

    HashRing.new(ring_nodes)
  end

  # Flush all messages from the mailbox for a given socket.
  defp flush_socket(socket) do
    receive do
      {:udp, ^socket, _, _, _} -> flush_socket(socket)
    after
      0 -> :ok
    end
  end

  setup do
    # Ensure the relay registry ETS table exists for tests that need it.
    # It's started by the application, but we check anyway.
    :ok
  end

  # ── 1. Three-relay mesh formation ────────────────────────────

  describe "3-relay mesh formation" do
    test "relays discover each other via HELLO exchange and form hash ring" do
      relay_a = start_relay()
      relay_b = start_relay()
      relay_c = start_relay()

      # A → B HELLO
      hello_ab =
        InterRelay.encode_hello(%{
          node_id: relay_a.node_id,
          address: relay_a.address,
          role: :all
        })

      :gen_udp.send(relay_a.socket, elem(relay_b.address, 0), elem(relay_b.address, 1), hello_ab)

      # B receives and decodes HELLO from A
      assert {:ok, data_ab} = receive_packet(relay_b.socket, 1_000)
      assert {:ok, {:relay_hello, sender_ab, _ts, payload_ab}} = InterRelay.decode(data_ab)
      assert sender_ab == relay_a.node_id
      assert payload_ab.address == relay_a.address

      # B → A HELLO_ACK
      ack_ba =
        InterRelay.encode_hello_ack(%{
          node_id: relay_b.node_id,
          address: relay_b.address,
          role: :all
        })

      :gen_udp.send(relay_b.socket, elem(relay_a.address, 0), elem(relay_a.address, 1), ack_ba)

      assert {:ok, data_ack} = receive_packet(relay_a.socket, 1_000)
      assert {:ok, {:relay_hello_ack, sender_ack, _ts, _payload}} = InterRelay.decode(data_ack)
      assert sender_ack == relay_b.node_id

      # A → C HELLO
      hello_ac =
        InterRelay.encode_hello(%{
          node_id: relay_a.node_id,
          address: relay_a.address,
          role: :all
        })

      :gen_udp.send(relay_a.socket, elem(relay_c.address, 0), elem(relay_c.address, 1), hello_ac)

      assert {:ok, data_ac} = receive_packet(relay_c.socket, 1_000)
      assert {:ok, {:relay_hello, _sender, _ts, _payload}} = InterRelay.decode(data_ac)

      # B → C HELLO
      hello_bc =
        InterRelay.encode_hello(%{
          node_id: relay_b.node_id,
          address: relay_b.address,
          role: :all
        })

      :gen_udp.send(relay_b.socket, elem(relay_c.address, 0), elem(relay_c.address, 1), hello_bc)

      assert {:ok, data_bc} = receive_packet(relay_c.socket, 1_000)
      assert {:ok, {:relay_hello, _sender, _ts, _payload}} = InterRelay.decode(data_bc)

      # Build consistent hash ring with all 3 relays
      ring = build_ring([relay_a, relay_b, relay_c])
      assert HashRing.node_count(ring) == 3
      assert HashRing.member?(ring, relay_a.node_id)
      assert HashRing.member?(ring, relay_b.node_id)
      assert HashRing.member?(ring, relay_c.node_id)

      # Verify we get correct number of vnodes (3 * 128 = 384)
      assert length(ring.vnodes) == 384

      stop_relay(relay_a)
      stop_relay(relay_b)
      stop_relay(relay_c)
    end
  end

  # ── 2. Consistent hash packet routing ────────────────────────

  describe "packet routing via consistent hash" do
    test "packet is forwarded to hash-determined relay owner" do
      relay_a = start_relay()
      relay_b = start_relay()
      relay_c = start_relay()

      ring = build_ring([relay_a, relay_b, relay_c])

      # Generate a session ID and find which relay owns it
      session_id = Crypto.generate_session_id()
      [owner | _] = HashRing.get_nodes(ring, session_id, 1)

      owner_relay =
        Enum.find([relay_a, relay_b, relay_c], fn r ->
          r.node_id == owner.node_id
        end)

      # Pick a non-owner relay to "receive" the packet initially
      ingress_relay =
        Enum.find([relay_a, relay_b, relay_c], fn r ->
          r.node_id != owner.node_id
        end)

      # Simulate: ingress relay wraps the ZTLP packet in a RELAY_FORWARD
      inner_pkt = Packet.build_data(session_id, 1, payload: "routed payload")
      inner_raw = Packet.serialize(inner_pkt)
      forward_msg = InterRelay.encode_forward(ingress_relay.node_id, inner_raw)

      # Send the forwarded packet to the owner relay
      {owner_ip, owner_port} = owner_relay.address
      :gen_udp.send(ingress_relay.socket, owner_ip, owner_port, forward_msg)

      # Owner relay receives and unwraps it
      assert {:ok, fwd_data} = receive_packet(owner_relay.socket, 1_000)

      assert {:ok, {:relay_forward, sender, _ts, %{inner_packet: inner}}} =
               InterRelay.decode(fwd_data)

      assert sender == ingress_relay.node_id
      assert inner == inner_raw

      # Verify the inner packet is valid ZTLP
      assert {:ok, parsed} = Packet.parse(inner)
      assert parsed.session_id == session_id
      assert parsed.payload == "routed payload"

      stop_relay(relay_a)
      stop_relay(relay_b)
      stop_relay(relay_c)
    end

    test "same session ID always routes to same relay" do
      relay_a = start_relay()
      relay_b = start_relay()
      relay_c = start_relay()

      ring = build_ring([relay_a, relay_b, relay_c])
      session_id = Crypto.generate_session_id()

      # Query 100 times — always same owner
      results =
        for _ <- 1..100 do
          [owner | _] = HashRing.get_nodes(ring, session_id, 1)
          owner.node_id
        end

      assert length(Enum.uniq(results)) == 1

      stop_relay(relay_a)
      stop_relay(relay_b)
      stop_relay(relay_c)
    end
  end

  # ── 3. Relay failover ────────────────────────────────────────

  describe "relay failover" do
    test "sessions redistribute when a relay is removed from the ring" do
      relay_a = start_relay()
      relay_b = start_relay()
      relay_c = start_relay()

      ring = build_ring([relay_a, relay_b, relay_c])

      # Generate 50 session IDs and record which relay owns each
      session_ids = for _ <- 1..50, do: Crypto.generate_session_id()

      original_owners =
        Map.new(session_ids, fn sid ->
          [owner | _] = HashRing.get_nodes(ring, sid, 1)
          {sid, owner.node_id}
        end)

      # Count sessions per relay before (verify distribution)
      _counts_before = Enum.frequencies(Map.values(original_owners))

      # Kill relay B — remove from ring
      ring_after = HashRing.remove_node(ring, relay_b.node_id)
      assert HashRing.node_count(ring_after) == 2
      refute HashRing.member?(ring_after, relay_b.node_id)

      # Sessions that were on B should move to A or C
      new_owners =
        Map.new(session_ids, fn sid ->
          [owner | _] = HashRing.get_nodes(ring_after, sid, 1)
          {sid, owner.node_id}
        end)

      # All sessions previously on B should now be on A or C
      relay_b_sessions =
        Enum.filter(session_ids, fn sid ->
          original_owners[sid] == relay_b.node_id
        end)

      for sid <- relay_b_sessions do
        assert new_owners[sid] in [relay_a.node_id, relay_c.node_id],
               "Session previously on B should be reassigned to A or C"
      end

      # Sessions NOT on B should still be on their original relay
      non_b_sessions =
        Enum.filter(session_ids, fn sid ->
          original_owners[sid] != relay_b.node_id
        end)

      for sid <- non_b_sessions do
        assert new_owners[sid] == original_owners[sid],
               "Sessions not on failed relay should remain stable"
      end

      stop_relay(relay_a)
      stop_relay(relay_b)
      stop_relay(relay_c)
    end
  end

  # ── 4. PathScore selection ───────────────────────────────────

  describe "PathScore selection" do
    test "selects lowest-score relay from candidates" do
      relay_a = start_relay()
      relay_b = start_relay()
      relay_c = start_relay()

      ring = build_ring([relay_a, relay_b, relay_c])

      # All three are candidates for some session
      session_id = Crypto.generate_session_id()
      candidates = HashRing.get_nodes(ring, session_id, 3)

      # Assign different simulated metrics
      scores = %{
        relay_a.node_id => %{rtt_ms: 100, loss_rate: 0.0, load_factor: 0.5},
        relay_b.node_id => %{rtt_ms: 20, loss_rate: 0.0, load_factor: 0.1},
        relay_c.node_id => %{rtt_ms: 50, loss_rate: 0.05, load_factor: 0.3}
      }

      # Compute expected scores
      score_a = PathScore.compute(scores[relay_a.node_id])
      score_b = PathScore.compute(scores[relay_b.node_id])
      score_c = PathScore.compute(scores[relay_c.node_id])

      # B should have the lowest score (20 * 1.0 * 1.2 = 24.0)
      assert score_b < score_a
      assert score_b < score_c

      # select_best should pick B
      assert {:ok, best} = PathScore.select_best(candidates, scores)
      assert best.node_id == relay_b.node_id

      stop_relay(relay_a)
      stop_relay(relay_b)
      stop_relay(relay_c)
    end

    test "skips relays with no score data (considered unreachable)" do
      relay_a = start_relay()
      relay_b = start_relay()

      ring = build_ring([relay_a, relay_b])
      session_id = Crypto.generate_session_id()
      candidates = HashRing.get_nodes(ring, session_id, 2)

      # Only provide scores for A — B is "unreachable"
      scores = %{
        relay_a.node_id => %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0}
      }

      assert {:ok, best} = PathScore.select_best(candidates, scores)
      assert best.node_id == relay_a.node_id

      stop_relay(relay_a)
      stop_relay(relay_b)
    end

    test "returns error when no candidates have scores" do
      relay_a = start_relay()
      ring = build_ring([relay_a])
      session_id = Crypto.generate_session_id()
      candidates = HashRing.get_nodes(ring, session_id, 1)

      assert :error == PathScore.select_best(candidates, %{})

      stop_relay(relay_a)
    end
  end

  # ── 5. Admission token flow ──────────────────────────────────

  describe "admission token flow" do
    test "ingress issues RAT, transit verifies it" do
      secret = AdmissionToken.generate_secret()
      node_id = :crypto.strong_rand_bytes(16)
      issuer_id = :crypto.strong_rand_bytes(16)
      session_id = Crypto.generate_session_id()

      # Ingress issues a RAT scoped to a session
      token =
        AdmissionToken.issue(node_id, session_id,
          secret_key: secret,
          issuer_id: issuer_id,
          ttl_seconds: 60
        )

      assert byte_size(token) == 93

      # Transit verifies the token
      assert {:ok, fields} = AdmissionToken.verify(token, secret, session_scope: session_id)
      assert fields.node_id == node_id
      assert fields.issuer_id == issuer_id
      assert fields.session_scope == session_id

      # Wrong session scope is rejected
      wrong_session = Crypto.generate_session_id()

      assert {:error, :session_scope_mismatch} =
               AdmissionToken.verify(token, secret, session_scope: wrong_session)

      # Wrong secret is rejected
      wrong_secret = AdmissionToken.generate_secret()
      assert {:error, :invalid_mac} = AdmissionToken.verify(token, wrong_secret)
    end

    test "expired token is rejected" do
      secret = AdmissionToken.generate_secret()
      node_id = :crypto.strong_rand_bytes(16)
      issuer_id = :crypto.strong_rand_bytes(16)

      # Issue a token that already expired
      token =
        AdmissionToken.issue(node_id, nil,
          secret_key: secret,
          issuer_id: issuer_id,
          ttl_seconds: 0
        )

      Process.sleep(50)

      assert {:error, :expired} = AdmissionToken.verify(token, secret)
    end

    test "wildcard session scope token works for any session" do
      secret = AdmissionToken.generate_secret()
      node_id = :crypto.strong_rand_bytes(16)
      issuer_id = :crypto.strong_rand_bytes(16)

      # Issue with nil scope (wildcard)
      token =
        AdmissionToken.issue(node_id, nil,
          secret_key: secret,
          issuer_id: issuer_id,
          ttl_seconds: 60
        )

      # Should accept any session scope
      any_session = Crypto.generate_session_id()
      assert {:ok, _fields} = AdmissionToken.verify(token, secret, session_scope: any_session)
    end

    test "key rotation accepts both current and previous secret" do
      old_secret = AdmissionToken.generate_secret()
      new_secret = AdmissionToken.generate_secret()
      node_id = :crypto.strong_rand_bytes(16)
      issuer_id = :crypto.strong_rand_bytes(16)

      # Token signed with old key
      old_token =
        AdmissionToken.issue(node_id, nil,
          secret_key: old_secret,
          issuer_id: issuer_id,
          ttl_seconds: 60
        )

      # Token signed with new key
      new_token =
        AdmissionToken.issue(node_id, nil,
          secret_key: new_secret,
          issuer_id: issuer_id,
          ttl_seconds: 60
        )

      # Both should verify with rotation
      assert {:ok, _} = AdmissionToken.verify_with_rotation(old_token, new_secret, old_secret)
      assert {:ok, _} = AdmissionToken.verify_with_rotation(new_token, new_secret, old_secret)
    end
  end

  # ── 6. Rate limiting ────────────────────────────────────────

  describe "rate limiting" do
    setup do
      # Start a dedicated rate limiter for this test
      table_name = :"ztlp_rate_test_#{:erlang.unique_integer([:positive])}"

      {:ok, pid} =
        RateLimiter.start_link(
          name: :"rate_limiter_test_#{:erlang.unique_integer([:positive])}",
          table: table_name
        )

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      %{table: table_name}
    end

    test "allows requests under the limit", %{table: table} do
      ip = {192, 168, 1, 1}

      for _ <- 1..10 do
        assert :ok == RateLimiter.check(ip, 10, 60_000, table: table)
      end
    end

    test "blocks requests exceeding the limit", %{table: table} do
      ip = {10, 0, 0, 1}

      # Use up all 10 allowed
      for _ <- 1..10 do
        assert :ok == RateLimiter.check(ip, 10, 60_000, table: table)
      end

      # 11th should be rate limited
      assert {:error, :rate_limited} == RateLimiter.check(ip, 10, 60_000, table: table)
    end

    test "different IPs have independent limits", %{table: table} do
      ip_a = {10, 0, 0, 1}
      ip_b = {10, 0, 0, 2}

      # Max out IP A
      for _ <- 1..10 do
        RateLimiter.check(ip_a, 10, 60_000, table: table)
      end

      assert {:error, :rate_limited} == RateLimiter.check(ip_a, 10, 60_000, table: table)

      # IP B should still be fine
      assert :ok == RateLimiter.check(ip_b, 10, 60_000, table: table)
    end

    test "window expires and counter resets", %{table: table} do
      ip = {10, 0, 0, 3}

      # Use up all 5 allowed in a very short window
      for _ <- 1..5 do
        assert :ok == RateLimiter.check(ip, 5, 50, table: table)
      end

      assert {:error, :rate_limited} == RateLimiter.check(ip, 5, 50, table: table)

      # Wait for window to expire
      Process.sleep(60)

      # Should be allowed again
      assert :ok == RateLimiter.check(ip, 5, 50, table: table)
    end

    test "simulates >10 HELLOs per minute from same IP", %{table: table} do
      ip = {172, 16, 0, 1}
      limit = 10
      window_ms = 60_000

      results =
        for _i <- 1..15 do
          RateLimiter.check(ip, limit, window_ms, table: table)
        end

      allowed = Enum.count(results, &(&1 == :ok))
      blocked = Enum.count(results, &(&1 == {:error, :rate_limited}))

      assert allowed == 10
      assert blocked == 5
    end
  end

  # ── 7. Session sync ─────────────────────────────────────────

  describe "session sync" do
    test "RELAY_SESSION_SYNC transfers session info between relays" do
      relay_a = start_relay()
      relay_b = start_relay()

      session_id = Crypto.generate_session_id()
      peer_a = {{192, 168, 1, 10}, 5000}
      peer_b = {{192, 168, 1, 20}, 6000}

      # Relay A encodes a session sync message
      sync_msg =
        InterRelay.encode_session_sync(relay_a.node_id, %{
          session_id: session_id,
          peer_a: peer_a,
          peer_b: peer_b
        })

      # Send to Relay B
      {b_ip, b_port} = relay_b.address
      :gen_udp.send(relay_a.socket, b_ip, b_port, sync_msg)

      # Relay B receives and decodes
      assert {:ok, data} = receive_packet(relay_b.socket, 1_000)
      assert {:ok, {:relay_session_sync, sender, _ts, payload}} = InterRelay.decode(data)
      assert sender == relay_a.node_id
      assert payload.session_id == session_id
      assert payload.peer_a == peer_a
      assert payload.peer_b == peer_b

      # Relay B can now register this session in its local registry
      SessionRegistry.register_session(session_id, peer_a, peer_b)
      assert SessionRegistry.session_exists?(session_id)

      # Cleanup
      SessionRegistry.unregister_session(session_id)
      stop_relay(relay_a)
      stop_relay(relay_b)
    end

    test "multiple sessions can be synced sequentially" do
      relay_a = start_relay()
      relay_b = start_relay()

      sessions =
        for _ <- 1..5 do
          sid = Crypto.generate_session_id()
          pa = {{10, 0, 0, Enum.random(1..254)}, Enum.random(1024..65535)}
          pb = {{10, 0, 0, Enum.random(1..254)}, Enum.random(1024..65535)}
          %{session_id: sid, peer_a: pa, peer_b: pb}
        end

      for sess <- sessions do
        sync_msg = InterRelay.encode_session_sync(relay_a.node_id, sess)
        {b_ip, b_port} = relay_b.address
        :gen_udp.send(relay_a.socket, b_ip, b_port, sync_msg)

        assert {:ok, data} = receive_packet(relay_b.socket, 1_000)
        assert {:ok, {:relay_session_sync, _sender, _ts, payload}} = InterRelay.decode(data)
        assert payload.session_id == sess.session_id
      end

      stop_relay(relay_a)
      stop_relay(relay_b)
    end
  end

  # ── 8. Graceful departure ───────────────────────────────────

  describe "graceful departure" do
    test "RELAY_LEAVE removes relay from ring and triggers session migration" do
      relay_a = start_relay()
      relay_b = start_relay()
      relay_c = start_relay()

      ring = build_ring([relay_a, relay_b, relay_c])
      assert HashRing.node_count(ring) == 3

      # Relay B sends LEAVE
      leave_msg = InterRelay.encode_leave(relay_b.node_id)

      # Send to A and C
      for target <- [relay_a, relay_c] do
        {ip, port} = target.address
        :gen_udp.send(relay_b.socket, ip, port, leave_msg)
      end

      # A receives LEAVE
      assert {:ok, leave_data_a} = receive_packet(relay_a.socket, 1_000)
      assert {:ok, {:relay_leave, sender_a, _ts, _}} = InterRelay.decode(leave_data_a)
      assert sender_a == relay_b.node_id

      # C receives LEAVE
      assert {:ok, leave_data_c} = receive_packet(relay_c.socket, 1_000)
      assert {:ok, {:relay_leave, sender_c, _ts, _}} = InterRelay.decode(leave_data_c)
      assert sender_c == relay_b.node_id

      # Remove B from the ring (simulating the handler)
      ring_after = HashRing.remove_node(ring, relay_b.node_id)
      assert HashRing.node_count(ring_after) == 2
      refute HashRing.member?(ring_after, relay_b.node_id)

      # Sessions that were on B are now redistributed
      session_id = Crypto.generate_session_id()
      [new_owner | _] = HashRing.get_nodes(ring_after, session_id, 1)
      assert new_owner.node_id in [relay_a.node_id, relay_c.node_id]

      stop_relay(relay_a)
      stop_relay(relay_b)
      stop_relay(relay_c)
    end
  end

  # ── 9. Inter-relay message encode/decode roundtrip ──────────

  describe "inter-relay protocol" do
    test "HELLO roundtrip" do
      node_id = :crypto.strong_rand_bytes(16)
      info = %{node_id: node_id, address: {{10, 0, 0, 1}, 23101}, role: :ingress}

      encoded = InterRelay.encode_hello(info)
      assert {:ok, {:relay_hello, ^node_id, _ts, payload}} = InterRelay.decode(encoded)
      assert payload.address == {{10, 0, 0, 1}, 23101}
      assert payload.role == :ingress
    end

    test "HELLO_ACK roundtrip" do
      node_id = :crypto.strong_rand_bytes(16)
      info = %{node_id: node_id, address: {{10, 0, 0, 2}, 23102}, role: :transit}

      encoded = InterRelay.encode_hello_ack(info)
      assert {:ok, {:relay_hello_ack, ^node_id, _ts, payload}} = InterRelay.decode(encoded)
      assert payload.address == {{10, 0, 0, 2}, 23102}
      assert payload.role == :transit
    end

    test "PING/PONG roundtrip" do
      node_id = :crypto.strong_rand_bytes(16)

      ping = InterRelay.encode_ping(node_id)
      assert {:ok, {:relay_ping, ^node_id, _ts, %{}}} = InterRelay.decode(ping)

      metrics = %{active_sessions: 42, max_sessions: 10_000, uptime_seconds: 3600}
      pong = InterRelay.encode_pong(node_id, metrics)
      assert {:ok, {:relay_pong, ^node_id, _ts, pong_payload}} = InterRelay.decode(pong)
      assert pong_payload.active_sessions == 42
      assert pong_payload.max_sessions == 10_000
      assert pong_payload.uptime_seconds == 3600
    end

    test "FORWARD wraps and unwraps ZTLP packets" do
      node_id = :crypto.strong_rand_bytes(16)
      session_id = Crypto.generate_session_id()
      inner = Packet.serialize(Packet.build_data(session_id, 1, payload: "test payload"))

      forward = InterRelay.encode_forward(node_id, inner)

      assert {:ok, {:relay_forward, ^node_id, _ts, %{inner_packet: ^inner}}} =
               InterRelay.decode(forward)

      # Also test unwrap helper
      assert {:ok, ^inner} = InterRelay.unwrap_forward(forward)
    end

    test "SESSION_SYNC roundtrip" do
      node_id = :crypto.strong_rand_bytes(16)
      session_id = Crypto.generate_session_id()

      sync =
        InterRelay.encode_session_sync(node_id, %{
          session_id: session_id,
          peer_a: {{192, 168, 1, 10}, 5000},
          peer_b: {{192, 168, 1, 20}, 6000}
        })

      assert {:ok, {:relay_session_sync, ^node_id, _ts, payload}} = InterRelay.decode(sync)
      assert payload.session_id == session_id
      assert payload.peer_a == {{192, 168, 1, 10}, 5000}
      assert payload.peer_b == {{192, 168, 1, 20}, 6000}
    end

    test "LEAVE roundtrip" do
      node_id = :crypto.strong_rand_bytes(16)
      leave = InterRelay.encode_leave(node_id)
      assert {:ok, {:relay_leave, ^node_id, _ts, %{}}} = InterRelay.decode(leave)
    end

    test "rejects unknown message type" do
      # Build a message with unknown type byte (0xFF)
      node_id = :crypto.strong_rand_bytes(16)
      bad_msg = <<0xFF::8, node_id::binary-size(16), 0::64>>
      assert {:error, :unknown_message_type} = InterRelay.decode(bad_msg)
    end

    test "inter_relay_message?/1 detects inter-relay messages" do
      node_id = :crypto.strong_rand_bytes(16)

      hello =
        InterRelay.encode_hello(%{
          node_id: node_id,
          address: {{127, 0, 0, 1}, 23101},
          role: :all
        })

      assert InterRelay.inter_relay_message?(hello)

      # A ZTLP packet should NOT match
      ztlp = Packet.serialize(Packet.build_data(Crypto.generate_session_id(), 1))
      refute InterRelay.inter_relay_message?(ztlp)
    end
  end

  # ── 10. Hash ring distribution ──────────────────────────────

  describe "hash ring distribution" do
    test "sessions distribute roughly evenly across 3 relays" do
      relays =
        for _ <- 1..3 do
          %{
            node_id: :crypto.strong_rand_bytes(16),
            address: {{127, 0, 0, 1}, Enum.random(10000..60000)}
          }
        end

      ring = HashRing.new(relays)

      # Generate 3000 session IDs and count distribution
      counts =
        for _ <- 1..3000, reduce: %{} do
          acc ->
            sid = Crypto.generate_session_id()
            [owner | _] = HashRing.get_nodes(ring, sid, 1)
            Map.update(acc, owner.node_id, 1, &(&1 + 1))
        end

      # Each relay should get roughly 1000 (±300 is generous)
      for {_nid, count} <- counts do
        assert count > 500, "Each relay should get >500 of 3000 sessions, got #{count}"
        assert count < 1500, "Each relay should get <1500 of 3000 sessions, got #{count}"
      end
    end

    test "adding a relay only moves ~1/N sessions" do
      relays_3 =
        for _ <- 1..3 do
          %{
            node_id: :crypto.strong_rand_bytes(16),
            address: {{127, 0, 0, 1}, Enum.random(10000..60000)}
          }
        end

      ring_3 = HashRing.new(relays_3)

      new_relay = %{
        node_id: :crypto.strong_rand_bytes(16),
        address: {{127, 0, 0, 1}, Enum.random(10000..60000)}
      }

      ring_4 = HashRing.add_node(ring_3, new_relay)

      session_ids = for _ <- 1..1000, do: Crypto.generate_session_id()

      moved =
        Enum.count(session_ids, fn sid ->
          [old | _] = HashRing.get_nodes(ring_3, sid, 1)
          [new | _] = HashRing.get_nodes(ring_4, sid, 1)
          old.node_id != new.node_id
        end)

      # With consistent hashing, ~25% of keys should move (1/4 for 3→4 relays)
      # Allow generous margin: 10-50%
      assert moved > 100, "Too few sessions moved: #{moved}/1000"
      assert moved < 500, "Too many sessions moved: #{moved}/1000"
    end
  end

  # ── 11. Full mesh routing simulation ────────────────────────

  describe "full mesh routing simulation" do
    test "end-to-end: ingress receives, hashes, forwards to owner, owner delivers" do
      # Three relay sockets
      relay_a = start_relay()
      relay_b = start_relay()
      relay_c = start_relay()

      # Two client sockets
      {:ok, client_a_sock} = :gen_udp.open(0, [:binary, {:active, true}, {:ip, {127, 0, 0, 1}}])
      {:ok, client_b_sock} = :gen_udp.open(0, [:binary, {:active, true}, {:ip, {127, 0, 0, 1}}])
      {:ok, client_a_port} = :inet.port(client_a_sock)
      {:ok, client_b_port} = :inet.port(client_b_sock)

      ring = build_ring([relay_a, relay_b, relay_c])
      session_id = Crypto.generate_session_id()

      # Determine owner
      [owner_info | _] = HashRing.get_nodes(ring, session_id, 1)
      owner = Enum.find([relay_a, relay_b, relay_c], &(&1.node_id == owner_info.node_id))
      non_owners = Enum.reject([relay_a, relay_b, relay_c], &(&1.node_id == owner_info.node_id))
      ingress = hd(non_owners)

      # Register session on the owner relay's local session registry
      client_a_addr = {{127, 0, 0, 1}, client_a_port}
      client_b_addr = {{127, 0, 0, 1}, client_b_port}
      SessionRegistry.register_session(session_id, client_a_addr, client_b_addr)

      # Step 1: Client A sends ZTLP data to ingress relay
      inner_raw = send_packet(client_a_sock, ingress.address, session_id, "mesh routed data")
      flush_socket(ingress.socket)

      # Step 2: Ingress wraps in RELAY_FORWARD and sends to owner
      forward_msg = InterRelay.encode_forward(ingress.node_id, inner_raw)
      {o_ip, o_port} = owner.address
      :gen_udp.send(ingress.socket, o_ip, o_port, forward_msg)

      # Step 3: Owner receives the forward, unwraps, and delivers to Client B
      assert {:ok, fwd_raw} = receive_packet(owner.socket, 1_000)
      assert {:ok, inner} = InterRelay.unwrap_forward(fwd_raw)
      assert {:ok, parsed} = Packet.parse(inner)
      assert parsed.session_id == session_id

      # Owner looks up the session and forwards to the other peer
      {:ok, other_peer} = SessionRegistry.lookup_peer(session_id, client_a_addr)
      assert other_peer == client_b_addr

      # Owner sends raw packet to Client B
      {cb_ip, cb_port} = client_b_addr
      :gen_udp.send(owner.socket, cb_ip, cb_port, inner)

      # Client B receives the original packet
      assert {:ok, ^inner} = receive_packet(client_b_sock, 1_000)

      # Cleanup
      SessionRegistry.unregister_session(session_id)
      :gen_udp.close(client_a_sock)
      :gen_udp.close(client_b_sock)
      stop_relay(relay_a)
      stop_relay(relay_b)
      stop_relay(relay_c)
    end
  end

  # ── 12. Relay registry integration ─────────────────────────

  describe "relay registry" do
    setup do
      # Start a dedicated RelayRegistry for these tests.
      # Use a unique name/table to avoid conflicts with the app's registry.
      name = :"relay_reg_test_#{:erlang.unique_integer([:positive])}"
      {:ok, pid} = RelayRegistry.start_link(name: name, sweep_interval_ms: 600_000)

      on_exit(fn ->
        if Process.alive?(pid), do: GenServer.stop(pid)
      end)

      :ok
    end

    test "register, lookup, and unregister relays" do
      node_a = :crypto.strong_rand_bytes(16)
      node_b = :crypto.strong_rand_bytes(16)

      RelayRegistry.register(%{
        node_id: node_a,
        address: {{10, 0, 0, 1}, 23101},
        role: :ingress
      })

      RelayRegistry.register(%{
        node_id: node_b,
        address: {{10, 0, 0, 2}, 23102},
        role: :transit
      })

      assert {:ok, info_a} = RelayRegistry.lookup(node_a)
      assert info_a.address == {{10, 0, 0, 1}, 23101}
      assert info_a.role == :ingress
      assert info_a.status == :active

      assert {:ok, info_b} = RelayRegistry.lookup(node_b)
      assert info_b.role == :transit

      # Cleanup
      RelayRegistry.unregister(node_a)
      RelayRegistry.unregister(node_b)
      assert :error == RelayRegistry.lookup(node_a)
    end

    test "get_by_role filters relays" do
      node_i = :crypto.strong_rand_bytes(16)
      node_t = :crypto.strong_rand_bytes(16)
      node_a = :crypto.strong_rand_bytes(16)

      RelayRegistry.register(%{node_id: node_i, address: {{10, 0, 0, 1}, 23101}, role: :ingress})
      RelayRegistry.register(%{node_id: node_t, address: {{10, 0, 0, 2}, 23102}, role: :transit})
      RelayRegistry.register(%{node_id: node_a, address: {{10, 0, 0, 3}, 23103}, role: :all})

      ingress_relays = RelayRegistry.get_by_role(:ingress)
      ingress_ids = Enum.map(ingress_relays, & &1.node_id)
      assert node_i in ingress_ids
      # :all matches any role
      assert node_a in ingress_ids
      refute node_t in ingress_ids

      # Cleanup
      RelayRegistry.unregister(node_i)
      RelayRegistry.unregister(node_t)
      RelayRegistry.unregister(node_a)
    end

    test "update_metrics refreshes last_seen" do
      node_id = :crypto.strong_rand_bytes(16)

      RelayRegistry.register(%{
        node_id: node_id,
        address: {{10, 0, 0, 1}, 23101},
        role: :all
      })

      {:ok, before_info} = RelayRegistry.lookup(node_id)
      # 50ms sleep to ensure monotonic_time(:millisecond) advances on busy CI runners
      Process.sleep(50)

      RelayRegistry.update_metrics(node_id, %{rtt_ms: 42})

      {:ok, after_update} = RelayRegistry.lookup(node_id)
      assert after_update.last_seen > before_info.last_seen
      assert after_update.metrics == %{rtt_ms: 42}
      assert after_update.status == :active

      RelayRegistry.unregister(node_id)
    end
  end
end
