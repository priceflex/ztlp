defmodule ZtlpRelay.UdpListenerTest do
  use ExUnit.Case

  alias ZtlpRelay.{UdpListener, Packet, SessionRegistry, Stats}

  setup do
    Stats.reset()
    :ok
  end

  describe "listener" do
    test "is running and has a port" do
      port = UdpListener.get_port()
      assert is_integer(port)
      assert port > 0
    end

    test "has a valid socket" do
      socket = UdpListener.get_socket()
      assert socket != nil
    end
  end

  describe "packet handling" do
    test "drops non-ZTLP traffic" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])

      :gen_udp.send(client, {127, 0, 0, 1}, port, <<0xDE, 0xAD, 0xBE, 0xEF>>)
      Process.sleep(50)

      stats = Stats.get_stats()
      assert stats.layer1_drops >= 1

      :gen_udp.close(client)
    end

    test "drops data packet with unknown session" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])

      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(session_id, 0)
      raw = Packet.serialize(pkt)

      :gen_udp.send(client, {127, 0, 0, 1}, port, raw)
      Process.sleep(50)

      stats = Stats.get_stats()
      assert stats.layer2_drops >= 1

      :gen_udp.close(client)
    end

    test "accepts HELLO messages" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])

      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize(pkt)

      :gen_udp.send(client, {127, 0, 0, 1}, port, raw)
      Process.sleep(50)

      stats = Stats.get_stats()
      assert stats.passed >= 1

      :gen_udp.close(client)
    end

    test "forwards packets between registered peers" do
      port = UdpListener.get_port()

      # Create two client sockets (peers)
      {:ok, client_a} = :gen_udp.open(0, [:binary, {:active, true}])
      {:ok, client_b} = :gen_udp.open(0, [:binary, {:active, true}])

      {:ok, port_a} = :inet.port(client_a)
      {:ok, port_b} = :inet.port(client_b)

      peer_a = {{127, 0, 0, 1}, port_a}
      peer_b = {{127, 0, 0, 1}, port_b}

      # Register a session
      session_id = :crypto.strong_rand_bytes(12)
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      # Send a data packet from peer A to relay
      pkt = Packet.build_data(session_id, 1)
      raw = Packet.serialize(pkt)
      :gen_udp.send(client_a, {127, 0, 0, 1}, port, raw)

      # Peer B should receive the forwarded packet
      assert_receive {:udp, ^client_b, {127, 0, 0, 1}, ^port, ^raw}, 1_000

      # Send from peer B to relay
      pkt2 = Packet.build_data(session_id, 2)
      raw2 = Packet.serialize(pkt2)
      :gen_udp.send(client_b, {127, 0, 0, 1}, port, raw2)

      # Peer A should receive the forwarded packet
      assert_receive {:udp, ^client_a, {127, 0, 0, 1}, ^port, ^raw2}, 1_000

      # Stats updates are async — allow time for counter to propagate
      Process.sleep(50)
      stats = Stats.get_stats()
      assert stats.forwarded >= 2

      # Cleanup
      SessionRegistry.unregister_session(session_id)
      :gen_udp.close(client_a)
      :gen_udp.close(client_b)
    end
  end

  describe "CLIENT_ROUTE (FRAME_CLIENT_ROUTE 0x5A 0x37 0x0B)" do
    # Build a CLIENT_ROUTE packet matching the wire format documented in
    # proto/src/bin/ztlp-cli.rs (constants CLIENT_ROUTE_*).
    #
    # Layout: 0x5A 0x37 0x0B | 16 node_id | 1 svc_len | svc_len service |
    #         8 timestamp (i64 BE) | 32 hmac
    defp build_client_route(node_id, service_name, timestamp, hmac) do
      svc_len = byte_size(service_name)
      <<0x5A, 0x37, 0x0B, node_id::binary-size(16), svc_len::8,
        service_name::binary-size(svc_len), timestamp::64-signed,
        hmac::binary-size(32)>>
    end

    setup do
      # The QUIC tuple table is normally created lazily on first GATEWAY_REGISTER
      # or CLIENT_ROUTE. Make sure each test starts from a clean state.
      if :ets.info(:ztlp_forwarded_quic_tuples, :name) != :undefined do
        :ets.delete_all_objects(:ztlp_forwarded_quic_tuples)
      end

      # Make sure the GatewayForwarder is up; some test orderings race the app
      # startup.
      case GenServer.whereis(ZtlpRelay.GatewayForwarder) do
        nil -> {:ok, _pid} = ZtlpRelay.GatewayForwarder.start_link()
        _pid -> :ok
      end

      ZtlpRelay.GatewayForwarder.clear_all()
      :ok
    end

    test "installs client→gateway 5-tuple mapping for a registered service" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      # Register a fake gateway for the target service
      gw_node_id = :crypto.strong_rand_bytes(16)
      gw_addr = {{10, 0, 0, 99}, 23097}
      service_name = "gw-route-test"
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(gw_addr, gw_node_id, service_name, 60)
      Process.sleep(20) # cast is async

      # Send the CLIENT_ROUTE packet
      client_node_id = :crypto.strong_rand_bytes(16)
      ts = System.system_time(:second)
      pkt = build_client_route(client_node_id, service_name, ts, <<0::256>>)

      :gen_udp.send(client, {127, 0, 0, 1}, port, pkt)
      Process.sleep(50)

      # ETS mapping should now exist
      assert :ets.info(:ztlp_forwarded_quic_tuples, :name) != :undefined

      # v0.29.3: ETS value is `{gw_addr, inserted_at_ms}` (was bare `gw_addr`).
      assert [{{:client_map, ^sender}, {^gw_addr, inserted_at}}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})

      assert is_integer(inserted_at)

      :gen_udp.close(client)
    end

    test "rejects CLIENT_ROUTE for an unregistered service (no ETS write)" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      ts = System.system_time(:second)
      pkt = build_client_route(:crypto.strong_rand_bytes(16), "gw-does-not-exist", ts, <<0::256>>)

      :gen_udp.send(client, {127, 0, 0, 1}, port, pkt)
      Process.sleep(50)

      # No client_map entry should have been written
      lookup_result =
        if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
          []
        else
          :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})
        end

      assert lookup_result == []

      :gen_udp.close(client)
    end

    test "rejects CLIENT_ROUTE with malformed (zero-length) service name" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      # Hand-craft a packet with svc_len=0 to bypass build_client_route guards.
      bad =
        <<0x5A, 0x37, 0x0B, 0::128, 0::8, 0::64, 0::256>>

      :gen_udp.send(client, {127, 0, 0, 1}, port, bad)
      Process.sleep(50)

      lookup_result =
        if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
          []
        else
          :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})
        end

      assert lookup_result == []

      :gen_udp.close(client)
    end

    # ------------------------------------------------------------------
    # v0.29.3 regression tests for the α-relay handshake-flakiness fix
    # ------------------------------------------------------------------
    #
    # Background: prior to v0.29.3, every `ztlp connect` from the same
    # client host installed a new {:client_map, {ip, ephem_port}} entry
    # WITHOUT removing the prior entry. The reverse-forward path used
    # `:ets.match_object` + `[head|_]`, which returns hits in arbitrary
    # ETS hash-bucket order. Gateway-→-client responses got routed to
    # dead ephemeral ports under load, producing the documented
    # "error: connection error: timed out after CLIENT_ROUTE sent"
    # flakiness with ~1/N success rate where N is the number of stale
    # entries.
    #
    # These tests pin down the three guarantees the fix establishes:
    #   1. A new CLIENT_ROUTE from the same client IP to the same gateway
    #      purges prior {:client_map, _} entries from that (IP, gw) pair.
    #   2. Concurrent tunnels from the same client IP to DIFFERENT gateways
    #      remain intact (no over-eager cleanup).
    #   3. The periodic sweeper removes {:client_map, _} entries whose
    #      `inserted_at` is older than the TTL.

    test "v0.29.3: new CLIENT_ROUTE purges prior entries from same client_ip → same gateway" do
      port = UdpListener.get_port()
      gw_node_id = :crypto.strong_rand_bytes(16)
      gw_addr = {{10, 0, 0, 99}, 23097}
      service_name = "gw-purge-test"
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(gw_addr, gw_node_id, service_name, 60)
      Process.sleep(20)

      # First CLIENT_ROUTE from ephemeral port A
      {:ok, client_a} = :gen_udp.open(0, [:binary])
      {:ok, port_a} = :inet.port(client_a)
      sender_a = {{127, 0, 0, 1}, port_a}
      ts = System.system_time(:second)
      pkt_a = build_client_route(:crypto.strong_rand_bytes(16), service_name, ts, <<0::256>>)
      :gen_udp.send(client_a, {127, 0, 0, 1}, port, pkt_a)
      Process.sleep(50)

      assert [{{:client_map, ^sender_a}, {^gw_addr, _}}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender_a})

      # Second CLIENT_ROUTE from a DIFFERENT ephemeral port — simulates the
      # user's next `ztlp connect` invocation. The first entry MUST be gone
      # (or at least one of {sender_a, sender_b} must remain — the fix only
      # purges entries that are different from the current sender).
      {:ok, client_b} = :gen_udp.open(0, [:binary])
      {:ok, port_b} = :inet.port(client_b)
      sender_b = {{127, 0, 0, 1}, port_b}
      pkt_b = build_client_route(:crypto.strong_rand_bytes(16), service_name, ts, <<0::256>>)
      :gen_udp.send(client_b, {127, 0, 0, 1}, port, pkt_b)
      Process.sleep(50)

      # Only the most-recent sender's entry survives.
      all_entries = :ets.match_object(:ztlp_forwarded_quic_tuples, {{:client_map, :_}, :_})

      assert Enum.any?(all_entries, fn
               {{:client_map, ^sender_b}, _} -> true
               _ -> false
             end),
             "fresh sender_b mapping should be present"

      refute Enum.any?(all_entries, fn
               {{:client_map, ^sender_a}, _} -> true
               _ -> false
             end),
             "stale sender_a mapping should have been purged"

      :gen_udp.close(client_a)
      :gen_udp.close(client_b)
    end

    test "v0.29.3: CLIENT_ROUTE to DIFFERENT gateway does NOT purge same-IP entries" do
      port = UdpListener.get_port()

      # Two distinct gateways
      gw1 = {{10, 0, 0, 99}, 23097}
      gw2 = {{10, 0, 0, 100}, 23097}
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(gw1, :crypto.strong_rand_bytes(16), "gw-keep-1", 60)
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(gw2, :crypto.strong_rand_bytes(16), "gw-keep-2", 60)
      Process.sleep(20)

      ts = System.system_time(:second)

      {:ok, client_a} = :gen_udp.open(0, [:binary])
      {:ok, port_a} = :inet.port(client_a)
      sender_a = {{127, 0, 0, 1}, port_a}
      pkt_a = build_client_route(:crypto.strong_rand_bytes(16), "gw-keep-1", ts, <<0::256>>)
      :gen_udp.send(client_a, {127, 0, 0, 1}, port, pkt_a)
      Process.sleep(50)

      {:ok, client_b} = :gen_udp.open(0, [:binary])
      {:ok, port_b} = :inet.port(client_b)
      sender_b = {{127, 0, 0, 1}, port_b}
      pkt_b = build_client_route(:crypto.strong_rand_bytes(16), "gw-keep-2", ts, <<0::256>>)
      :gen_udp.send(client_b, {127, 0, 0, 1}, port, pkt_b)
      Process.sleep(50)

      # Both entries should still be present — different gateways.
      assert [{{:client_map, ^sender_a}, {^gw1, _}}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender_a})

      assert [{{:client_map, ^sender_b}, {^gw2, _}}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender_b})

      :gen_udp.close(client_a)
      :gen_udp.close(client_b)
    end

    test "v0.29.3: periodic sweeper purges entries older than TTL" do
      # We can't easily wait the full 5-minute TTL, so we plant entries with a
      # very-old `inserted_at` directly into ETS and trigger the sweep handler
      # by sending the message that the timer would have sent.
      #
      # The setup block already ensures the table exists (lazily created on
      # GATEWAY_REGISTER / CLIENT_ROUTE) and is empty.
      if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
        :ets.new(:ztlp_forwarded_quic_tuples, [
          :named_table,
          :public,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])
      end

      :ets.delete_all_objects(:ztlp_forwarded_quic_tuples)

      old = System.monotonic_time(:millisecond) - 10 * 60 * 1_000
      fresh = System.monotonic_time(:millisecond)
      gw = {{10, 0, 0, 1}, 23097}
      stale_key = {:client_map, {{127, 0, 0, 1}, 60_001}}
      fresh_key = {:client_map, {{127, 0, 0, 1}, 60_002}}

      :ets.insert(:ztlp_forwarded_quic_tuples, {stale_key, {gw, old}})
      :ets.insert(:ztlp_forwarded_quic_tuples, {fresh_key, {gw, fresh}})

      # Trigger the sweep handler directly.
      send(ZtlpRelay.UdpListener, :sweep_client_routes)

      # Sweep runs as a regular handle_info on the listener GenServer. Poll
      # until the old entry is gone (up to ~1s) so the test isn't dependent
      # on scheduler timing.
      Enum.reduce_while(1..50, nil, fn _, _ ->
        case :ets.lookup(:ztlp_forwarded_quic_tuples, stale_key) do
          [] -> {:halt, :gone}
          _ -> Process.sleep(20); {:cont, nil}
        end
      end)

      assert :ets.lookup(:ztlp_forwarded_quic_tuples, stale_key) == [],
             "old entry should have been swept"

      assert [{^fresh_key, {^gw, ^fresh}}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, fresh_key)
    end

    test "v0.29.3: forwarded packets refresh inserted_at (touch) so active tunnels survive sweeps" do
      # Spin up a tenant gateway + send one CLIENT_ROUTE so an entry exists.
      port = UdpListener.get_port()
      gw_node_id = :crypto.strong_rand_bytes(16)
      gw_addr = {{10, 0, 0, 42}, 23097}
      service_name = "gw-touch-test"
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(gw_addr, gw_node_id, service_name, 60)
      Process.sleep(20)

      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      ts = System.system_time(:second)
      pkt = build_client_route(:crypto.strong_rand_bytes(16), service_name, ts, <<0::256>>)
      :gen_udp.send(client, {127, 0, 0, 1}, port, pkt)
      Process.sleep(50)

      [{_, {_, inserted_at_initial}}] =
        :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})

      assert is_integer(inserted_at_initial)

      # Sleep a few milliseconds, then send an opaque data packet that should
      # be matched by the forward arm and trigger the touch. Use a byte
      # pattern that does NOT start with the ZTLP control-frame magic so the
      # forward arm fires (any non-`0x5A 0x37 *` payload is fine).
      Process.sleep(20)
      :gen_udp.send(client, {127, 0, 0, 1}, port, <<0xC0, 1, 2, 3, 4, 5, 6, 7, 8>>)
      Process.sleep(50)

      [{_, {_, inserted_at_after}}] =
        :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})

      assert inserted_at_after > inserted_at_initial,
             "forward arm should have refreshed inserted_at to keep the entry alive"

      :gen_udp.close(client)
    end

    # ------------------------------------------------------------------
    # NodeID fallback for CLIENT_ROUTE service-name mismatch
    # ------------------------------------------------------------------
    #
    # Background (Casita Village Dental BILLING-COMPUTER, 2026-06-11):
    # A remote-site, symmetric-NAT'd endpoint can ONLY be reached via relay
    # forwarding. Its gateway registers under its Z2LS service-name
    # (e.g. "z2ls-bill-008247"), and the operator dials it with a generic
    # `--service ssh`. The QUIC fast-path sends a CLIENT_ROUTE whose
    # service-name field is the literal "ssh" but whose 16-byte node_id IS
    # the NS-resolved gateway NodeID.
    #
    # Before this fix, `do_install_client_route/3` looked the gateway up
    # SOLELY by the service-name string ("ssh") and rejected the route
    # ("no gateway registered for service=ssh"), so the tunnel never
    # established. The HELLO/`dst_svc_id` path already matches by NodeID
    # (GatewayForwarder.pick_gateway_for_service/1 NodeID tier); the
    # CLIENT_ROUTE path must do the same: when the service-name lookup
    # misses, fall back to the parsed node_id (16 bytes → NodeID tier).
    #
    # This also covers the 16-char service-name collision: a name that is
    # exactly 16 bytes ("z2ls-bill-008247") is indistinguishable from a raw
    # NodeID/hash binary in pick_gateway_for_service/1, so name-string
    # matching is unreliable for these registrations — NodeID is the only
    # robust key.
    test "installs route via parsed NodeID when CLIENT_ROUTE service-name does not match (billing remote-site case)" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      # Gateway registers under its Z2LS service-name with a known NodeID.
      gw_node_id = :crypto.strong_rand_bytes(16)
      gw_addr = {{174, 79, 254, 16}, 23095}
      registered_service = "z2ls-bill-008247"
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(gw_addr, gw_node_id, registered_service, 60)
      Process.sleep(20)

      # Operator dials `--service ssh` → CLIENT_ROUTE carries service="ssh"
      # but node_id = the registered gateway's NodeID.
      ts = System.system_time(:second)
      pkt = build_client_route(gw_node_id, "ssh", ts, <<0::256>>)
      :gen_udp.send(client, {127, 0, 0, 1}, port, pkt)
      Process.sleep(50)

      assert [{{:client_map, ^sender}, {^gw_addr, inserted_at}}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender}),
             "CLIENT_ROUTE with a mismatched service-name but a valid registered " <>
               "NodeID must install the route via the NodeID fallback"

      assert is_integer(inserted_at)

      :gen_udp.close(client)
    end

    test "NodeID fallback does NOT route when neither service-name nor NodeID match (no cross-tenant leak)" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      # A registered gateway exists, but the CLIENT_ROUTE carries an
      # UNKNOWN NodeID and an unknown service-name. Must reject — no
      # silent round-robin onto the wrong tenant.
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(
        {{10, 9, 9, 9}, 23095},
        :crypto.strong_rand_bytes(16),
        "z2ls-other-tenant",
        60
      )

      Process.sleep(20)

      ts = System.system_time(:second)
      pkt = build_client_route(:crypto.strong_rand_bytes(16), "ssh", ts, <<0::256>>)
      :gen_udp.send(client, {127, 0, 0, 1}, port, pkt)
      Process.sleep(50)

      lookup_result =
        if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
          []
        else
          :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})
        end

      assert lookup_result == [],
             "unknown NodeID + unknown service must NOT install any route"

      :gen_udp.close(client)
    end
  end
end
