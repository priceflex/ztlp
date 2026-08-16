defmodule ZtlpRelay.HeartbeatAfterSessionTest do
  @moduledoc """
  Regression test for the gateway-heartbeat hijack bug discovered 2026-05-28
  during the v0.34.0 end-to-end walkthrough.

  ## Symptom (production)

  After a v0.34.0 client successfully connects through a v0.34.0 relay to a
  v0.34.0 gateway:

    1. First contact: gateway sends `GATEWAY_REGISTER` (V1 0x0A or V2 0x0E).
       Relay logs `[GatewayForwarder] Registered dynamic gateway ...`. ✓
    2. Client connects: HELLO is forwarded to gateway, gateway responds with
       HELLO_ACK. Relay's `register_forwarded_session/3` writes the
       `{gateway_addr → session_id, client_addr}` entry into the
       `@peer_table` ETS so post-handshake Noise transport packets can be
       blind-forwarded by 5-tuple match. ✓
    3. Gateway sends its next 10 s heartbeat from the SAME `{gw_ip, gw_port}`.
    4. `UdpListener.handle_info({:udp, ...})` calls `lookup_by_peer/1` FIRST,
       before any control-frame magic check. The heartbeat's source 5-tuple
       matches the peer-table entry from step 2, so the listener treats the
       heartbeat as Noise transport data and forwards it to the client. ✗
    5. The control-frame branch is never reached → `register_dynamic_gateway`
       never fires → the registration's 60 s TTL expires → CLIENT_ROUTE from
       new clients is rejected with `no gateway registered`. ✗

  ## Root cause

  `udp_listener.ex:126-136` — the data-forwarder fast path is gated on the
  sender being a known peer, but does not first reject ZTLP control frames
  (magic `0x5A 0x37`). The QUIC-bypass branch immediately below it (line 208)
  DOES have that protection; this branch missed it.

  ## What this test pins

  After installing a forwarded session whose gateway side is `{127,0,0,1, P}`,
  sending a GATEWAY_REGISTER from that same `{127,0,0,1, P}` must still reach
  `GatewayForwarder.register_dynamic_gateway/4`. The peer-table entry must
  NOT swallow it.
  """

  use ExUnit.Case, async: false

  alias ZtlpRelay.{UdpListener, GatewayForwarder}

  setup do
    # [gpq-xvfw regression fix] ZTLP_RELAY_HMAC_MODE now defaults to
    # :prod (fail-closed) as of the gpq-xvfw security fix — this test
    # is about the heartbeat/data-forwarder interaction, not HMAC
    # verification, so explicitly opt into :dev mode (unsigned frames
    # accepted) to match this file's original intent, matching the
    # "HMAC field is ignored" comment on build_v1_gateway_register/4
    # below.
    prev_mode = System.get_env("ZTLP_RELAY_HMAC_MODE")
    System.put_env("ZTLP_RELAY_HMAC_MODE", "dev")

    on_exit(fn ->
      if prev_mode do
        System.put_env("ZTLP_RELAY_HMAC_MODE", prev_mode)
      else
        System.delete_env("ZTLP_RELAY_HMAC_MODE")
      end
    end)

    # GatewayForwarder is started by the app supervisor; reuse it.
    GatewayForwarder.clear_all()

    on_exit(fn ->
      try do
        GatewayForwarder.clear_all()
      catch
        :exit, _ -> :ok
      end
    end)

    :ok
  end

  defp build_v1_gateway_register(node_id, service_name, ttl, timestamp) do
    # Pad/truncate service to 16 bytes.
    name = String.slice(service_name, 0, 16)
    pad_bits = (16 - byte_size(name)) * 8
    service_bytes = <<name::binary, 0::size(pad_bits)>>

    # In dev mode (default in tests) the HMAC field is ignored; zero it.
    hmac = <<0::256>>

    <<0x5A, 0x37, 0x0A, node_id::binary, service_bytes::binary, ttl::32, timestamp::64,
      hmac::binary>>
  end

  describe "gateway heartbeat after a forwarded session is registered" do
    test "GATEWAY_REGISTER from a known peer 5-tuple is not swallowed by the data-forwarder" do
      relay_port = UdpListener.get_port()
      assert is_integer(relay_port) and relay_port > 0

      # Open a socket that will play BOTH roles needed for the repro:
      #   • Pretend to be the gateway: send GATEWAY_REGISTER from this 5-tuple.
      #   • We don't actually need a real client socket — we just plant an
      #     entry in the peer table claiming this 5-tuple is the gateway side
      #     of an existing forwarded session.
      {:ok, gw_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, gw_port} = :inet.port(gw_socket)
      gateway_addr = {{127, 0, 0, 1}, gw_port}

      # And a fake "client" peer address — doesn't have to be live, the bug
      # manifests by the listener trying to forward the heartbeat to it.
      client_addr = {{127, 0, 0, 1}, 65501}

      # Plant the forwarded-session entry the way HELLO/HELLO_ACK forwarding
      # would. After this, `lookup_by_peer({127.0.0.1, gw_port})` returns
      # `{:ok, _, client_addr}` — the trigger for the bug.
      session_id = :crypto.strong_rand_bytes(12)
      GatewayForwarder.register_forwarded_session(session_id, client_addr, gateway_addr)
      Process.sleep(20)

      assert {:ok, ^session_id, ^client_addr} =
               GatewayForwarder.lookup_by_peer(gateway_addr),
             "precondition: peer table must contain the forwarded session"

      # Now send a GATEWAY_REGISTER from the gateway 5-tuple. With the bug,
      # the listener forwards this to client_addr and never registers the
      # gateway. With the fix, it routes to handle_gateway_register/2.
      node_id = :crypto.strong_rand_bytes(16)
      service_name = "gw:trs.ztlp"
      ttl = 60
      timestamp = System.system_time(:second)
      packet = build_v1_gateway_register(node_id, service_name, ttl, timestamp)

      :ok = :gen_udp.send(gw_socket, {127, 0, 0, 1}, relay_port, packet)

      # Give the listener time to process. Registration is via a cast.
      Process.sleep(100)

      dynamic = GatewayForwarder.dynamic_gateways()
      hit = Enum.find(dynamic, fn gw -> gw.node_id == node_id end)

      assert hit != nil,
             "GATEWAY_REGISTER from a known peer 5-tuple must be processed, " <>
               "not forwarded as opaque data. dynamic_gateways=#{inspect(dynamic)}"

      assert hit.service_name == service_name
      assert hit.address == gateway_addr

      :gen_udp.close(gw_socket)
    end

    test "CLIENT_ROUTE from a known peer 5-tuple is not swallowed either" do
      # Belt-and-braces: the bug applies to every ZTLP control frame, not
      # just GATEWAY_REGISTER. CLIENT_ROUTE (0x0B) is the other one the
      # production system relies on. This test pins the contract for the
      # whole 0x5A 0x37 0xXX frame family.
      relay_port = UdpListener.get_port()

      {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, src_port} = :inet.port(sock)
      src_addr = {{127, 0, 0, 1}, src_port}
      peer_addr = {{127, 0, 0, 1}, 65502}

      # Plant a peer-table entry so lookup_by_peer hits for src_addr.
      session_id = :crypto.strong_rand_bytes(12)
      GatewayForwarder.register_forwarded_session(session_id, peer_addr, src_addr)
      Process.sleep(20)

      # Build a deliberately malformed CLIENT_ROUTE (just the magic+type
      # plus a few bytes) — we only care that the listener attempts to
      # PARSE it (i.e. routes to handle_client_route/3), not that the parse
      # succeeds. The parse failure will log a warning; the data-forwarder
      # hijack would silently send it to peer_addr instead.
      bogus_client_route = <<0x5A, 0x37, 0x0B, 0::8>>

      # Capture log output to verify the listener tried to parse it.
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          :ok = :gen_udp.send(sock, {127, 0, 0, 1}, relay_port, bogus_client_route)
          Process.sleep(100)
        end)

      assert log =~ "CLIENT_ROUTE",
             "Listener must attempt to parse the CLIENT_ROUTE frame, not " <>
               "blind-forward it. log=#{inspect(log)}"

      :gen_udp.close(sock)
    end
  end
end
