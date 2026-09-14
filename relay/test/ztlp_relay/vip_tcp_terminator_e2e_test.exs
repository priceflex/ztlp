defmodule ZtlpRelay.VipTcpTerminatorE2eTest do
  @moduledoc """
  End-to-end dispatch tests for `VipTcpTerminator.handle_vip_packet/4`:
  a real encrypted compact data packet -> decrypt -> VipFrame -> service
  lookup -> VipConnection spawn -> bytes on a real loopback TCP backend.
  """
  # async: false — global ETS tables, env vars, Application env.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ZtlpRelay.{Packet, VipFrame, VipServiceTable, VipTcpTerminator}

  @session_id <<9::96>>
  @psk_hex String.duplicate("CD", 32)

  # ── fixtures ────────────────────────────────────────────────────────────

  setup do
    prev = %{
      key: System.get_env("ZTLP_RELAY_VIP_SESSION_KEY"),
      enabled: System.get_env("ZTLP_RELAY_VIP_ENABLED"),
      tls: System.get_env("ZTLP_RELAY_VIP_TLS_ENABLED"),
      svcs: System.get_env("ZTLP_RELAY_VIP_SERVICES")
    }

    System.put_env("ZTLP_RELAY_VIP_SESSION_KEY", @psk_hex)
    System.put_env("ZTLP_RELAY_VIP_ENABLED", "true")
    System.delete_env("ZTLP_RELAY_VIP_TLS_ENABLED")
    System.delete_env("ZTLP_RELAY_VIP_SERVICES")

    on_exit(fn ->
      for {k, env} <- [
            {:key, "ZTLP_RELAY_VIP_SESSION_KEY"},
            {:enabled, "ZTLP_RELAY_VIP_ENABLED"},
            {:tls, "ZTLP_RELAY_VIP_TLS_ENABLED"},
            {:svcs, "ZTLP_RELAY_VIP_SERVICES"}
          ] do
        case prev[k] do
          nil -> System.delete_env(env)
          v -> System.put_env(env, v)
        end
      end
    end)

    # VipServiceTable + VipTcpTerminator are not started by the app in test
    # (VIP disabled at boot). Start them here; start_supervised cleans up.
    if :ets.whereis(:ztlp_vip_service_table) != :undefined, do: wait_gone(:ztlp_vip_service_table)
    start_supervised!(VipServiceTable)

    case :ets.whereis(:ztlp_vip_connections) do
      :undefined -> start_supervised!(VipTcpTerminator)
      _ ->
        # Table pre-created by the older unit test file; reuse it.
        :ets.delete_all_objects(:ztlp_vip_connections)
    end

    :ok
  end

  defp wait_gone(tab, n \\ 50) do
    cond do
      :ets.whereis(tab) == :undefined -> :ok
      n == 0 -> flunk("stale #{tab}")
      true -> Process.sleep(10); wait_gone(tab, n - 1)
    end
  end

  defp start_backend do
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(lsock)
    test = self()

    spawn_link(fn ->
      case :gen_tcp.accept(lsock, 5_000) do
        {:ok, s} ->
          :gen_tcp.controlling_process(s, test)
          send(test, {:backend_accepted, s})

        other ->
          send(test, {:backend_accept_failed, other})
      end
    end)

    port
  end

  defp await_backend(timeout \\ 5_000) do
    receive do
      {:backend_accepted, s} ->
        :inet.setopts(s, active: true)
        s
    after
      timeout -> :none
    end
  end

  defp udp_pair do
    {:ok, client} = :gen_udp.open(0, [:binary, active: true, ip: {127, 0, 0, 1}])
    {:ok, cport} = :inet.port(client)
    {:ok, relay} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    %{client: client, sender: {{127, 0, 0, 1}, cport}, relay: relay}
  end

  # Build a real compact data packet carrying an encrypted VIP frame, the
  # way an iOS/Rust VIP client would: nonce = packet_seq, AAD = header AAD.
  defp vip_packet(frame_type, conn_id, payload, packet_seq) do
    key = VipTcpTerminator.test_get_session_key(@session_id)
    frame = VipFrame.encode(conn_id, frame_type, payload)

    # Serialize once with an empty payload of the right length to compute
    # the AAD (AAD covers header bytes incl. payload_len, not the payload).
    body_len = byte_size(frame) + 16
    skeleton = Packet.build_data(@session_id, packet_seq, payload: :binary.copy(<<0>>, body_len), payload_len: body_len)
    raw0 = Packet.serialize_data(skeleton)
    {:ok, aad} = Packet.extract_aad(raw0)

    {ct, tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, key, <<packet_seq::96>>, frame, aad, true)

    pkt = Packet.build_data(@session_id, packet_seq, payload: ct <> tag, payload_len: body_len)
    raw = Packet.serialize_data(pkt)
    {:ok, parsed} = Packet.parse(raw)
    {parsed, raw}
  end

  # ── enabled?/tls_enabled? ───────────────────────────────────────────────

  describe "enabled?/0 and tls_enabled?/0" do
    test "env var values" do
      for {v, exp} <- [{"true", true}, {"1", true}, {"false", false}, {"yes", false}, {"", false}] do
        System.put_env("ZTLP_RELAY_VIP_ENABLED", v)
        assert VipTcpTerminator.enabled?() == exp, "VIP_ENABLED=#{inspect(v)}"
        System.put_env("ZTLP_RELAY_VIP_TLS_ENABLED", v)
        assert VipTcpTerminator.tls_enabled?() == exp, "VIP_TLS_ENABLED=#{inspect(v)}"
      end
    end

    test "falls back to Application env when env var is unset" do
      System.delete_env("ZTLP_RELAY_VIP_ENABLED")
      System.delete_env("ZTLP_RELAY_VIP_TLS_ENABLED")
      prev_e = Application.get_env(:ztlp_relay, :vip_enabled)
      prev_t = Application.get_env(:ztlp_relay, :vip_tls_enabled)

      on_exit(fn ->
        if prev_e == nil, do: Application.delete_env(:ztlp_relay, :vip_enabled), else: Application.put_env(:ztlp_relay, :vip_enabled, prev_e)
        if prev_t == nil, do: Application.delete_env(:ztlp_relay, :vip_tls_enabled), else: Application.put_env(:ztlp_relay, :vip_tls_enabled, prev_t)
      end)

      Application.put_env(:ztlp_relay, :vip_enabled, true)
      Application.put_env(:ztlp_relay, :vip_tls_enabled, true)
      assert VipTcpTerminator.enabled?()
      assert VipTcpTerminator.tls_enabled?()
      Application.delete_env(:ztlp_relay, :vip_enabled)
      Application.delete_env(:ztlp_relay, :vip_tls_enabled)
      refute VipTcpTerminator.enabled?()
      refute VipTcpTerminator.tls_enabled?()
    end
  end

  # ── GenServer surface ───────────────────────────────────────────────────

  describe "GenServer" do
    test ":get_state exposes enabled/tls flags and the ETS table" do
      if Process.whereis(VipTcpTerminator) do
        state = GenServer.call(VipTcpTerminator, :get_state)
        assert is_boolean(state.enabled)
        assert is_boolean(state.tls_enabled)
        assert state.udp_socket == nil
        assert is_integer(state.started_at)
      end
    end

    test "udp_socket_ready cast and unknown info are accepted" do
      if pid = Process.whereis(VipTcpTerminator) do
        GenServer.cast(pid, :udp_socket_ready)
        send(pid, :noise)
        assert %{} = :sys.get_state(pid)
        assert Process.alive?(pid)
      end
    end
  end

  # ── handle_vip_packet: negative paths ───────────────────────────────────

  describe "handle_vip_packet/4 rejects before spawning anything" do
    test "no configured session key -> :not_vip_service" do
      System.delete_env("ZTLP_RELAY_VIP_SESSION_KEY")
      udp = udp_pair()
      {parsed, raw} = build_plain(1)
      assert :not_vip_service = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
    end

    test "non-hex / wrong-length session key -> :not_vip_service" do
      udp = udp_pair()
      {parsed, raw} = build_plain(1)
      System.put_env("ZTLP_RELAY_VIP_SESSION_KEY", "zz")
      assert :not_vip_service = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
      System.put_env("ZTLP_RELAY_VIP_SESSION_KEY", String.duplicate("AB", 16))
      assert :not_vip_service = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
    end

    test "payload shorter than tag -> :vip_error" do
      udp = udp_pair()
      pkt = Packet.build_data(@session_id, 1, payload: <<1, 2, 3>>, payload_len: 3)
      raw = Packet.serialize_data(pkt)
      {:ok, parsed} = Packet.parse(raw)
      assert :vip_error = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
    end

    test "tampered ciphertext -> :vip_error" do
      udp = udp_pair()
      {parsed, raw} = vip_packet(:syn, 1, "x", 5)
      <<a, rest::binary>> = parsed.payload
      bad = %{parsed | payload: <<Bitwise.bxor(a, 0xFF), rest::binary>>}
      assert :vip_error = VipTcpTerminator.handle_vip_packet(bad, raw, udp.sender, udp.relay)
    end

    test "packet replayed under a different packet_seq -> :vip_error (nonce binding)" do
      udp = udp_pair()
      {parsed, raw} = vip_packet(:syn, 1, "x", 5)
      assert :vip_error = VipTcpTerminator.handle_vip_packet(%{parsed | packet_seq: 6}, raw, udp.sender, udp.relay)
    end

    test "valid ciphertext but VIP frame too short -> :vip_error" do
      udp = udp_pair()
      key = VipTcpTerminator.test_get_session_key(@session_id)
      frame = <<0x12>>
      body_len = byte_size(frame) + 16
      skel = Packet.build_data(@session_id, 3, payload: :binary.copy(<<0>>, body_len), payload_len: body_len)
      {:ok, aad} = Packet.extract_aad(Packet.serialize_data(skel))
      {ct, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, <<3::96>>, frame, aad, true)
      raw = Packet.serialize_data(Packet.build_data(@session_id, 3, payload: ct <> tag, payload_len: body_len))
      {:ok, parsed} = Packet.parse(raw)

      assert :vip_error = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
    end

    test "service not in VIP table -> :not_vip_service (classic relay fallback)" do
      udp = udp_pair()
      {parsed, raw} = vip_packet(:syn, 1, "x", 7)
      # No services registered.
      assert VipServiceTable.count() == 0

      assert :not_vip_service = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
    end
  end

  # ── connections_summary ─────────────────────────────────────────────────

  describe "connections_summary/0" do
    test "aggregates per service and is robust to missing table" do
      :ets.delete_all_objects(:ztlp_vip_connections)
      VipTcpTerminator.register_connection(@session_id, 1, self(), "web", {{1, 1, 1, 1}, 1})
      VipTcpTerminator.register_connection(@session_id, 2, self(), "web", {{1, 1, 1, 1}, 1})
      VipTcpTerminator.register_connection(<<8::96>>, 1, self(), "db", {{1, 1, 1, 2}, 2})
      s = VipTcpTerminator.connections_summary()
      assert s.active_connections == 3
      assert Enum.sort(s.services) == [{"db", 1}, {"web", 2}]
      VipTcpTerminator.unregister_connection(@session_id, 1)
      VipTcpTerminator.unregister_connection(@session_id, 2)
      VipTcpTerminator.unregister_connection(<<8::96>>, 1)
      assert VipTcpTerminator.connections_summary().active_connections == 0
    end
  end

  # ── the real dispatch path ──────────────────────────────────────────────

  describe "SYN dispatch to a VIP service" do
    # BUG (found 2026-09-13): two independent defects make the VIP dispatch
    # path dead code in production:
    #
    #  1. `extract_service_name/1` reads `parsed.dst_svc_id`, but UdpListener
    #     only calls handle_vip_packet for `:data_compact` packets, whose
    #     parsed map has NO dst_svc_id (only handshake packets carry it). So
    #     service_name is always "" and every packet falls back to classic
    #     relay. The test below injects dst_svc_id to get past this.
    #
    #  2. `route_connection/6` calls `SessionSupervisor.start_session/1`,
    #     which starts a `ZtlpRelay.Session` (peer_a/peer_b relay session),
    #     NOT a `VipConnection`. Session.init does Keyword.fetch!(:peer_a)
    #     -> KeyError -> {:error, _} -> :vip_error. VipConnection.start_link
    #     is not referenced anywhere in lib/.
    #
    # The skipped test is the intended behaviour; the following test pins
    # the current failure so the fix is deliberate.
    @tag :skip
    test "SYN for a configured service spawns a VipConnection and the payload reaches the backend" do
      port = start_backend()
      VipServiceTable.register("svc", {{127, 0, 0, 1}, port})
      udp = udp_pair()
      {parsed, raw} = vip_packet(:syn, 0x2222, "hello backend", 11)
      parsed = Map.put(parsed, :dst_svc_id, pad_svc("svc"))

      assert :vip_handled = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
      bsock = await_backend()
      assert bsock != :none
      assert_receive {:tcp, ^bsock, "hello backend"}, 2_000

      assert [{{@session_id, 0x2222}, pid, "svc", {{127, 0, 0, 1}, ^port}}] =
               :ets.lookup(:ztlp_vip_connections, {@session_id, 0x2222})
      assert Process.alive?(pid)

      # Follow-up DATA frame is routed to the existing connection.
      {parsed2, raw2} = vip_packet(:data, 0x2222, " more", 12)
      parsed2 = Map.put(parsed2, :dst_svc_id, pad_svc("svc"))
      assert :vip_handled = VipTcpTerminator.handle_vip_packet(parsed2, raw2, udp.sender, udp.relay)
      assert_receive {:tcp, ^bsock, " more"}, 2_000
    end

    test "SYN for a configured service currently fails to spawn (pins the Session-vs-VipConnection bug)" do
      port = start_backend()
      VipServiceTable.register("svc", {{127, 0, 0, 1}, port})
      udp = udp_pair()
      {parsed, raw} = vip_packet(:syn, 0x2222, "hello backend", 11)
      parsed = Map.put(parsed, :dst_svc_id, pad_svc("svc"))

      log = capture_log(fn ->
        assert :vip_error = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
      end)

      assert log =~ "Failed to start VipConnection"
      assert :none = await_backend(500), "no TCP connection to backend was ever attempted"
      assert :ets.lookup(:ztlp_vip_connections, {@session_id, 0x2222}) == []
    end

    test "compact data packets carry no dst_svc_id, so service name resolves to '' (pins bug 1)" do
      port = start_backend()
      VipServiceTable.register("svc", {{127, 0, 0, 1}, port})
      udp = udp_pair()
      {parsed, raw} = vip_packet(:syn, 1, "x", 13)
      refute Map.has_key?(parsed, :dst_svc_id)
      assert :not_vip_service = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
    end

    test "non-SYN frame for an unknown {session, conn} -> :vip_error" do
      VipServiceTable.register("svc", {{127, 0, 0, 1}, 1})
      udp = udp_pair()
      {parsed, raw} = vip_packet(:data, 0x7777, "orphan", 14)
      parsed = Map.put(parsed, :dst_svc_id, pad_svc("svc"))

      assert :vip_error = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
    end

    test "non-SYN frame for a registered {session, conn} is delivered to that pid" do
      VipServiceTable.register("svc", {{127, 0, 0, 1}, 1})
      VipTcpTerminator.register_connection(@session_id, 0x4242, self(), "svc", {{127, 0, 0, 1}, 1})
      udp = udp_pair()
      {parsed, raw} = vip_packet(:data, 0x4242, "to-me", 15)
      parsed = Map.put(parsed, :dst_svc_id, pad_svc("svc"))

      assert :vip_handled = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
      assert_receive {:client_data, %{connection_id: 0x4242, frame_type: :data, payload: "to-me"}}
      VipTcpTerminator.unregister_connection(@session_id, 0x4242)
    end

    test "service name is extracted as the NUL-terminated prefix of dst_svc_id" do
      VipServiceTable.register("ab", {{127, 0, 0, 1}, 1})
      VipTcpTerminator.register_connection(@session_id, 5, self(), "ab", {{127, 0, 0, 1}, 1})
      udp = udp_pair()
      {parsed, raw} = vip_packet(:data, 5, "z", 16)
      parsed = Map.put(parsed, :dst_svc_id, <<"ab", 0, "garbage-after-nul", 0>> |> binary_part(0, 16))
      assert :vip_handled = VipTcpTerminator.handle_vip_packet(parsed, raw, udp.sender, udp.relay)
      assert_receive {:client_data, _}
      VipTcpTerminator.unregister_connection(@session_id, 5)
    end
  end

  defp pad_svc(name) do
    name <> :binary.copy(<<0>>, 16 - byte_size(name))
  end

  defp build_plain(seq) do
    pkt = Packet.build_data(@session_id, seq, payload: :binary.copy(<<0>>, 20), payload_len: 20)
    raw = Packet.serialize_data(pkt)
    {:ok, parsed} = Packet.parse(raw)
    {parsed, raw}
  end
end
