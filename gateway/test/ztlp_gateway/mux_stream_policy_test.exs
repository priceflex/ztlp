defmodule ZtlpGateway.MuxStreamPolicyTest do
  @moduledoc """
  Tests for per-stream service authorization on FRAME_OPEN (mux streams).

  Regression test for the SAST finding:
    [HIGH/CWE-639] gateway/session.ex open_mux_stream/3 — "Per-stream service
    authorization bypass exposes backends".

  Before the fix, a client authenticated for service A (passes the session-level
  PolicyEngine.authorize? at handshake) could send a FRAME_OPEN carrying a
  different service_name and open a tunnel to ANY configured backend whose name
  resolves — because open_mux_stream/3 called find_backend/2 +
  BackendPool.checkout/4 with NO per-stream PolicyEngine.authorize? check.

  These tests assert that the per-stream service is now authorized against the
  session identity, so lateral movement across backends via mux is blocked.
  """
  use ExUnit.Case

  alias ZtlpGateway.{Crypto, Handshake, Packet, Session, PolicyEngine}

  # ── Test helpers (mirrors AsyncOpenTest harness) ───────────────────

  defp setup_session(backends, rules) do
    {gw_pub, gw_priv} = Crypto.generate_keypair()
    {client_pub, client_priv} = Crypto.generate_keypair()

    {:ok, client_sock} = :gen_udp.open(0, [:binary, {:active, false}])
    {:ok, client_port} = :inet.port(client_sock)
    client_addr = {{127, 0, 0, 1}, client_port}
    {:ok, gw_sock} = :gen_udp.open(0, [:binary, {:active, false}])

    # Real backend listeners so the default (authorized) stream can connect.
    listeners =
      Enum.map(backends, fn b ->
        {:ok, ls} = :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])
        {b.name, ls}
      end)

    listener_map = Map.new(listeners)

    backends_with_ports =
      Enum.map(backends, fn b ->
        {:ok, p} = :inet.port(Map.fetch!(listener_map, b.name))
        Map.put(b, :port, p)
      end)

    Application.put_env(:ztlp_gateway, :backends, backends_with_ports)
    Enum.each(rules, fn {svc, allow} -> PolicyEngine.put_rule(svc, allow) end)

    session_id = :crypto.strong_rand_bytes(12)

    session_opts = %{
      session_id: session_id,
      client_addr: client_addr,
      udp_socket: gw_sock,
      static_pub: gw_pub,
      static_priv: gw_priv,
      service: "default"
    }

    {:ok, session_pid} = Session.start_link(session_opts)

    # Noise_XX handshake (client → server)
    initiator = Handshake.init_initiator(client_pub, client_priv)
    {initiator, msg1_payload} = Handshake.create_msg1(initiator)
    Session.handle_packet(session_pid, Packet.build_hello(msg1_payload), client_addr)

    Process.sleep(50)
    {:ok, {_ip, _port, msg2_raw}} = :gen_udp.recv(client_sock, 0, 2000)
    {:ok, %{payload: msg2_payload}} = Packet.parse(msg2_raw)
    {initiator, _} = Handshake.process_msg2(initiator, msg2_payload)

    {initiator, msg3_payload} = Handshake.create_msg3(initiator)
    msg3_pkt = Packet.build_handshake(:hello, session_id, payload: msg3_payload)
    Session.handle_packet(session_pid, Packet.serialize_handshake(msg3_pkt), client_addr)

    {:ok, client_keys} = Handshake.split(initiator, session_id)
    Process.sleep(50)

    %{
      session_pid: session_pid,
      session_id: session_id,
      client_addr: client_addr,
      client_sock: client_sock,
      gw_sock: gw_sock,
      i2r_key: client_keys.i2r_key,
      listeners: listeners
    }
  end

  defp send_frame(ctx, plaintext, seq) do
    nonce = <<0::32, seq::little-64>>
    {ct, tag} = Crypto.encrypt(ctx.i2r_key, nonce, plaintext, <<>>)
    encrypted = ct <> tag

    pkt =
      Packet.build_data(ctx.session_id, seq,
        payload: encrypted,
        payload_len: byte_size(encrypted)
      )

    Session.handle_packet(ctx.session_pid, Packet.serialize_data_with_auth(pkt, ctx.i2r_key), ctx.client_addr)
  end

  defp frame_open(stream_id, svc_name),
    do: <<0x06, stream_id::big-32, byte_size(svc_name)::8, svc_name::binary>>

  defp cleanup(ctx) do
    if Process.alive?(ctx.session_pid), do: catch_close(fn -> GenServer.stop(ctx.session_pid) end)

    Enum.each(ctx.listeners, fn {_name, ls} -> catch_close(fn -> :gen_tcp.close(ls) end) end)
    :gen_udp.close(ctx.client_sock)
    :gen_udp.close(ctx.gw_sock)
  end

  defp catch_close(fun) do
    try do
      fun.()
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end

  # ── Tests ─────────────────────────────────────────────────────────

  describe "per-stream service authorization" do
    test "FRAME_OPEN to a non-authorized service is rejected" do
      # Client is authorized for "default" only. "secret" is configured but NOT
      # allowed for this identity.
      ctx =
        setup_session(
          [
            %{name: "default", host: ~c"127.0.0.1"},
            %{name: "secret", host: ~c"127.0.0.1"}
          ],
          [{"default", :all}, {"secret", ["nobody-can-see-this"]}]
        )

      # Attempt to open a mux stream to the unauthorized "secret" service.
      send_frame(ctx, frame_open(42, "secret"), 0)
      Process.sleep(50)

      session_state = :sys.get_state(ctx.session_pid)
      assert Map.get(session_state.streams, 42) == nil,
             "Stream 42 to unauthorized service 'secret' must be rejected, " <>
               "but it was admitted: #{inspect(Map.get(session_state.streams, 42))}"

      cleanup(ctx)
    end

    test "FRAME_OPEN to an authorized service is still admitted (no regression)" do
      # Client is authorized for "default". Opening a stream to "default" must
      # still work (the fix must not break the legitimate path).
      ctx =
        setup_session(
          [%{name: "default", host: ~c"127.0.0.1"}],
          [{"default", :all}]
        )

      send_frame(ctx, frame_open(7, "default"), 0)
      Process.sleep(200)

      session_state = :sys.get_state(ctx.session_pid)
      stream = Map.get(session_state.streams, 7)
      assert stream != nil, "Stream 7 to authorized service 'default' must be admitted"
      assert stream.state in [:connecting, :connected]

      cleanup(ctx)
    end
  end
end
