defmodule ZtlpRelay.GatewayForwarderTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.GatewayForwarder

  setup do
    # GatewayForwarder may or may not be started by the application
    case GenServer.whereis(GatewayForwarder) do
      nil ->
        {:ok, pid} = GatewayForwarder.start_link()

        on_exit(fn ->
          try do
            GenServer.stop(pid, :normal, 1000)
          catch
            :exit, _ -> :ok
          end
        end)

        :ok

      _pid ->
        :ok
    end
  end

  test "register and lookup forwarded session" do
    initial_count = GatewayForwarder.count()
    session_id = :crypto.strong_rand_bytes(12)
    client = {{10, 0, 0, 1}, 5000}
    gateway = {{10, 0, 0, 2}, 23098}

    GatewayForwarder.register_forwarded_session(session_id, client, gateway)
    # Cast is async, give it a moment
    Process.sleep(10)

    assert {:ok, session} = GatewayForwarder.lookup(session_id)
    assert session.client == client
    assert session.gateway == gateway
    assert GatewayForwarder.count() == initial_count + 1
  end

  test "lookup returns error for unknown session" do
    assert :error == GatewayForwarder.lookup(:crypto.strong_rand_bytes(12))
  end

  test "multiple sessions tracked independently" do
    initial_count = GatewayForwarder.count()
    s1 = :crypto.strong_rand_bytes(12)
    s2 = :crypto.strong_rand_bytes(12)
    c1 = {{10, 0, 0, 1}, 5000}
    c2 = {{10, 0, 0, 3}, 6000}
    gw = {{10, 0, 0, 2}, 23098}

    GatewayForwarder.register_forwarded_session(s1, c1, gw)
    GatewayForwarder.register_forwarded_session(s2, c2, gw)
    Process.sleep(10)

    assert {:ok, session1} = GatewayForwarder.lookup(s1)
    assert {:ok, session2} = GatewayForwarder.lookup(s2)
    assert session1.client == c1
    assert session2.client == c2
    assert GatewayForwarder.count() == initial_count + 2
  end

  describe "lookup_by_peer/1 — post-handshake Noise transport forwarding" do
    # These tests verify the fast-path used by the UDP listener to forward
    # raw Noise transport packets between peers after the handshake has
    # completed. The relay can't parse the ciphertext (zero-trust), so it
    # must route purely by sender→other-peer mapping.

    test "returns the gateway address when the sender is the client" do
      session_id = :crypto.strong_rand_bytes(12)
      client = {{10, 0, 0, 1}, 5000}
      gateway = {{10, 0, 0, 2}, 23098}

      GatewayForwarder.register_forwarded_session(session_id, client, gateway)
      Process.sleep(10)

      assert {:ok, ^session_id, ^gateway} = GatewayForwarder.lookup_by_peer(client)
    end

    test "returns the client address when the sender is the gateway" do
      session_id = :crypto.strong_rand_bytes(12)
      client = {{10, 0, 0, 1}, 5001}
      gateway = {{10, 0, 0, 2}, 23099}

      GatewayForwarder.register_forwarded_session(session_id, client, gateway)
      Process.sleep(10)

      assert {:ok, ^session_id, ^client} = GatewayForwarder.lookup_by_peer(gateway)
    end

    test "returns :error for an unknown peer address" do
      assert :error == GatewayForwarder.lookup_by_peer({{192, 168, 99, 99}, 1234})
    end

    test "update_client/2 rewrites the peer index so old client address is no longer routable" do
      # When a NAT rebinds the client's source port, the relay's
      # GatewayForwarder is updated via {:update_client, ...}. The peer
      # index must be kept in sync so the old (stale) address can no
      # longer be used to forward packets.
      session_id = :crypto.strong_rand_bytes(12)
      old_client = {{10, 0, 0, 1}, 5002}
      new_client = {{10, 0, 0, 1}, 5999}
      gateway = {{10, 0, 0, 2}, 23100}

      GatewayForwarder.register_forwarded_session(session_id, old_client, gateway)
      Process.sleep(10)
      assert {:ok, ^session_id, ^gateway} = GatewayForwarder.lookup_by_peer(old_client)

      GenServer.cast(GatewayForwarder, {:update_client, session_id, new_client})
      Process.sleep(10)

      assert :error == GatewayForwarder.lookup_by_peer(old_client)
      assert {:ok, ^session_id, ^gateway} = GatewayForwarder.lookup_by_peer(new_client)
      # Gateway can still reach the client (now at its new addr)
      assert {:ok, ^session_id, ^new_client} = GatewayForwarder.lookup_by_peer(gateway)
    end
  end
end
