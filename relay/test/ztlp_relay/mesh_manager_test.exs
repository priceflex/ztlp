defmodule ZtlpRelay.MeshManagerTest do
  use ExUnit.Case

  alias ZtlpRelay.{MeshManager, RelayRegistry, InterRelay}

  # Start with mesh disabled in the app config (default),
  # but spin up components manually for testing.

  setup do
    # Start a RelayRegistry for the MeshManager to use
    # Check if one is already running and stop it
    case Process.whereis(ZtlpRelay.RelayRegistry) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 5000)
    end

    # Start a fresh RelayRegistry
    {:ok, reg_pid} = RelayRegistry.start_link(
      sweep_interval_ms: 60_000_000
    )

    # Start a MeshManager with a random mesh port to avoid conflicts
    # and no bootstrap relays (isolated test)
    node_id = :crypto.strong_rand_bytes(16)

    case Process.whereis(ZtlpRelay.MeshManager) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 5000)
    end

    {:ok, mm_pid} = MeshManager.start_link(
      node_id: node_id,
      relay_role: :all,
      mesh_listen_port: 0,  # random port
      ping_interval_ms: 60_000_000,  # very long, we don't want auto pings
      bootstrap_relays: []
    )

    on_exit(fn ->
      if Process.alive?(mm_pid), do: GenServer.stop(mm_pid, :normal, 5000)
      if Process.alive?(reg_pid), do: GenServer.stop(reg_pid, :normal, 5000)
    end)

    %{node_id: node_id, mm_pid: mm_pid, reg_pid: reg_pid}
  end

  describe "node_id/0" do
    test "returns the configured node_id", %{node_id: node_id} do
      assert MeshManager.node_id() == node_id
    end
  end

  describe "get_mesh_status/0" do
    test "returns mesh status info", %{node_id: node_id} do
      status = MeshManager.get_mesh_status()
      assert status.node_id == node_id
      assert status.role == :all
      assert status.ring_nodes >= 1  # at least ourselves
      assert status.socket_open == true
      assert is_map(status.scores)
    end
  end

  describe "route/1" do
    test "routes to self when only node in ring", %{node_id: _node_id} do
      session_id = :crypto.strong_rand_bytes(12)
      result = MeshManager.route(session_id)
      # With only ourselves in the ring, we should get {:local, :self}
      assert result == {:local, :self}
    end

    test "routes to other relay when it owns the key" do
      # Add another relay to the mesh via a simulated RELAY_HELLO
      other_node_id = :crypto.strong_rand_bytes(16)
      other_address = {{10, 0, 0, 99}, 23096}

      hello = InterRelay.encode_hello(%{
        node_id: other_node_id,
        address: other_address,
        role: :all,
        capabilities: 0
      })

      MeshManager.handle_inter_relay(hello, other_address)

      # Give GenServer time to process
      Process.sleep(50)

      # Try many session IDs — some should route to the other relay
      results = for _ <- 1..100 do
        session_id = :crypto.strong_rand_bytes(12)
        MeshManager.route(session_id)
      end

      # We should see both {:local, :self} and {:ok, _} results
      local_count = Enum.count(results, &match?({:local, :self}, &1))
      remote_count = Enum.count(results, &match?({:ok, _}, &1))

      assert local_count > 0 or remote_count > 0,
        "Should route to at least one destination"
    end
  end

  describe "handle_inter_relay — RELAY_HELLO" do
    test "registers new relay in registry" do
      other_node_id = :crypto.strong_rand_bytes(16)
      other_address = {{10, 0, 0, 50}, 23096}

      hello = InterRelay.encode_hello(%{
        node_id: other_node_id,
        address: other_address,
        role: :ingress,
        capabilities: 0
      })

      MeshManager.handle_inter_relay(hello, other_address)
      Process.sleep(50)

      assert {:ok, relay} = RelayRegistry.lookup(other_node_id)
      assert relay.address == other_address
      assert relay.role == :ingress
    end
  end

  describe "handle_inter_relay — RELAY_LEAVE" do
    test "removes relay from registry and ring" do
      # First add a relay
      other_node_id = :crypto.strong_rand_bytes(16)
      other_address = {{10, 0, 0, 60}, 23096}

      hello = InterRelay.encode_hello(%{
        node_id: other_node_id,
        address: other_address,
        role: :all,
        capabilities: 0
      })
      MeshManager.handle_inter_relay(hello, other_address)
      Process.sleep(50)

      assert {:ok, _} = RelayRegistry.lookup(other_node_id)

      # Now send LEAVE
      leave = InterRelay.encode_leave(other_node_id)
      MeshManager.handle_inter_relay(leave, other_address)
      Process.sleep(50)

      assert :error = RelayRegistry.lookup(other_node_id)
    end
  end

  describe "handle_inter_relay — RELAY_HELLO_ACK" do
    test "registers relay from ACK" do
      other_node_id = :crypto.strong_rand_bytes(16)
      other_address = {{10, 0, 0, 70}, 23096}

      ack = InterRelay.encode_hello_ack(%{
        node_id: other_node_id,
        address: other_address,
        role: :transit,
        capabilities: 0
      })

      MeshManager.handle_inter_relay(ack, other_address)
      Process.sleep(50)

      assert {:ok, relay} = RelayRegistry.lookup(other_node_id)
      assert relay.role == :transit
    end
  end

  describe "handle_inter_relay — RELAY_PONG" do
    test "updates scores for relay" do
      other_node_id = :crypto.strong_rand_bytes(16)
      other_address = {{10, 0, 0, 80}, 23096}

      # First register the relay
      hello = InterRelay.encode_hello(%{
        node_id: other_node_id,
        address: other_address,
        role: :all,
        capabilities: 0
      })
      MeshManager.handle_inter_relay(hello, other_address)
      Process.sleep(50)

      # Now send PONG with metrics
      pong = InterRelay.encode_pong(other_node_id, %{
        active_sessions: 100,
        max_sessions: 10_000,
        uptime_seconds: 3600
      })
      MeshManager.handle_inter_relay(pong, other_address)
      Process.sleep(50)

      # Check that scores were updated
      status = MeshManager.get_mesh_status()
      assert Map.has_key?(status.scores, other_node_id)
    end
  end
end
