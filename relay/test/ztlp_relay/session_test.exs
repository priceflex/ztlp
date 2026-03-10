defmodule ZtlpRelay.SessionTest do
  use ExUnit.Case

  alias ZtlpRelay.{Session, SessionRegistry}

  describe "lifecycle" do
    test "starts and tracks state" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      # Register in the registry first
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} = Session.start_link(
        session_id: session_id,
        peer_a: peer_a,
        peer_b: peer_b,
        timeout_ms: 5_000
      )

      state = Session.get_state(pid)
      assert state.session_id == session_id
      assert state.peer_a == peer_a
      assert state.peer_b == peer_b
      assert state.packet_count == 0

      Session.close(pid)
      # Give it a moment to process the close
      Process.sleep(50)
    end

    test "forward increments packet count" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} = Session.start_link(
        session_id: session_id,
        peer_a: peer_a,
        peer_b: peer_b,
        timeout_ms: 5_000
      )

      Session.forward(pid)
      Session.forward(pid)
      Session.forward(pid)
      # Small delay for async casts to process
      Process.sleep(50)

      state = Session.get_state(pid)
      assert state.packet_count == 3

      Session.close(pid)
      Process.sleep(50)
    end

    test "close stops the GenServer and unregisters" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} = Session.start_link(
        session_id: session_id,
        peer_a: peer_a,
        peer_b: peer_b,
        timeout_ms: 5_000
      )

      ref = Process.monitor(pid)
      Session.close(pid)

      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1_000

      # Session should be unregistered
      assert :error = SessionRegistry.lookup_session(session_id)
    end
  end

  describe "timeout" do
    test "session times out after inactivity" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} = Session.start_link(
        session_id: session_id,
        peer_a: peer_a,
        peer_b: peer_b,
        timeout_ms: 100  # 100ms timeout for testing
      )

      ref = Process.monitor(pid)

      # Wait for timeout
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 500

      # Session should be unregistered
      assert :error = SessionRegistry.lookup_session(session_id)
    end

    test "forward resets the timeout" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} = Session.start_link(
        session_id: session_id,
        peer_a: peer_a,
        peer_b: peer_b,
        timeout_ms: 200
      )

      ref = Process.monitor(pid)

      # Keep sending forwards to reset timeout
      Process.sleep(100)
      Session.forward(pid)
      Process.sleep(100)
      Session.forward(pid)
      Process.sleep(100)

      # Should still be alive after 300ms (3x 100ms sleeps)
      assert Process.alive?(pid)

      # Now let it timeout
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 500
    end
  end
end
