defmodule ZtlpRelay.SessionTest do
  use ExUnit.Case

  alias ZtlpRelay.{Session, SessionRegistry}

  describe "lifecycle" do
    test "starts and tracks state — established" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      # Register in the registry first
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: peer_b,
          timeout_ms: 5_000
        )

      state = Session.get_state(pid)
      assert state.session_id == session_id
      assert state.peer_a == peer_a
      assert state.peer_b == peer_b
      assert state.status == :established
      assert state.packet_count == 0

      Session.close(pid)
      Process.sleep(50)
    end

    test "forward increments packet count" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: peer_b,
          timeout_ms: 5_000
        )

      Session.forward(pid)
      Session.forward(pid)
      Session.forward(pid)
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

      {:ok, pid} =
        Session.start_link(
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

  describe "state machine" do
    test "starts in HALF_OPEN when peer_b is nil" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}

      SessionRegistry.register_session(session_id, peer_a, nil)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: nil,
          timeout_ms: 5_000,
          half_open_timeout_ms: 5_000
        )

      state = Session.get_state(pid)
      assert state.status == :half_open
      assert state.peer_b == nil

      Session.close(pid)
      Process.sleep(50)
    end

    test "starts in HALF_OPEN when peer_b is placeholder {0,0,0,0}:0" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}

      SessionRegistry.register_session(session_id, peer_a, {{0, 0, 0, 0}, 0})

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: {{0, 0, 0, 0}, 0},
          timeout_ms: 5_000,
          half_open_timeout_ms: 5_000
        )

      state = Session.get_state(pid)
      assert state.status == :half_open
      assert state.peer_b == nil

      Session.close(pid)
      Process.sleep(50)
    end

    test "transitions HALF_OPEN → ESTABLISHED on set_peer_b" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, nil)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: nil,
          timeout_ms: 5_000,
          half_open_timeout_ms: 5_000
        )

      # Simulate what the UdpListener would do: register the pid
      SessionRegistry.update_session_pid(session_id, pid)

      assert :ok = Session.set_peer_b(pid, peer_b)

      state = Session.get_state(pid)
      assert state.status == :established
      assert state.peer_b == peer_b

      # Registry should also be updated
      {:ok, {^peer_a, ^peer_b, ^pid}} = SessionRegistry.lookup_session(session_id)

      Session.close(pid)
      Process.sleep(50)
    end

    test "set_peer_b fails on already established session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: peer_b,
          timeout_ms: 5_000
        )

      assert {:error, :not_half_open} = Session.set_peer_b(pid, {{127, 0, 0, 1}, 5003})

      Session.close(pid)
      Process.sleep(50)
    end

    test "HALF_OPEN → ESTABLISHED → CLOSED lifecycle" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, nil)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: nil,
          timeout_ms: 5_000,
          half_open_timeout_ms: 5_000
        )

      # HALF_OPEN
      assert %{status: :half_open} = Session.get_state(pid)

      # → ESTABLISHED
      assert :ok = Session.set_peer_b(pid, peer_b)
      assert %{status: :established} = Session.get_state(pid)

      # → CLOSED
      ref = Process.monitor(pid)
      Session.close(pid)
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1_000

      # Unregistered
      assert :error = SessionRegistry.lookup_session(session_id)
    end
  end

  describe "timeout" do
    test "established session times out after inactivity" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: peer_b,
          # 100ms timeout for testing
          timeout_ms: 100
        )

      ref = Process.monitor(pid)

      # Wait for timeout
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 500

      # Session should be unregistered
      assert :error = SessionRegistry.lookup_session(session_id)
    end

    test "half-open session expires after half_open_timeout" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}

      SessionRegistry.register_session(session_id, peer_a, nil)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: nil,
          timeout_ms: 60_000,
          half_open_timeout_ms: 100
        )

      ref = Process.monitor(pid)

      # Wait for half-open timeout (100ms)
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 500

      # Session should be unregistered
      assert :error = SessionRegistry.lookup_session(session_id)
    end

    test "forward resets the timeout" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      {:ok, pid} =
        Session.start_link(
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

    test "set_peer_b switches from half_open to established timeout" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, nil)

      {:ok, pid} =
        Session.start_link(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: nil,
          # Long established timeout
          timeout_ms: 60_000,
          # Short half-open timeout
          half_open_timeout_ms: 100
        )

      # Quickly set peer_b before half-open expires
      Process.sleep(50)
      assert :ok = Session.set_peer_b(pid, peer_b)

      # Should survive past the half-open timeout since we're now established
      Process.sleep(150)
      assert Process.alive?(pid)

      Session.close(pid)
      Process.sleep(50)
    end
  end
end
