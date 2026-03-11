defmodule ZtlpRelay.SessionRegistryTest do
  use ExUnit.Case

  alias ZtlpRelay.SessionRegistry

  setup do
    # Clean up any test sessions after each test
    :ok
  end

  describe "register_session/4 and lookup_session/1" do
    test "registers and looks up a session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      :ok = SessionRegistry.register_session(session_id, peer_a, peer_b)
      assert {:ok, {^peer_a, ^peer_b, nil}} = SessionRegistry.lookup_session(session_id)

      SessionRegistry.unregister_session(session_id)
    end

    test "registers with a session pid" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}
      pid = self()

      :ok = SessionRegistry.register_session(session_id, peer_a, peer_b, pid)
      assert {:ok, {^peer_a, ^peer_b, ^pid}} = SessionRegistry.lookup_session(session_id)

      SessionRegistry.unregister_session(session_id)
    end

    test "returns :error for unknown session" do
      session_id = :crypto.strong_rand_bytes(12)
      assert :error = SessionRegistry.lookup_session(session_id)
    end
  end

  describe "unregister_session/1" do
    test "removes a session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)
      assert {:ok, _} = SessionRegistry.lookup_session(session_id)

      SessionRegistry.unregister_session(session_id)
      assert :error = SessionRegistry.lookup_session(session_id)
    end

    test "unregistering non-existent session is a no-op" do
      session_id = :crypto.strong_rand_bytes(12)
      :ok = SessionRegistry.unregister_session(session_id)
    end
  end

  describe "session_exists?/1" do
    test "returns true for registered session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)
      assert SessionRegistry.session_exists?(session_id)

      SessionRegistry.unregister_session(session_id)
    end

    test "returns false for unknown session" do
      session_id = :crypto.strong_rand_bytes(12)
      refute SessionRegistry.session_exists?(session_id)
    end
  end

  describe "lookup_peer/2" do
    test "returns peer_b when sender is peer_a" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)
      assert {:ok, ^peer_b} = SessionRegistry.lookup_peer(session_id, peer_a)

      SessionRegistry.unregister_session(session_id)
    end

    test "returns peer_a when sender is peer_b" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)
      assert {:ok, ^peer_a} = SessionRegistry.lookup_peer(session_id, peer_b)

      SessionRegistry.unregister_session(session_id)
    end

    test "returns :error for unknown sender" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}
      unknown = {{127, 0, 0, 1}, 9999}

      SessionRegistry.register_session(session_id, peer_a, peer_b)
      assert :error = SessionRegistry.lookup_peer(session_id, unknown)

      SessionRegistry.unregister_session(session_id)
    end

    test "returns :error for unknown session" do
      session_id = :crypto.strong_rand_bytes(12)
      assert :error = SessionRegistry.lookup_peer(session_id, {{127, 0, 0, 1}, 5001})
    end
  end

  describe "update_session_pid/2" do
    test "updates the pid for an existing session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)
      pid = self()
      :ok = SessionRegistry.update_session_pid(session_id, pid)

      assert {:ok, {^peer_a, ^peer_b, ^pid}} = SessionRegistry.lookup_session(session_id)

      SessionRegistry.unregister_session(session_id)
    end

    test "returns :error for unknown session" do
      session_id = :crypto.strong_rand_bytes(12)
      assert :error = SessionRegistry.update_session_pid(session_id, self())
    end
  end

  describe "count/0" do
    test "counts registered sessions" do
      initial = SessionRegistry.count()

      ids =
        for _ <- 1..5 do
          id = :crypto.strong_rand_bytes(12)
          SessionRegistry.register_session(id, {{127, 0, 0, 1}, 5001}, {{127, 0, 0, 1}, 5002})
          id
        end

      assert SessionRegistry.count() == initial + 5

      Enum.each(ids, &SessionRegistry.unregister_session/1)
    end
  end

  describe "concurrent access" do
    test "handles concurrent registrations" do
      tasks =
        for i <- 1..50 do
          Task.async(fn ->
            session_id = :crypto.strong_rand_bytes(12)
            peer_a = {{127, 0, 0, 1}, 6000 + i}
            peer_b = {{127, 0, 0, 1}, 7000 + i}
            SessionRegistry.register_session(session_id, peer_a, peer_b)
            session_id
          end)
        end

      ids = Enum.map(tasks, &Task.await/1)

      # All should be registered
      for id <- ids do
        assert {:ok, _} = SessionRegistry.lookup_session(id)
      end

      Enum.each(ids, &SessionRegistry.unregister_session/1)
    end
  end
end
