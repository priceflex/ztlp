defmodule ZtlpGateway.SessionDedupTest do
  @moduledoc """
  Tests for session deduplication via address-based lookup in SessionRegistry.

  Verifies that:
  1. SessionRegistry tracks client addresses
  2. lookup_by_addr finds sessions by {ip, port}
  3. Address entries are cleaned up on unregister and process death
  """
  use ExUnit.Case

  alias ZtlpGateway.SessionRegistry

  describe "address-based lookup" do
    test "register with client_addr enables lookup_by_addr" do
      sid = :crypto.strong_rand_bytes(12)
      addr = {{192, 168, 1, 100}, 5000}
      {:ok, pid} = Agent.start_link(fn -> nil end)

      :ok = SessionRegistry.register(sid, pid, addr)
      assert {:ok, {^sid, ^pid}} = SessionRegistry.lookup_by_addr(addr)

      # Normal lookup still works
      assert {:ok, ^pid} = SessionRegistry.lookup(sid)

      SessionRegistry.unregister(sid)
      Agent.stop(pid)
    end

    test "lookup_by_addr returns :error for unknown address" do
      addr = {{10, 0, 0, 99}, 12345}
      assert :error = SessionRegistry.lookup_by_addr(addr)
    end

    test "unregister cleans up addr table" do
      sid = :crypto.strong_rand_bytes(12)
      addr = {{192, 168, 1, 101}, 6000}
      {:ok, pid} = Agent.start_link(fn -> nil end)

      :ok = SessionRegistry.register(sid, pid, addr)
      assert {:ok, _} = SessionRegistry.lookup_by_addr(addr)

      SessionRegistry.unregister(sid)
      assert :error = SessionRegistry.lookup_by_addr(addr)

      Agent.stop(pid)
    end

    test "process death cleans up addr table" do
      sid = :crypto.strong_rand_bytes(12)
      addr = {{192, 168, 1, 102}, 7000}
      {:ok, pid} = Agent.start_link(fn -> nil end)

      :ok = SessionRegistry.register(sid, pid, addr)
      assert {:ok, _} = SessionRegistry.lookup_by_addr(addr)

      # Kill the process
      Agent.stop(pid)
      Process.sleep(50)

      # Both tables should be cleaned up
      assert :error = SessionRegistry.lookup(sid)
      assert :error = SessionRegistry.lookup_by_addr(addr)
    end

    test "register without addr (backward compat) does not populate addr table" do
      sid = :crypto.strong_rand_bytes(12)
      {:ok, pid} = Agent.start_link(fn -> nil end)

      # 2-arg register (no addr)
      :ok = SessionRegistry.register(sid, pid)
      assert {:ok, ^pid} = SessionRegistry.lookup(sid)

      SessionRegistry.unregister(sid)
      Agent.stop(pid)
    end

    test "new registration for same addr overwrites old addr entry" do
      addr = {{192, 168, 1, 103}, 8000}

      sid1 = :crypto.strong_rand_bytes(12)
      {:ok, pid1} = Agent.start_link(fn -> nil end)
      :ok = SessionRegistry.register(sid1, pid1, addr)

      # Register a NEW session from the same addr
      # (In production, the old session would be terminated first by the Listener)
      sid2 = :crypto.strong_rand_bytes(12)
      {:ok, pid2} = Agent.start_link(fn -> nil end)
      :ok = SessionRegistry.register(sid2, pid2, addr)

      # lookup_by_addr now points to the newer session
      assert {:ok, {^sid2, ^pid2}} = SessionRegistry.lookup_by_addr(addr)

      # Both sessions still exist in the main table
      assert {:ok, ^pid1} = SessionRegistry.lookup(sid1)
      assert {:ok, ^pid2} = SessionRegistry.lookup(sid2)

      SessionRegistry.unregister(sid1)
      SessionRegistry.unregister(sid2)
      Agent.stop(pid1)
      Agent.stop(pid2)
    end
  end
end
