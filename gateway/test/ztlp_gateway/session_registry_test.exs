defmodule ZtlpGateway.SessionRegistryTest do
  use ExUnit.Case

  alias ZtlpGateway.SessionRegistry

  describe "register/lookup/unregister" do
    test "register and lookup" do
      sid = :crypto.strong_rand_bytes(12)
      {:ok, pid} = Agent.start_link(fn -> nil end)
      :ok = SessionRegistry.register(sid, pid)
      assert {:ok, ^pid} = SessionRegistry.lookup(sid)
      SessionRegistry.unregister(sid)
      Agent.stop(pid)
    end

    test "lookup returns :error for unknown session" do
      sid = :crypto.strong_rand_bytes(12)
      assert :error = SessionRegistry.lookup(sid)
    end

    test "double registration returns error" do
      sid = :crypto.strong_rand_bytes(12)
      {:ok, pid1} = Agent.start_link(fn -> nil end)
      {:ok, pid2} = Agent.start_link(fn -> nil end)

      :ok = SessionRegistry.register(sid, pid1)
      assert {:error, :already_registered} = SessionRegistry.register(sid, pid2)

      SessionRegistry.unregister(sid)
      Agent.stop(pid1)
      Agent.stop(pid2)
    end

    test "unregister removes entry" do
      sid = :crypto.strong_rand_bytes(12)
      {:ok, pid} = Agent.start_link(fn -> nil end)
      :ok = SessionRegistry.register(sid, pid)

      SessionRegistry.unregister(sid)
      assert :error = SessionRegistry.lookup(sid)
      Agent.stop(pid)
    end

    test "count reflects active sessions" do
      initial = SessionRegistry.count()

      sid = :crypto.strong_rand_bytes(12)
      {:ok, pid} = Agent.start_link(fn -> nil end)
      :ok = SessionRegistry.register(sid, pid)
      assert SessionRegistry.count() == initial + 1

      SessionRegistry.unregister(sid)
      assert SessionRegistry.count() == initial

      Agent.stop(pid)
    end

    test "auto-unregisters on process death" do
      sid = :crypto.strong_rand_bytes(12)
      {:ok, pid} = Agent.start_link(fn -> nil end)
      :ok = SessionRegistry.register(sid, pid)

      # Kill the registered process
      Agent.stop(pid)

      # Give the :DOWN message time to be processed
      Process.sleep(50)

      assert :error = SessionRegistry.lookup(sid)
    end
  end
end
