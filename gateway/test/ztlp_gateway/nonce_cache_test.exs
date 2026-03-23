defmodule ZtlpGateway.HeaderSigner.NonceCacheTest do
  use ExUnit.Case

  alias ZtlpGateway.HeaderSigner.NonceCache

  setup do
    # Ensure the NonceCache is running. In test, the application
    # may or may not have started it.
    case GenServer.whereis(NonceCache) do
      nil ->
        {:ok, pid} = NonceCache.start_link()
        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5000)
        end)
        :ok

      _pid ->
        # Already running — clear the table for a clean test
        :ets.delete_all_objects(:ztlp_nonce_cache)
        :ok
    end
  end

  describe "check_nonce/1" do
    test "first use of nonce returns :ok" do
      assert :ok = NonceCache.check_nonce("unique-nonce-001")
    end

    test "second use of same nonce returns :replayed" do
      assert :ok = NonceCache.check_nonce("replayed-nonce-001")
      assert {:error, :replayed} = NonceCache.check_nonce("replayed-nonce-001")
    end

    test "different nonces don't conflict" do
      assert :ok = NonceCache.check_nonce("nonce-a")
      assert :ok = NonceCache.check_nonce("nonce-b")
      assert :ok = NonceCache.check_nonce("nonce-c")
    end

    test "replayed detection is consistent" do
      assert :ok = NonceCache.check_nonce("persistent-nonce")
      assert {:error, :replayed} = NonceCache.check_nonce("persistent-nonce")
      assert {:error, :replayed} = NonceCache.check_nonce("persistent-nonce")
    end
  end

  describe "nonce_ttl/0" do
    test "returns 2 * timestamp_window" do
      window = ZtlpGateway.Config.get(:header_signing_timestamp_window)
      assert NonceCache.nonce_ttl() == 2 * window
    end
  end

  describe "cleanup" do
    test "expired nonces are purged" do
      # Insert a nonce that's already expired
      :ets.insert(:ztlp_nonce_cache, {"expired-nonce", 0})

      # The cleanup runs on a timer, but we can trigger it manually
      send(GenServer.whereis(NonceCache), :cleanup)
      Process.sleep(50)

      # The expired nonce should be gone, so inserting it again should succeed
      assert :ok = NonceCache.check_nonce("expired-nonce")
    end

    test "non-expired nonces survive cleanup" do
      assert :ok = NonceCache.check_nonce("fresh-nonce")

      send(GenServer.whereis(NonceCache), :cleanup)
      Process.sleep(50)

      # Fresh nonce should still be tracked
      assert {:error, :replayed} = NonceCache.check_nonce("fresh-nonce")
    end
  end
end
