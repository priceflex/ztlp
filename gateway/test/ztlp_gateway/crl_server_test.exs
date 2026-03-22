defmodule ZtlpGateway.CrlServerTest do
  use ExUnit.Case

  alias ZtlpGateway.CrlServer

  setup do
    case GenServer.whereis(CrlServer) do
      nil -> :ok
      pid ->
        GenServer.stop(pid, :normal, 5000)
        Process.sleep(50)
    end

    {:ok, pid} = CrlServer.start_link()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5000)
    end)

    :ok
  end

  describe "revoke/2" do
    test "revokes a certificate by fingerprint" do
      :ok = CrlServer.revoke("aabbccdd" <> String.duplicate("ee", 28))
      assert CrlServer.revoked?("aabbccdd" <> String.duplicate("ee", 28))
    end

    test "non-revoked certificate returns false" do
      refute CrlServer.revoked?("not-revoked-fingerprint")
    end

    test "revokes with serial number" do
      :ok = CrlServer.revoke("fp123", serial: "12345", reason: "compromised")
      assert CrlServer.revoked?("fp123")
      assert CrlServer.revoked_serial?("12345")
    end

    test "revokes with reason" do
      :ok = CrlServer.revoke("fp456", reason: "key-compromise")
      revoked = CrlServer.list_revoked()
      entry = Enum.find(revoked, &(&1.fingerprint == "fp456"))
      assert entry.reason == "key-compromise"
    end
  end

  describe "unrevoke/1" do
    test "removes revocation" do
      :ok = CrlServer.revoke("fp789", serial: "789")
      assert CrlServer.revoked?("fp789")
      :ok = CrlServer.unrevoke("fp789")
      refute CrlServer.revoked?("fp789")
      refute CrlServer.revoked_serial?("789")
    end
  end

  describe "list_revoked/0" do
    test "lists all revoked certs" do
      :ok = CrlServer.revoke("fp1")
      :ok = CrlServer.revoke("fp2")
      revoked = CrlServer.list_revoked()
      assert length(revoked) >= 2
    end
  end

  describe "count/0" do
    test "returns count of revoked certs" do
      assert CrlServer.count() == 0
      :ok = CrlServer.revoke("fp1")
      :ok = CrlServer.revoke("fp2")
      assert CrlServer.count() == 2
    end
  end
end
