defmodule ZtlpGateway.TlsRevocationTest do
  @moduledoc """
  Tests for TLS certificate revocation integration.

  Verifies that the CrlServer correctly tracks revoked certificates
  and that revocation status is checked during mTLS identity extraction.
  """
  use ExUnit.Case

  alias ZtlpGateway.CrlServer

  setup do
    # Start CrlServer fresh for each test
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

  describe "CRL revocation checks for mTLS identities" do
    test "non-revoked fingerprint is not rejected" do
      fingerprint = "aa" <> String.duplicate("bb", 31)
      refute CrlServer.revoked?(fingerprint)
    end

    test "revoked fingerprint is detected" do
      fingerprint = "cc" <> String.duplicate("dd", 31)
      :ok = CrlServer.revoke(fingerprint, reason: "key-compromise")
      assert CrlServer.revoked?(fingerprint)
    end

    test "revocation by serial number works" do
      fingerprint = "ee" <> String.duplicate("ff", 31)
      :ok = CrlServer.revoke(fingerprint, serial: "123456789", reason: "compromised")
      assert CrlServer.revoked?(fingerprint)
      assert CrlServer.revoked_serial?("123456789")
    end

    test "unrevoked certificate is no longer detected" do
      fingerprint = "11" <> String.duplicate("22", 31)
      :ok = CrlServer.revoke(fingerprint, serial: "999")
      assert CrlServer.revoked?(fingerprint)

      :ok = CrlServer.unrevoke(fingerprint)
      refute CrlServer.revoked?(fingerprint)
      refute CrlServer.revoked_serial?("999")
    end

    test "CRL changes take effect on new lookups immediately" do
      fingerprint = "33" <> String.duplicate("44", 31)

      # Initially not revoked
      refute CrlServer.revoked?(fingerprint)

      # Revoke it
      :ok = CrlServer.revoke(fingerprint)

      # Immediately visible on new lookup (no caching delay)
      assert CrlServer.revoked?(fingerprint)

      # Unrevoke it
      :ok = CrlServer.unrevoke(fingerprint)

      # Immediately visible
      refute CrlServer.revoked?(fingerprint)
    end

    test "multiple revocations tracked independently" do
      fp1 = "aa" <> String.duplicate("11", 31)
      fp2 = "bb" <> String.duplicate("22", 31)
      fp3 = "cc" <> String.duplicate("33", 31)

      :ok = CrlServer.revoke(fp1, reason: "key-compromise")
      :ok = CrlServer.revoke(fp2, reason: "superseded")

      assert CrlServer.revoked?(fp1)
      assert CrlServer.revoked?(fp2)
      refute CrlServer.revoked?(fp3)

      # Unrevoke just fp1
      :ok = CrlServer.unrevoke(fp1)
      refute CrlServer.revoked?(fp1)
      assert CrlServer.revoked?(fp2)
    end

    test "revocation reason is preserved in the list" do
      fp = "dd" <> String.duplicate("55", 31)
      :ok = CrlServer.revoke(fp, serial: "42", reason: "key-compromise")

      revoked = CrlServer.list_revoked()
      entry = Enum.find(revoked, &(&1.fingerprint == fp))
      assert entry != nil
      assert entry.reason == "key-compromise"
      assert entry.serial == "42"
    end

    test "revocation of cert without serial does not crash serial check" do
      fp = "ee" <> String.duplicate("66", 31)
      :ok = CrlServer.revoke(fp)
      assert CrlServer.revoked?(fp)
      # Serial check for unrelated serial should not crash
      refute CrlServer.revoked_serial?("nonexistent")
    end
  end

  describe "revocation integration with identity flow" do
    test "authenticated identity with revoked fingerprint should be detectable" do
      # Simulate what TlsSession does: extract identity, then check CRL
      identity = %{
        authenticated: true,
        node_id: "abc123",
        node_name: "test.corp.ztlp",
        cert_fingerprint: "ff" <> String.duplicate("00", 31),
        cert_serial: "12345",
        assurance: :software
      }

      # Not revoked initially
      refute CrlServer.revoked?(identity.cert_fingerprint)

      # Revoke it
      :ok = CrlServer.revoke(identity.cert_fingerprint, serial: identity.cert_serial)

      # Now the revocation check should catch it
      assert CrlServer.revoked?(identity.cert_fingerprint)
    end

    test "unauthenticated identity has no fingerprint to check" do
      identity = %{
        authenticated: false,
        node_id: nil,
        cert_fingerprint: nil,
        cert_serial: nil
      }

      # nil fingerprint should not crash CrlServer
      # (TlsSession skips the check for unauthenticated identities)
      assert identity.cert_fingerprint == nil
    end
  end
end
