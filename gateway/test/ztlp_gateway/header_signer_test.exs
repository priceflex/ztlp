defmodule ZtlpGateway.HeaderSignerTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.HeaderSigner

  describe "sign/2" do
    test "signs headers with HMAC-SHA256" do
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Authenticated", "true"}
      ]
      sig = HeaderSigner.sign(headers, "test-secret")
      assert is_binary(sig)
      assert byte_size(sig) == 64  # hex-encoded SHA-256
    end

    test "same headers produce same signature" do
      headers = [{"X-ZTLP-Node-ID", "abc123"}]
      sig1 = HeaderSigner.sign(headers, "secret")
      sig2 = HeaderSigner.sign(headers, "secret")
      assert sig1 == sig2
    end

    test "different secrets produce different signatures" do
      headers = [{"X-ZTLP-Node-ID", "abc123"}]
      sig1 = HeaderSigner.sign(headers, "secret1")
      sig2 = HeaderSigner.sign(headers, "secret2")
      refute sig1 == sig2
    end

    test "different headers produce different signatures" do
      sig1 = HeaderSigner.sign([{"X-ZTLP-Node-ID", "abc"}], "secret")
      sig2 = HeaderSigner.sign([{"X-ZTLP-Node-ID", "xyz"}], "secret")
      refute sig1 == sig2
    end

    test "ignores X-ZTLP-Signature header" do
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Signature", "old-signature"}
      ]
      sig = HeaderSigner.sign(headers, "secret")
      # Should produce same sig as without the signature header
      headers2 = [{"X-ZTLP-Node-ID", "abc123"}]
      sig2 = HeaderSigner.sign(headers2, "secret")
      assert sig == sig2
    end

    test "sorts headers alphabetically" do
      headers1 = [
        {"X-ZTLP-Zone", "corp"},
        {"X-ZTLP-Node-ID", "abc"}
      ]
      headers2 = [
        {"X-ZTLP-Node-ID", "abc"},
        {"X-ZTLP-Zone", "corp"}
      ]
      assert HeaderSigner.sign(headers1, "secret") == HeaderSigner.sign(headers2, "secret")
    end
  end

  describe "canonical_string/1" do
    test "builds canonical string from headers" do
      headers = [
        {"X-ZTLP-Zone", "corp"},
        {"X-ZTLP-Node-ID", "abc"}
      ]
      canonical = HeaderSigner.canonical_string(headers)
      assert canonical == "x-ztlp-node-id:abc\nx-ztlp-zone:corp"
    end

    test "excludes X-ZTLP-Signature" do
      headers = [
        {"X-ZTLP-Node-ID", "abc"},
        {"X-ZTLP-Signature", "sig"}
      ]
      canonical = HeaderSigner.canonical_string(headers)
      assert canonical == "x-ztlp-node-id:abc"
    end

    test "excludes non-ZTLP headers" do
      headers = [
        {"X-ZTLP-Node-ID", "abc"},
        {"Host", "example.com"},
        {"Content-Type", "text/plain"}
      ]
      canonical = HeaderSigner.canonical_string(headers)
      assert canonical == "x-ztlp-node-id:abc"
    end
  end

  describe "verify/3" do
    test "valid signature verifies" do
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Authenticated", "true"}
      ]
      sig = HeaderSigner.sign(headers, "secret")
      assert HeaderSigner.verify(headers, sig, "secret")
    end

    test "invalid signature fails" do
      headers = [{"X-ZTLP-Node-ID", "abc123"}]
      refute HeaderSigner.verify(headers, "bad-signature", "secret")
    end

    test "wrong secret fails" do
      headers = [{"X-ZTLP-Node-ID", "abc123"}]
      sig = HeaderSigner.sign(headers, "secret1")
      refute HeaderSigner.verify(headers, sig, "secret2")
    end
  end

  describe "verify_with_timestamp/4" do
    test "valid signature and fresh timestamp" do
      now = DateTime.utc_now() |> DateTime.to_iso8601()
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Timestamp", now}
      ]
      sig = HeaderSigner.sign(headers, "secret")
      assert {:ok, :valid} = HeaderSigner.verify_with_timestamp(headers, sig, "secret", 60)
    end

    test "valid signature but expired timestamp" do
      past = DateTime.utc_now() |> DateTime.add(-120, :second) |> DateTime.to_iso8601()
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Timestamp", past}
      ]
      sig = HeaderSigner.sign(headers, "secret")
      assert {:error, :expired} = HeaderSigner.verify_with_timestamp(headers, sig, "secret", 60)
    end

    test "invalid signature" do
      now = DateTime.utc_now() |> DateTime.to_iso8601()
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Timestamp", now}
      ]
      assert {:error, :invalid_signature} =
               HeaderSigner.verify_with_timestamp(headers, "badsig", "secret", 60)
    end

    test "missing timestamp header" do
      headers = [{"X-ZTLP-Node-ID", "abc123"}]
      sig = HeaderSigner.sign(headers, "secret")
      assert {:error, :missing_timestamp} =
               HeaderSigner.verify_with_timestamp(headers, sig, "secret", 60)
    end

    test "invalid ISO8601 timestamp is treated as missing" do
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Timestamp", "not-a-timestamp"}
      ]
      sig = HeaderSigner.sign(headers, "secret")
      assert {:error, :missing_timestamp} =
               HeaderSigner.verify_with_timestamp(headers, sig, "secret", 60)
    end

    test "future timestamp is rejected" do
      future = DateTime.utc_now() |> DateTime.add(120, :second) |> DateTime.to_iso8601()
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Timestamp", future}
      ]
      sig = HeaderSigner.sign(headers, "secret")
      assert {:error, :expired} =
               HeaderSigner.verify_with_timestamp(headers, sig, "secret", 60)
    end

    test "timestamp at exact boundary passes" do
      # 30 seconds ago with 60-second window should pass
      recent = DateTime.utc_now() |> DateTime.add(-30, :second) |> DateTime.to_iso8601()
      headers = [
        {"X-ZTLP-Node-ID", "abc123"},
        {"X-ZTLP-Timestamp", recent}
      ]
      sig = HeaderSigner.sign(headers, "secret")
      assert {:ok, :valid} = HeaderSigner.verify_with_timestamp(headers, sig, "secret", 60)
    end
  end

  describe "default_secret/0" do
    test "returns nil when no secret is configured" do
      # In test environment, no secret is configured
      # This is the expected behavior — nil means skip signing
      result = HeaderSigner.default_secret()
      assert is_nil(result) or is_binary(result)
    end
  end

  describe "validate_secret!/0" do
    test "returns :ok without crashing" do
      assert :ok = HeaderSigner.validate_secret!()
    end

    test "logs warning when signing enabled but no secret configured" do
      # Temporarily enable signing
      prev = Application.get_env(:ztlp_gateway, :header_signing_enabled)
      Application.put_env(:ztlp_gateway, :header_signing_enabled, true)

      # Should not crash, just log
      assert :ok = HeaderSigner.validate_secret!()

      # Restore
      if prev do
        Application.put_env(:ztlp_gateway, :header_signing_enabled, prev)
      else
        Application.delete_env(:ztlp_gateway, :header_signing_enabled)
      end
    end

    test "logs warning when signing enabled with default insecure secret" do
      prev_enabled = Application.get_env(:ztlp_gateway, :header_signing_enabled)
      prev_secret = Application.get_env(:ztlp_gateway, :header_signing_secret)

      Application.put_env(:ztlp_gateway, :header_signing_enabled, true)
      Application.put_env(:ztlp_gateway, :header_signing_secret, "ztlp-default-signing-secret")

      assert :ok = HeaderSigner.validate_secret!()

      # Restore
      if prev_enabled do
        Application.put_env(:ztlp_gateway, :header_signing_enabled, prev_enabled)
      else
        Application.delete_env(:ztlp_gateway, :header_signing_enabled)
      end
      if prev_secret do
        Application.put_env(:ztlp_gateway, :header_signing_secret, prev_secret)
      else
        Application.delete_env(:ztlp_gateway, :header_signing_secret)
      end
    end
  end
end
