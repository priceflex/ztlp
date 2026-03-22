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

  describe "default_secret/0" do
    test "returns a string" do
      assert is_binary(HeaderSigner.default_secret())
    end
  end
end
