defmodule ZtlpGateway.HeaderVerifierTest do
  use ExUnit.Case

  alias ZtlpGateway.HeaderVerifier
  alias ZtlpGateway.HeaderSigner

  @secret "test-verification-secret"

  setup do
    # Ensure NonceCache is running
    case GenServer.whereis(ZtlpGateway.HeaderSigner.NonceCache) do
      nil ->
        {:ok, pid} = ZtlpGateway.HeaderSigner.NonceCache.start_link()
        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5000)
        end)
        :ok

      _pid ->
        :ets.delete_all_objects(:ztlp_nonce_cache)
        :ok
    end
  end

  defp make_signed_headers(opts \\ []) do
    now = Keyword.get(opts, :timestamp, DateTime.utc_now() |> DateTime.to_iso8601())
    nonce = Keyword.get(opts, :nonce, ZtlpGateway.HttpHeaderInjector.generate_nonce())
    request_id = Keyword.get(opts, :request_id, ZtlpGateway.HttpHeaderInjector.generate_request_id())
    secret = Keyword.get(opts, :secret, @secret)

    headers = [
      {"X-ZTLP-Node-ID", "abc123"},
      {"X-ZTLP-Node-Name", "node1.corp.ztlp"},
      {"X-ZTLP-Zone", "corp.ztlp"},
      {"X-ZTLP-Authenticated", "true"},
      {"X-ZTLP-Assurance", "software"},
      {"X-ZTLP-Key-Source", "file"},
      {"X-ZTLP-Key-Attestation", "unverified"},
      {"X-ZTLP-Cert-Fingerprint", "aabbccdd"},
      {"X-ZTLP-Cert-Serial", "12345"},
      {"X-ZTLP-Timestamp", now},
      {"X-ZTLP-Nonce", nonce},
      {"X-ZTLP-Request-ID", request_id}
    ]

    sig = HeaderSigner.sign(headers, secret)
    headers ++ [{"X-ZTLP-Signature", sig}]
  end

  describe "verify_request/2" do
    test "valid signed headers pass verification" do
      headers = make_signed_headers()
      assert {:ok, identity} = HeaderVerifier.verify_request(headers, secret: @secret)
      assert identity["node_id"] == "abc123"
      assert identity["node_name"] == "node1.corp.ztlp"
      assert identity["zone"] == "corp.ztlp"
      assert identity["authenticated"] == "true"
    end

    test "returns identity map with all fields" do
      headers = make_signed_headers()
      {:ok, identity} = HeaderVerifier.verify_request(headers, secret: @secret)

      assert Map.has_key?(identity, "node_id")
      assert Map.has_key?(identity, "node_name")
      assert Map.has_key?(identity, "zone")
      assert Map.has_key?(identity, "authenticated")
      assert Map.has_key?(identity, "assurance")
      assert Map.has_key?(identity, "key_source")
      assert Map.has_key?(identity, "key_attestation")
      assert Map.has_key?(identity, "cert_fingerprint")
      assert Map.has_key?(identity, "cert_serial")
      assert Map.has_key?(identity, "timestamp")
      assert Map.has_key?(identity, "nonce")
      assert Map.has_key?(identity, "request_id")
    end

    test "invalid signature is rejected" do
      headers = make_signed_headers()
      # Tamper with the signature
      tampered =
        Enum.map(headers, fn
          {"X-ZTLP-Signature", _} -> {"X-ZTLP-Signature", "deadbeef" <> String.duplicate("0", 56)}
          other -> other
        end)

      assert {:error, :invalid_signature} =
               HeaderVerifier.verify_request(tampered, secret: @secret)
    end

    test "wrong secret is rejected" do
      headers = make_signed_headers()
      assert {:error, :invalid_signature} =
               HeaderVerifier.verify_request(headers, secret: "wrong-secret")
    end

    test "missing signature is rejected" do
      headers =
        make_signed_headers()
        |> Enum.reject(fn {name, _} -> name == "X-ZTLP-Signature" end)

      assert {:error, :missing_signature} =
               HeaderVerifier.verify_request(headers, secret: @secret)
    end

    test "expired timestamp is rejected" do
      past = DateTime.utc_now() |> DateTime.add(-120, :second) |> DateTime.to_iso8601()
      headers = make_signed_headers(timestamp: past)

      assert {:error, :expired} =
               HeaderVerifier.verify_request(headers, secret: @secret, max_age_seconds: 60)
    end

    test "custom max_age_seconds works" do
      past = DateTime.utc_now() |> DateTime.add(-90, :second) |> DateTime.to_iso8601()
      headers = make_signed_headers(timestamp: past)

      # 60 seconds — should fail
      assert {:error, :expired} =
               HeaderVerifier.verify_request(headers, secret: @secret, max_age_seconds: 60)

      # 120 seconds — should pass
      assert {:ok, _} =
               HeaderVerifier.verify_request(headers, secret: @secret, max_age_seconds: 120)
    end

    test "nonce replay is detected when check_nonce is true" do
      nonce = ZtlpGateway.HttpHeaderInjector.generate_nonce()
      headers = make_signed_headers(nonce: nonce)

      # First request succeeds
      assert {:ok, _} =
               HeaderVerifier.verify_request(headers, secret: @secret, check_nonce: true)

      # Second request with same nonce fails
      assert {:error, :replayed} =
               HeaderVerifier.verify_request(headers, secret: @secret, check_nonce: true)
    end

    test "nonce replay is not checked by default" do
      nonce = ZtlpGateway.HttpHeaderInjector.generate_nonce()
      headers = make_signed_headers(nonce: nonce)

      assert {:ok, _} = HeaderVerifier.verify_request(headers, secret: @secret)
      # Without check_nonce: true, same nonce should still pass
      assert {:ok, _} = HeaderVerifier.verify_request(headers, secret: @secret)
    end

    test "tampered header value is caught by signature check" do
      headers = make_signed_headers()
      tampered =
        Enum.map(headers, fn
          {"X-ZTLP-Node-ID", _} -> {"X-ZTLP-Node-ID", "tampered-id"}
          other -> other
        end)

      assert {:error, :invalid_signature} =
               HeaderVerifier.verify_request(tampered, secret: @secret)
    end

    test "non-ZTLP headers are ignored" do
      headers = make_signed_headers() ++ [
        {"Host", "example.com"},
        {"Content-Type", "application/json"}
      ]

      assert {:ok, _} = HeaderVerifier.verify_request(headers, secret: @secret)
    end
  end
end
