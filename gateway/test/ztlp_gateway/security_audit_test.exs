defmodule ZtlpGateway.SecurityAuditTest do
  @moduledoc """
  Security audit tests for the ZTLP Gateway.

  These tests verify that security hardening measures are in place
  and that common attack vectors are mitigated.
  """

  use ExUnit.Case

  alias ZtlpGateway.PolicyEngine

  setup do
    # Ensure PolicyEngine is running
    case GenServer.whereis(PolicyEngine) do
      nil ->
        {:ok, pid} = PolicyEngine.start_link()
        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5000)
        end)
        :ok

      _pid ->
        :ok
    end
  end

  describe "policy engine ETS table protection" do
    test "policy table is protected (not writable by other processes)" do
      # The policy engine ETS table should be :protected, meaning
      # only the owning GenServer can write to it
      info = :ets.info(:ztlp_gateway_policies)
      assert info[:protection] == :protected
    end

    test "put_rule works through GenServer" do
      PolicyEngine.put_rule("security-test-service", :all)
      assert PolicyEngine.authorize?("any-node", "security-test-service")
      PolicyEngine.delete_rule("security-test-service")
    end

    test "direct ETS write from non-owner process fails" do
      # This should raise an ArgumentError because the table is :protected
      assert_raise ArgumentError, fn ->
        :ets.insert(:ztlp_gateway_policies, {"hacked-service", :all})
      end
    end
  end

  describe "no hardcoded default signing secret" do
    test "default_secret returns nil when no secret configured" do
      prev = Application.get_env(:ztlp_gateway, :header_signing_secret)
      Application.delete_env(:ztlp_gateway, :header_signing_secret)

      assert is_nil(ZtlpGateway.HeaderSigner.default_secret())

      if prev, do: Application.put_env(:ztlp_gateway, :header_signing_secret, prev)
    end

    test "default_secret returns configured value" do
      prev = Application.get_env(:ztlp_gateway, :header_signing_secret)
      Application.put_env(:ztlp_gateway, :header_signing_secret, "my-custom-secret")

      assert "my-custom-secret" == ZtlpGateway.HeaderSigner.default_secret()

      if prev do
        Application.put_env(:ztlp_gateway, :header_signing_secret, prev)
      else
        Application.delete_env(:ztlp_gateway, :header_signing_secret)
      end
    end
  end

  describe "wildcard matching safety" do
    test "wildcard only matches suffix after dot" do
      PolicyEngine.put_rule("test-wildcard", ["*.ops.ztlp"])

      # Should match
      assert PolicyEngine.authorize?("node1.ops.ztlp", "test-wildcard")
      assert PolicyEngine.authorize?("deep.nested.ops.ztlp", "test-wildcard")

      # Should NOT match — no dot before suffix
      refute PolicyEngine.authorize?("ops.ztlp", "test-wildcard")
      refute PolicyEngine.authorize?("malicious-ops.ztlp", "test-wildcard")

      PolicyEngine.delete_rule("test-wildcard")
    end

    test "wildcard pattern doesn't allow regex injection" do
      # Patterns with regex-like characters should be treated literally
      PolicyEngine.put_rule("test-regex", ["*.evil.*"])

      # This should NOT match because it's not regex — it's literal String.ends_with?
      refute PolicyEngine.authorize?("node.evil.ztlp", "test-regex")

      PolicyEngine.delete_rule("test-regex")
    end
  end

  describe "constant-time signature comparison" do
    test "signature verification uses constant-time comparison" do
      # Both valid and invalid signatures should take similar time
      # We can't truly test timing, but we verify the function works correctly
      headers = [{"X-ZTLP-Node-ID", "test"}]
      secret = "test-secret"
      sig = ZtlpGateway.HeaderSigner.sign(headers, secret)

      assert ZtlpGateway.HeaderSigner.verify(headers, sig, secret)
      refute ZtlpGateway.HeaderSigner.verify(headers, "x" <> String.slice(sig, 1..-1//1), secret)

      # Different length should also fail
      refute ZtlpGateway.HeaderSigner.verify(headers, "short", secret)
    end
  end

  describe "nonce uniqueness" do
    test "generated nonces have sufficient entropy (16 bytes)" do
      nonces = for _ <- 1..100, do: ZtlpGateway.HttpHeaderInjector.generate_nonce()

      # All should be unique
      assert length(Enum.uniq(nonces)) == 100

      # All should be 32 hex chars (16 bytes)
      assert Enum.all?(nonces, fn n -> byte_size(n) == 32 end)
    end
  end

  describe "request ID format" do
    test "request IDs are valid UUID v4" do
      for _ <- 1..50 do
        id = ZtlpGateway.HttpHeaderInjector.generate_request_id()
        # UUID v4: version nibble is 4, variant bits are 10xx
        assert Regex.match?(~r/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, id),
               "Invalid UUID v4: #{id}"
      end
    end
  end

  describe "session state machine safety" do
    test "handshake split requires complete phase" do
      # Attempting to split with incomplete handshake should fail
      state = %{phase: :initialized}
      assert {:error, :handshake_incomplete} = ZtlpGateway.Handshake.split(state)
    end

    test "handshake msg1 rejects short messages" do
      {pub, priv} = ZtlpGateway.Crypto.generate_keypair()
      state = ZtlpGateway.Handshake.init_responder(pub, priv)

      assert {:error, :msg1_too_short} = ZtlpGateway.Handshake.handle_msg1(state, <<1, 2, 3>>)
    end

    test "handshake msg3 rejects short messages" do
      {pub, priv} = ZtlpGateway.Crypto.generate_keypair()
      state = %{ZtlpGateway.Handshake.init_responder(pub, priv) | phase: :sent_msg2, n: 0, k: :crypto.strong_rand_bytes(32), ck: :crypto.strong_rand_bytes(32)}

      assert {:error, :msg3_too_short} = ZtlpGateway.Handshake.handle_msg3(state, <<1, 2, 3>>)
    end
  end

  describe "header anti-forgery" do
    test "strip_ztlp_headers removes all X-ZTLP-* variants" do
      request = "GET / HTTP/1.1\r\nHost: example.com\r\nX-ZTLP-Node-ID: forged\r\nx-ztlp-zone: evil\r\nX-Ztlp-Assurance: hardware\r\n\r\n"
      stripped = ZtlpGateway.HttpHeaderInjector.strip_ztlp_headers(request)

      refute String.contains?(stripped, "forged")
      refute String.contains?(stripped, "evil")
      # Note: the case-insensitive prefix check handles mixed-case
    end
  end
end
