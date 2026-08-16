defmodule ZtlpNs.EndpointAuthTest do
  use ExUnit.Case, async: false

  alias ZtlpNs.{Crypto, EndpointAuth, Record, Store}

  @moduledoc """
  Unit tests for ZtlpNs.EndpointAuth -- the irt-rwzo fix.

  Covers the core ownership policy directly (verify_and_bind/4) rather
  than through the full UDP wire protocol (see punch_protocol_test.exs
  for those integration-level checks).
  """

  setup do
    EndpointAuth.clear_pins()
    :ok
  end

  defp gen_identity, do: :crypto.generate_key(:eddsa, :ed25519)

  defp sign_claim(node_id, timestamp, priv) do
    message = <<node_id::binary-size(16), timestamp::unsigned-big-64>>
    Crypto.sign(message, priv)
  end

  describe "signature verification" do
    test "accepts a valid signature for a fresh (unregistered) node_id" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, priv} = gen_identity()
      timestamp = System.system_time(:second)
      sig = sign_claim(node_id, timestamp, priv)

      assert :ok = EndpointAuth.verify_and_bind(node_id, timestamp, sig, pub)
    end

    test "rejects an invalid signature" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _priv} = gen_identity()
      {_other_pub, other_priv} = gen_identity()
      timestamp = System.system_time(:second)
      # Sign with a DIFFERENT key than the pubkey we claim.
      bad_sig = sign_claim(node_id, timestamp, other_priv)

      assert {:error, :invalid_signature} =
               EndpointAuth.verify_and_bind(node_id, timestamp, bad_sig, pub)
    end

    test "rejects a signature over the wrong node_id (replay against a different target)" do
      node_id = :crypto.strong_rand_bytes(16)
      other_node_id = :crypto.strong_rand_bytes(16)
      {pub, priv} = gen_identity()
      timestamp = System.system_time(:second)
      # Sign a claim for other_node_id, then try to use it for node_id.
      sig = sign_claim(other_node_id, timestamp, priv)

      assert {:error, :invalid_signature} =
               EndpointAuth.verify_and_bind(node_id, timestamp, sig, pub)
    end

    test "rejects a stale timestamp (replay protection)" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, priv} = gen_identity()
      # 10 minutes in the past -- well beyond the skew tolerance.
      timestamp = System.system_time(:second) - 600
      sig = sign_claim(node_id, timestamp, priv)

      assert {:error, :stale_timestamp} =
               EndpointAuth.verify_and_bind(node_id, timestamp, sig, pub)
    end

    test "rejects a timestamp too far in the future" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, priv} = gen_identity()
      timestamp = System.system_time(:second) + 600
      sig = sign_claim(node_id, timestamp, priv)

      assert {:error, :stale_timestamp} =
               EndpointAuth.verify_and_bind(node_id, timestamp, sig, pub)
    end
  end

  describe "TOFU pinning (no registered record)" do
    test "the second claim with a DIFFERENT pubkey for the same node_id is rejected" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub_a, priv_a} = gen_identity()
      {pub_b, priv_b} = gen_identity()

      ts1 = System.system_time(:second)
      sig1 = sign_claim(node_id, ts1, priv_a)
      assert :ok = EndpointAuth.verify_and_bind(node_id, ts1, sig1, pub_a)

      # A second, DIFFERENT key claiming the same node_id -- this is the
      # attack irt-rwzo closes: without TOFU pinning, this would silently
      # succeed and let the attacker hijack node_id's endpoint tracking.
      ts2 = System.system_time(:second)
      sig2 = sign_claim(node_id, ts2, priv_b)

      assert {:error, :pubkey_mismatch} =
               EndpointAuth.verify_and_bind(node_id, ts2, sig2, pub_b)
    end

    test "repeated claims with the SAME pubkey for the same node_id all succeed" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, priv} = gen_identity()

      for _ <- 1..5 do
        ts = System.system_time(:second)
        sig = sign_claim(node_id, ts, priv)
        assert :ok = EndpointAuth.verify_and_bind(node_id, ts, sig, pub)
      end
    end

    test "different node_ids can be pinned independently" do
      node_id_a = :crypto.strong_rand_bytes(16)
      node_id_b = :crypto.strong_rand_bytes(16)
      {pub_a, priv_a} = gen_identity()
      {pub_b, priv_b} = gen_identity()

      ts = System.system_time(:second)
      assert :ok =
               EndpointAuth.verify_and_bind(node_id_a, ts, sign_claim(node_id_a, ts, priv_a), pub_a)

      assert :ok =
               EndpointAuth.verify_and_bind(node_id_b, ts, sign_claim(node_id_b, ts, priv_b), pub_b)
    end
  end

  describe "strict path (registered KEY record exists)" do
    setup do
      node_id = :crypto.strong_rand_bytes(16)
      {registered_pub, registered_priv} = gen_identity()
      {ns_pub, ns_priv} = gen_identity()

      key_record = %Record{
        name: "device-under-test-#{System.unique_integer([:positive])}.ztlp",
        type: :key,
        data: %{
          "algorithm" => "Ed25519",
          "node_id" => Base.encode16(node_id, case: :lower),
          "public_key" => Base.encode16(registered_pub, case: :lower)
        },
        created_at: System.system_time(:second),
        ttl: 86_400,
        serial: System.system_time(:second),
        signature: nil,
        signer_public_key: nil
      }

      signed = Record.sign(key_record, ns_priv)
      :ok = Store.insert(signed)

      on_exit(fn ->
        # Best-effort cleanup -- Store doesn't expose a generic delete,
        # so just let subsequent tests use fresh random node_ids
        # (collision probability with 16 random bytes is negligible).
        :ok
      end)

      %{node_id: node_id, registered_pub: registered_pub, registered_priv: registered_priv, ns_pub: ns_pub}
    end

    test "accepts a claim signed by the REGISTERED pubkey", %{
      node_id: node_id,
      registered_pub: registered_pub,
      registered_priv: registered_priv
    } do
      ts = System.system_time(:second)
      sig = sign_claim(node_id, ts, registered_priv)

      assert :ok = EndpointAuth.verify_and_bind(node_id, ts, sig, registered_pub)
    end

    test "rejects a claim signed by a DIFFERENT (attacker) pubkey, even with a valid self-signature",
         %{node_id: node_id} do
      {attacker_pub, attacker_priv} = gen_identity()
      ts = System.system_time(:second)
      # The attacker's signature IS internally valid -- they really do
      # control attacker_priv -- but attacker_pub doesn't match what's
      # registered for this node_id. This is the core guarantee: a
      # valid Ed25519 signature alone is not sufficient authorization.
      sig = sign_claim(node_id, ts, attacker_priv)

      assert {:error, :not_key_owner} =
               EndpointAuth.verify_and_bind(node_id, ts, sig, attacker_pub)
    end

    test "the strict path takes priority over any prior TOFU pin", %{
      node_id: node_id,
      registered_pub: registered_pub,
      registered_priv: registered_priv
    } do
      # Simulate an attacker having TOFU-pinned themselves to this
      # node_id BEFORE registration existed (e.g. raced the real
      # device during a brief pre-enrollment window). Once a real KEY
      # record exists, verify_and_bind must ignore the stale pin and
      # trust the registered record instead.
      {attacker_pub, attacker_priv} = gen_identity()
      ts0 = System.system_time(:second)
      # Note: verify_and_bind checks the registered record FIRST, so
      # this call actually already hits the strict path and correctly
      # rejects the attacker -- demonstrating no TOFU pin ever gets a
      # chance to form once registration exists.
      sig0 = sign_claim(node_id, ts0, attacker_priv)
      assert {:error, :not_key_owner} =
               EndpointAuth.verify_and_bind(node_id, ts0, sig0, attacker_pub)

      # The legitimate owner still succeeds afterward.
      ts1 = System.system_time(:second)
      sig1 = sign_claim(node_id, ts1, registered_priv)
      assert :ok = EndpointAuth.verify_and_bind(node_id, ts1, sig1, registered_pub)
    end
  end

  describe "malformed input" do
    test "rejects a node_id that isn't exactly 16 bytes" do
      {pub, priv} = gen_identity()
      timestamp = System.system_time(:second)
      short_node_id = :crypto.strong_rand_bytes(8)
      sig = Crypto.sign(<<short_node_id::binary, timestamp::unsigned-big-64>>, priv)

      assert {:error, :malformed} =
               EndpointAuth.verify_and_bind(short_node_id, timestamp, sig, pub)
    end
  end
end
