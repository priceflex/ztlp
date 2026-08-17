defmodule ZtlpNs.EndpointAuthTest do
  @moduledoc """
  Verifies `ZtlpNs.EndpointAuth` — the Ed25519 authentication for
  PEER_ENDPOINTS (0x0A) and PUNCH_REPORT (0x0C) endpoint-tracking requests.

  ## Background (irt-rwzo)

  Before this fix, the 0x0A/0x0C UDP handlers accepted a `node_id` from the
  packet with zero authentication: any UDP sender could claim to be any node
  and poison the `EndpointStore` (endpoint-store poisoning / hole-punch
  hijack, CWE-284). The NS-side half verifies a signature over
  `node_id || timestamp` AND enforces that the claimed pubkey is the one
  legitimately registered for that node_id (strict-if-registered) or the one
  pinned on first sight (TOFU).

  These tests pin the NS-side contract, with special attention to the exact
  bug that shipped in the live full-stack deploy: the Rust registration path
  originally sent the X25519 `static_public_key` in the KEY record while the
  punch-agent signed PUNCH_REPORT with the Ed25519 key, so `check_ownership`
  rejected every legitimate claim as `:not_key_owner`. The "register key ==
  signer key" test below is the NS-side mirror of the Rust regression test
  (`ns_publish_self_key_record_uses_ed25519_signing_pubkey_not_x25519`).
  """

  use ExUnit.Case, async: false

  require Bitwise
  alias ZtlpNs.{Crypto, EndpointAuth, Record, Store}

  @node_id :binary.decode_hex("82abae07daadbaf003a84b96d7de8dc6")

  # The message the NS reconstructs from a (node_id, timestamp) pair and
  # verifies the signature against — must match ZtlpNs.EndpointAuth
  # `check_signature/4` byte-for-byte.
  defp claim_message(node_id, timestamp),
    do: <<node_id::binary-size(16), timestamp::unsigned-big-64>>

  setup do
    Store.clear()
    EndpointAuth.init()
    EndpointAuth.clear_pins()

    on_exit(fn ->
      EndpointAuth.clear_pins()
      Store.clear()
    end)

    :ok
  end

  # Insert a SIGNED KEY record binding @node_id to the given 32-byte pubkey,
  # mirroring what `ztlp ns register` writes (Record.new_key hex-encodes the
  # pubkey; the record is Ed25519-signed so Store.insert accepts it).
  #
  # Note: the record's SIGNER key is irrelevant to check_ownership — it only
  # reads record.data.node_id + record.data.public_key. We sign with a throwaway
  # CA key purely to satisfy the Store.insert signature invariant.
  defp register_key(pubkey) do
    {_signer_pub, signer_priv} = Crypto.generate_keypair()
    record = Record.new_key("server.fullstack.ztlp", @node_id, pubkey, serial: 1)
    signed = Record.sign(record, signer_priv)
    assert :ok = Store.insert(signed)
  end

  describe "strict path: KEY record already registered (the irt-rwzo case)" do
    test "accepts a claim signed by the registered key (register key == signer key)" do
      {pub, priv} = Crypto.generate_keypair()
      register_key(pub)
      ts = System.system_time(:second)
      sig = Crypto.sign(claim_message(@node_id, ts), priv)

      assert :ok = EndpointAuth.verify_and_bind(@node_id, ts, sig, pub)
    end

    test "rejects a claim signed by a DIFFERENT key as :not_key_owner (the original bug)" do
      # The KEY record was registered with pub_A (e.g. the Ed25519 signing key),
      # but the claimant signs/sends pub_B (e.g. the legacy X25519 key, or an
      # attacker's throwaway key). check_ownership must reject.
      {registered_pub, _registered_priv} = Crypto.generate_keypair()
      register_key(registered_pub)

      {imposter_pub, imposter_priv} = Crypto.generate_keypair()
      ts = System.system_time(:second)
      # A VALID signature from the imposter's own key — passes check_signature,
      # so the rejection must come from check_ownership, not the sig check.
      sig = Crypto.sign(claim_message(@node_id, ts), imposter_priv)

      assert {:error, :not_key_owner} =
               EndpointAuth.verify_and_bind(@node_id, ts, sig, imposter_pub)
    end
  end

  describe "signature verification" do
    test "rejects a tampered signature as :invalid_signature (TOFU path)" do
      {pub, priv} = Crypto.generate_keypair()
      ts = System.system_time(:second)
      good_sig = Crypto.sign(claim_message(@node_id, ts), priv)
      # Flip the very first byte — always changes the signature, so it can
      # never accidentally remain a valid signature.
      <<first_byte::8, rest::binary>> = good_sig
      flipped = Bitwise.bxor(first_byte, 0xFF)
      tampered = <<flipped, rest::binary>>

      assert {:error, :invalid_signature} =
               EndpointAuth.verify_and_bind(@node_id, ts, tampered, pub)
    end

    test "rejects a signature over the wrong timestamp" do
      {pub, priv} = Crypto.generate_keypair()
      ts = System.system_time(:second)
      # Sign a different timestamp than the one claimed in the request.
      sig = Crypto.sign(claim_message(@node_id, ts + 1), priv)

      assert {:error, :invalid_signature} =
               EndpointAuth.verify_and_bind(@node_id, ts, sig, pub)
    end
  end

  describe "timestamp (replay protection)" do
    test "rejects a stale timestamp as :stale_timestamp even with a valid signature" do
      {pub, priv} = Crypto.generate_keypair()
      # A timestamp 10 minutes in the past is outside @max_skew_seconds (120s),
      # so it fails before the signature is even considered.
      stale = System.system_time(:second) - 600
      sig = Crypto.sign(claim_message(@node_id, stale), priv)

      assert {:error, :stale_timestamp} =
               EndpointAuth.verify_and_bind(@node_id, stale, sig, pub)
    end

    test "accepts a timestamp within the allowed skew window" do
      {pub, priv} = Crypto.generate_keypair()
      # 60s in the past is within the 120s skew window.
      ts = System.system_time(:second) - 60
      sig = Crypto.sign(claim_message(@node_id, ts), priv)

      assert :ok = EndpointAuth.verify_and_bind(@node_id, ts, sig, pub)
    end
  end

  describe "TOFU path: no KEY record registered yet" do
    test "pins the first pubkey seen, then accepts the same key" do
      {pub, priv} = Crypto.generate_keypair()
      ts = System.system_time(:second)
      sig = Crypto.sign(claim_message(@node_id, ts), priv)

      # First claim: no record, no pin -> pins pub, returns :ok.
      assert :ok = EndpointAuth.verify_and_bind(@node_id, ts, sig, pub)

      # Second claim with the same pinned key: still :ok.
      ts2 = System.system_time(:second)
      sig2 = Crypto.sign(claim_message(@node_id, ts2), priv)
      assert :ok = EndpointAuth.verify_and_bind(@node_id, ts2, sig2, pub)
    end

    test "rejects a later claim with a DIFFERENT pubkey as :pubkey_mismatch" do
      {first_pub, first_priv} = Crypto.generate_keypair()
      ts = System.system_time(:second)
      sig = Crypto.sign(claim_message(@node_id, ts), first_priv)
      assert :ok = EndpointAuth.verify_and_bind(@node_id, ts, sig, first_pub)

      # A second, different key trying to take over the same node_id:
      # check_ownership sees a pin with a different pubkey -> rejected.
      {other_pub, other_priv} = Crypto.generate_keypair()
      ts2 = System.system_time(:second)
      sig2 = Crypto.sign(claim_message(@node_id, ts2), other_priv)
      assert {:error, :pubkey_mismatch} =
               EndpointAuth.verify_and_bind(@node_id, ts2, sig2, other_pub)
    end
  end

  describe "malformed inputs" do
    test "rejects a node_id that is not exactly 16 bytes as :malformed" do
      {pub, priv} = Crypto.generate_keypair()
      ts = System.system_time(:second)
      sig = Crypto.sign(claim_message(@node_id, ts), priv)

      assert {:error, :malformed} =
               EndpointAuth.verify_and_bind(@node_id <> <<0x00>>, ts, sig, pub)
    end
  end
end
