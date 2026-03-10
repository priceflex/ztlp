defmodule ZtlpNs.ZoneAuthorityTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.{Crypto, Record, ZoneAuthority}

  describe "generate/1" do
    test "creates authority with keypair and zone" do
      auth = ZoneAuthority.generate("example.ztlp")
      assert auth.zone.name == "example.ztlp"
      assert auth.zone.parent_name == "ztlp"
      assert byte_size(auth.public_key) == 32
      assert byte_size(auth.private_key) == 32
    end

    test "root zone has nil parent" do
      auth = ZoneAuthority.generate("ztlp")
      assert auth.zone.parent_name == nil
    end
  end

  describe "sign_record/2" do
    test "signs a record within the zone" do
      auth = ZoneAuthority.generate("acme.ztlp")
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("node1.acme.ztlp", node_id, pub)
      assert {:ok, signed} = ZoneAuthority.sign_record(auth, record)
      assert Record.verify(signed)
      assert signed.signer_public_key == auth.public_key
    end

    test "rejects record outside the zone" do
      auth = ZoneAuthority.generate("acme.ztlp")
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("node1.other.ztlp", node_id, pub)
      assert {:error, :not_in_zone} = ZoneAuthority.sign_record(auth, record)
    end

    test "signs the zone apex itself" do
      auth = ZoneAuthority.generate("acme.ztlp")
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("acme.ztlp", node_id, pub)
      assert {:ok, signed} = ZoneAuthority.sign_record(auth, record)
      assert Record.verify(signed)
    end
  end

  describe "delegate/2" do
    test "creates a signed delegation record" do
      root = ZoneAuthority.generate("ztlp")
      operator = ZoneAuthority.generate("example.ztlp")

      delegation = ZoneAuthority.delegate(root, operator)
      assert delegation.type == :key
      assert delegation.name == "example.ztlp"
      assert delegation.data[:delegation] == true
      assert Record.verify(delegation)
      # Signed by the root authority
      assert delegation.signer_public_key == root.public_key
    end

    test "delegation contains child's public key" do
      root = ZoneAuthority.generate("ztlp")
      child = ZoneAuthority.generate("child.ztlp")

      delegation = ZoneAuthority.delegate(root, child)
      assert delegation.data[:public_key] == Base.encode16(child.public_key, case: :lower)
    end
  end

  describe "verify_record/2" do
    test "verifies record signed by expected authority" do
      auth = ZoneAuthority.generate("test.ztlp")
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("node.test.ztlp", node_id, pub)
      {:ok, signed} = ZoneAuthority.sign_record(auth, record)

      assert ZoneAuthority.verify_record(signed, auth.public_key)
    end

    test "rejects record signed by different authority" do
      auth1 = ZoneAuthority.generate("zone1.ztlp")
      auth2 = ZoneAuthority.generate("zone2.ztlp")
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("node.zone1.ztlp", node_id, pub)
      {:ok, signed} = ZoneAuthority.sign_record(auth1, record)

      refute ZoneAuthority.verify_record(signed, auth2.public_key)
    end
  end
end
