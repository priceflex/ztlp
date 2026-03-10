defmodule ZtlpNs.BootstrapTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.{Crypto, Record, Bootstrap}

  describe "verify_response/1" do
    test "accepts valid signed bootstrap record" do
      {_pub, priv} = Crypto.generate_keypair()
      relays = [
        %{node_id: "aabbccdd", endpoints: ["1.2.3.4:23095"], public_key: "deadbeef"},
        %{node_id: "11223344", endpoints: ["5.6.7.8:23095"], public_key: "cafebabe"}
      ]
      record = Record.new_bootstrap("bootstrap.ztlp", relays,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      signed = Record.sign(record, priv)

      assert {:ok, returned_relays} = Bootstrap.verify_response(signed)
      assert length(returned_relays) == 2
    end

    test "rejects unsigned bootstrap record" do
      relays = [%{node_id: "aabb", endpoints: ["1.2.3.4:23095"], public_key: "dead"}]
      record = Record.new_bootstrap("bootstrap.ztlp", relays)
      assert {:error, :invalid_signature} = Bootstrap.verify_response(record)
    end

    test "rejects non-bootstrap record" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, priv} = Crypto.generate_keypair()
      record = Record.new_key("test.ztlp", node_id, pub)
      signed = Record.sign(record, priv)
      assert {:error, :not_a_bootstrap_record} = Bootstrap.verify_response(signed)
    end
  end

  describe "discover_hardcoded/0" do
    test "returns error when no hardcoded relays set" do
      assert {:error, :no_hardcoded_relays} = Bootstrap.discover_hardcoded()
    end

    test "returns relays when set" do
      {_pub, priv} = Crypto.generate_keypair()
      relay = Record.new_relay("r.ztlp", :crypto.strong_rand_bytes(16), ["1.2.3.4:23095"], 100, "us")
      relay = Record.sign(relay, priv)
      Bootstrap.set_hardcoded_relays([relay])
      assert {:ok, [returned]} = Bootstrap.discover_hardcoded()
      assert returned.type == :relay
    end
  end

  describe "discover_dns_srv/0" do
    test "returns not_implemented (prototype)" do
      assert {:error, :not_implemented} = Bootstrap.discover_dns_srv()
    end
  end

  describe "discover/0" do
    test "falls through to hardcoded when available" do
      {_pub, priv} = Crypto.generate_keypair()
      relay = Record.new_relay("r.ztlp", :crypto.strong_rand_bytes(16), ["1.2.3.4:23095"], 100, "us")
      relay = Record.sign(relay, priv)
      Bootstrap.set_hardcoded_relays([relay])

      assert {:ok, relays} = Bootstrap.discover()
      assert length(relays) == 1
    end

    test "returns error when all steps fail" do
      # Clear any hardcoded relays
      Process.delete(:ztlp_hardcoded_relays)
      assert {:error, :bootstrap_failed} = Bootstrap.discover()
    end
  end
end
