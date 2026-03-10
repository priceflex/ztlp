defmodule ZtlpNs.TrustAnchorTest do
  use ExUnit.Case

  alias ZtlpNs.{Crypto, TrustAnchor}

  # TrustAnchor uses a named ETS table, so tests must be sequential
  setup do
    TrustAnchor.clear()
    :ok
  end

  describe "add/2 and trusted?/1" do
    test "added key is trusted" do
      {pub, _priv} = Crypto.generate_keypair()
      TrustAnchor.add("test-root", pub)
      assert TrustAnchor.trusted?(pub)
    end

    test "unknown key is not trusted" do
      {pub, _priv} = Crypto.generate_keypair()
      refute TrustAnchor.trusted?(pub)
    end

    test "can add multiple anchors" do
      {pub1, _} = Crypto.generate_keypair()
      {pub2, _} = Crypto.generate_keypair()
      TrustAnchor.add("root-1", pub1)
      TrustAnchor.add("root-2", pub2)
      assert TrustAnchor.trusted?(pub1)
      assert TrustAnchor.trusted?(pub2)
    end
  end

  describe "list/0" do
    test "empty on start" do
      assert TrustAnchor.list() == []
    end

    test "lists added anchors" do
      {pub, _} = Crypto.generate_keypair()
      TrustAnchor.add("my-root", pub)
      anchors = TrustAnchor.list()
      assert length(anchors) == 1
      assert {"my-root", ^pub} = hd(anchors)
    end
  end

  describe "remove/1" do
    test "removes an anchor by label" do
      {pub, _} = Crypto.generate_keypair()
      TrustAnchor.add("temp", pub)
      assert TrustAnchor.trusted?(pub)
      TrustAnchor.remove("temp")
      refute TrustAnchor.trusted?(pub)
    end
  end

  describe "clear/0" do
    test "removes all anchors" do
      {pub1, _} = Crypto.generate_keypair()
      {pub2, _} = Crypto.generate_keypair()
      TrustAnchor.add("a", pub1)
      TrustAnchor.add("b", pub2)
      TrustAnchor.clear()
      assert TrustAnchor.list() == []
      refute TrustAnchor.trusted?(pub1)
      refute TrustAnchor.trusted?(pub2)
    end
  end
end
