defmodule ZtlpNs.ZoneTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.Zone

  describe "new/3" do
    test "creates a zone with name and public key" do
      zone = Zone.new("example.ztlp", <<1, 2, 3>>, "ztlp")
      assert zone.name == "example.ztlp"
      assert zone.public_key == <<1, 2, 3>>
      assert zone.parent_name == "ztlp"
    end

    test "root zone has nil parent" do
      zone = Zone.new("ztlp", <<1, 2, 3>>)
      assert zone.parent_name == nil
    end
  end

  describe "parent_name/1" do
    test "extracts parent from multi-level name" do
      assert Zone.parent_name("node1.office.acme.ztlp") == "office.acme.ztlp"
    end

    test "extracts parent from two-level name" do
      assert Zone.parent_name("acme.ztlp") == "ztlp"
    end

    test "root name returns nil" do
      assert Zone.parent_name("ztlp") == nil
    end
  end

  describe "contains?/2" do
    test "zone contains its own apex name" do
      zone = Zone.new("acme.ztlp", <<>>, "ztlp")
      assert Zone.contains?(zone, "acme.ztlp")
    end

    test "zone contains direct child" do
      zone = Zone.new("acme.ztlp", <<>>, "ztlp")
      assert Zone.contains?(zone, "node1.acme.ztlp")
    end

    test "zone contains deep child" do
      zone = Zone.new("acme.ztlp", <<>>, "ztlp")
      assert Zone.contains?(zone, "node1.office.acme.ztlp")
    end

    test "zone does not contain sibling" do
      zone = Zone.new("acme.ztlp", <<>>, "ztlp")
      refute Zone.contains?(zone, "other.ztlp")
    end

    test "zone does not contain parent" do
      zone = Zone.new("acme.ztlp", <<>>, "ztlp")
      refute Zone.contains?(zone, "ztlp")
    end

    test "zone does not match partial suffix" do
      zone = Zone.new("acme.ztlp", <<>>, "ztlp")
      # "fakeacme.ztlp" should NOT match "acme.ztlp"
      refute Zone.contains?(zone, "fakeacme.ztlp")
    end
  end
end
