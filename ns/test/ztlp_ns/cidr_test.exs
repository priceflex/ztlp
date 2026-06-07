defmodule ZtlpNs.CidrTest do
  use ExUnit.Case, async: true
  alias ZtlpNs.Cidr

  describe "parse/1 — happy paths" do
    test "parses 172.18.0.0/16" do
      assert {:ok, %Cidr{base: {172, 18, 0, 0}, mask_bits: 16}} = Cidr.parse("172.18.0.0/16")
    end

    test "parses 127.0.0.1/32 (single host)" do
      assert {:ok, %Cidr{base: {127, 0, 0, 1}, mask_bits: 32}} = Cidr.parse("127.0.0.1/32")
    end

    test "parses 0.0.0.0/0 (allow-all)" do
      assert {:ok, %Cidr{base: {0, 0, 0, 0}, mask_bits: 0}} = Cidr.parse("0.0.0.0/0")
    end

    test "host bits set are normalized — 172.18.1.5/16 parses to base 172.18.0.0" do
      assert {:ok, %Cidr{base: {172, 18, 0, 0}, mask_bits: 16}} = Cidr.parse("172.18.1.5/16")
    end
  end

  describe "parse/1 — rejection" do
    test "rejects mask > 32" do
      assert {:error, :invalid_mask} = Cidr.parse("172.18.0.0/33")
    end

    test "rejects malformed address" do
      assert {:error, :invalid_address} = Cidr.parse("not.an.ip/24")
    end

    test "rejects empty string" do
      assert {:error, :invalid_format} = Cidr.parse("")
    end

    test "rejects nil" do
      assert {:error, :invalid_input} = Cidr.parse(nil)
    end

    test "rejects IPv6 with explicit reason" do
      assert {:error, :ipv6_not_supported} = Cidr.parse("::1/128")
    end

    test "rejects missing slash" do
      assert {:error, :invalid_format} = Cidr.parse("172.18.0.0")
    end
  end

  describe "match?/2" do
    test "172.18.1.5 in 172.18.0.0/16 — true" do
      {:ok, cidr} = Cidr.parse("172.18.0.0/16")
      assert Cidr.match?(cidr, {172, 18, 1, 5})
    end

    test "172.19.1.5 in 172.18.0.0/16 — false" do
      {:ok, cidr} = Cidr.parse("172.18.0.0/16")
      refute Cidr.match?(cidr, {172, 19, 1, 5})
    end

    test "127.0.0.1 in 127.0.0.0/8 — true" do
      {:ok, cidr} = Cidr.parse("127.0.0.0/8")
      assert Cidr.match?(cidr, {127, 0, 0, 1})
    end

    test "8.8.8.8 in 127.0.0.0/8 — false" do
      {:ok, cidr} = Cidr.parse("127.0.0.0/8")
      refute Cidr.match?(cidr, {8, 8, 8, 8})
    end

    test "any IP in 0.0.0.0/0 — true" do
      {:ok, cidr} = Cidr.parse("0.0.0.0/0")
      assert Cidr.match?(cidr, {1, 2, 3, 4})
      assert Cidr.match?(cidr, {255, 255, 255, 255})
    end

    test "boundary: 172.18.0.0 in 172.18.0.0/16 — true (network address itself)" do
      {:ok, cidr} = Cidr.parse("172.18.0.0/16")
      assert Cidr.match?(cidr, {172, 18, 0, 0})
    end

    test "boundary: 172.18.255.255 in 172.18.0.0/16 — true (broadcast)" do
      {:ok, cidr} = Cidr.parse("172.18.0.0/16")
      assert Cidr.match?(cidr, {172, 18, 255, 255})
    end
  end
end
