defmodule ZtlpGateway.CborTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.Cbor

  # RFC 8949 Appendix A test vectors (subset relevant to the implemented
  # subset). Hex from the RFC.
  @rfc_vectors [
    {0, "00"},
    {1, "01"},
    {10, "0a"},
    {23, "17"},
    {24, "1818"},
    {25, "1819"},
    {100, "1864"},
    {1000, "1903e8"},
    {1_000_000, "1a000f4240"},
    {1_000_000_000_000, "1b000000e8d4a51000"},
    {18_446_744_073_709_551_615, "1bffffffffffffffff"},
    {-1, "20"},
    {-10, "29"},
    {-100, "3863"},
    {-1000, "3903e7"},
    {false, "f4"},
    {true, "f5"},
    {nil, "f6"},
    {"", "60"},
    {"a", "6161"},
    {"IETF", "6449455446"},
    {"\"\\", "62225c"},
    {"ü", "62c3bc"},
    {"水", "63e6b0b4"},
    {[], "80"},
    {[1, 2, 3], "83010203"},
    {[1, [2, 3], [4, 5]], "8301820203820405"},
    {Enum.to_list(1..25), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"},
    {%{}, "a0"},
    {%{"a" => 1, "b" => [2, 3]}, "a26161016162820203"},
    {["a", %{"b" => "c"}], "826161a161626163"},
    {%{"a" => "A", "b" => "B", "c" => "C", "d" => "D", "e" => "E"},
     "a56161614161626142616361436164614461656145"}
  ]

  defp hex(bin), do: Base.encode16(bin, case: :lower)
  defp unhex(h), do: Base.decode16!(h, case: :lower)

  describe "RFC 8949 Appendix A vectors" do
    for {term, expected_hex} <- @rfc_vectors do
      @term term
      @hex expected_hex
      test "encode #{inspect(term)} == #{expected_hex}" do
        assert hex(Cbor.encode(@term)) == @hex
      end

      test "decode #{expected_hex} == #{inspect(term)}" do
        assert Cbor.decode(unhex(@hex)) == {:ok, @term}
      end
    end
  end

  describe "byte strings vs text strings" do
    test "invalid UTF-8 is encoded as major type 2 (bytes)" do
      bin = <<0xFF, 0xFE, 0x00>>
      enc = Cbor.encode(bin)
      assert hex(enc) == "43fffe00"
      assert Cbor.decode(enc) == {:ok, bin}
    end

    test "valid UTF-8 is encoded as major type 3 (text)" do
      assert hex(Cbor.encode("hi")) == "626869"
    end

    test "RFC bytes vectors decode" do
      assert Cbor.decode(unhex("40")) == {:ok, ""}
      assert Cbor.decode(unhex("4401020304")) == {:ok, <<1, 2, 3, 4>>}
    end

    test "empty binary round-trips as text (String.valid? is true)" do
      assert hex(Cbor.encode("")) == "60"
    end
  end

  describe "integer width selection" do
    test "boundaries pick the smallest head" do
      assert byte_size(Cbor.encode(23)) == 1
      assert byte_size(Cbor.encode(24)) == 2
      assert byte_size(Cbor.encode(255)) == 2
      assert byte_size(Cbor.encode(256)) == 3
      assert byte_size(Cbor.encode(65_535)) == 3
      assert byte_size(Cbor.encode(65_536)) == 5
      assert byte_size(Cbor.encode(4_294_967_295)) == 5
      assert byte_size(Cbor.encode(4_294_967_296)) == 9
    end

    test "negative boundaries" do
      assert byte_size(Cbor.encode(-24)) == 1
      assert byte_size(Cbor.encode(-25)) == 2
      assert byte_size(Cbor.encode(-256)) == 2
      assert byte_size(Cbor.encode(-257)) == 3
      assert Cbor.decode(Cbor.encode(-18_446_744_073_709_551_616)) == {:ok, -18_446_744_073_709_551_616}
    end

    test "round-trips across the whole width range" do
      for n <- [0, 1, 23, 24, 255, 256, 65_535, 65_536, 4_294_967_295, 4_294_967_296, 2 ** 64 - 1,
                -1, -24, -25, -256, -257, -65_536, -65_537, -(2 ** 32), -(2 ** 32) - 1, -(2 ** 64)] do
        assert Cbor.decode(Cbor.encode(n)) == {:ok, n}, "n=#{n}"
      end
    end
  end

  describe "deterministic map encoding (RFC 8949 §4.2.1)" do
    test "keys are sorted length-first then bytewise regardless of insertion order" do
      a = Cbor.encode(%{"bb" => 1, "a" => 2, "c" => 3})
      b = Cbor.encode(%{"c" => 3, "a" => 2, "bb" => 1})
      assert a == b
      # order: "a"(1 byte), "c"(1 byte), "bb"(2 bytes)
      assert hex(a) == "a3616102616303626262 01" |> String.replace(" ", "")
    end

    test "atom keys are stringified and sort with string keys" do
      assert Cbor.encode(%{"b" => 2, a: 1}) == Cbor.encode(%{"a" => 1, "b" => 2})
    end

    test "integer keys are stringified via to_string" do
      assert Cbor.encode(%{1 => "x"}) == Cbor.encode(%{"1" => "x"})
    end

    test "nested maps are deterministic at every level" do
      x = Cbor.encode(%{"outer" => %{"z" => 1, "y" => 2}, "a" => [%{"q" => 1, "p" => 2}]})
      y = Cbor.encode(%{"a" => [%{"p" => 2, "q" => 1}], "outer" => %{"y" => 2, "z" => 1}})
      assert x == y
    end

    test "map round-trip yields string keys" do
      assert Cbor.decode(Cbor.encode(%{name: "svc", port: 443, tls: true, tags: ["a", "b"], none: nil})) ==
               {:ok, %{"name" => "svc", "port" => 443, "tls" => true, "tags" => ["a", "b"], "none" => nil}}
    end
  end

  describe "atoms" do
    test "non-boolean atoms encode as their text name" do
      assert Cbor.encode(:hello) == Cbor.encode("hello")
      assert Cbor.decode(Cbor.encode(:hello)) == {:ok, "hello"}
    end

    test "true/false/nil are simple values, not text" do
      assert hex(Cbor.encode(true)) == "f5"
      assert hex(Cbor.encode(false)) == "f4"
      assert hex(Cbor.encode(nil)) == "f6"
    end
  end

  describe "large / nested structures" do
    test "array with >255 items uses a 16-bit head" do
      list = Enum.to_list(1..300)
      enc = Cbor.encode(list)
      assert <<0x99, 300::16, _::binary>> = enc
      assert Cbor.decode(enc) == {:ok, list}
    end

    test "map with >23 entries uses an 8-bit head" do
      map = for i <- 1..30, into: %{}, do: {"k#{i}", i}
      enc = Cbor.encode(map)
      assert <<0xB8, 30, _::binary>> = enc
      assert Cbor.decode(enc) == {:ok, map}
    end

    test "text longer than 255 bytes uses a 16-bit head" do
      s = String.duplicate("x", 300)
      enc = Cbor.encode(s)
      assert <<0x79, 300::16, _::binary>> = enc
      assert Cbor.decode(enc) == {:ok, s}
    end

    test "deep nesting round-trips" do
      deep = Enum.reduce(1..50, "leaf", fn _, acc -> [acc] end)
      assert Cbor.decode(Cbor.encode(deep)) == {:ok, deep}
    end
  end

  describe "decode error handling" do
    test "empty input" do
      assert Cbor.decode(<<>>) == {:error, :invalid_cbor}
    end

    test "truncated integer head" do
      assert Cbor.decode(<<0x18>>) == {:error, :invalid_cbor}
      assert Cbor.decode(<<0x19, 0x01>>) == {:error, :invalid_cbor}
      assert Cbor.decode(<<0x1B, 0, 0, 0>>) == {:error, :invalid_cbor}
    end

    test "truncated text/bytes payload" do
      assert Cbor.decode(<<0x63, ?a, ?b>>) == {:error, :invalid_cbor}
      assert Cbor.decode(<<0x42, 1>>) == {:error, :invalid_cbor}
    end

    test "truncated array and map" do
      assert Cbor.decode(<<0x83, 1, 2>>) == {:error, :invalid_cbor}
      assert Cbor.decode(<<0xA1, 0x61, ?a>>) == {:error, :invalid_cbor}
      assert Cbor.decode(<<0xA1>>) == {:error, :invalid_cbor}
    end

    test "reserved additional info 28-31 and indefinite length are rejected" do
      assert Cbor.decode(<<0x1C>>) == {:error, :invalid_cbor}
      assert Cbor.decode(<<0x1F>>) == {:error, :invalid_cbor}
      # indefinite-length array 0x9f ... 0xff (not supported)
      assert Cbor.decode(<<0x9F, 1, 0xFF>>) == {:error, :invalid_cbor}
    end

    test "unsupported major types (tags, floats, other simple values) are rejected" do
      # tag 0 (0xc0) wrapping text
      assert Cbor.decode(<<0xC0, 0x61, ?a>>) == {:error, :invalid_cbor}
      # float16 1.0 = f9 3c 00
      assert Cbor.decode(<<0xF9, 0x3C, 0x00>>) == {:error, :invalid_cbor}
      # simple(23) undefined
      assert Cbor.decode(<<0xF7>>) == {:error, :invalid_cbor}
      # simple(0)
      assert Cbor.decode(<<0xE0>>) == {:error, :invalid_cbor}
    end

    test "trailing bytes after a complete item are ignored (documented lenient behaviour)" do
      assert Cbor.decode(<<0x01, 0xFF, 0xFF>>) == {:ok, 1}
    end

    test "non-binary input raises FunctionClauseError (guard)" do
      assert_raise FunctionClauseError, fn -> Cbor.decode(:not_binary) end
    end
  end

  describe "property-style round trips" do
    test "random nested terms round-trip (string keys, no floats)" do
      :rand.seed(:exsss, {1, 2, 3})

      for _ <- 1..200 do
        term = gen_term(3)
        assert Cbor.decode(Cbor.encode(term)) == {:ok, normalize(term)}
      end
    end
  end

  # ── generators ──────────────────────────────────────────────────────────

  defp gen_term(0), do: gen_scalar()

  defp gen_term(depth) do
    case :rand.uniform(4) do
      1 -> gen_scalar()
      2 -> for _ <- 1..:rand.uniform(4), do: gen_term(depth - 1)
      3 -> for i <- 1..:rand.uniform(4), into: %{}, do: {"k#{i}", gen_term(depth - 1)}
      4 -> gen_scalar()
    end
  end

  defp gen_scalar do
    case :rand.uniform(6) do
      1 -> :rand.uniform(1_000_000_000) - 500_000_000
      2 -> :crypto.strong_rand_bytes(:rand.uniform(40))
      3 -> Base.encode64(:crypto.strong_rand_bytes(:rand.uniform(20)))
      4 -> Enum.random([true, false, nil])
      5 -> :rand.uniform(2 ** 40)
      6 -> -:rand.uniform(2 ** 40)
    end
  end

  # Encoding is lossy only in that atoms become strings; we generate none.
  defp normalize(t), do: t
end
