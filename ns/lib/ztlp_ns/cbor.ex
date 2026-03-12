defmodule ZtlpNs.Cbor do
  @moduledoc """
  Minimal RFC 8949 CBOR encoder/decoder with deterministic sorted-key encoding.

  Implements only the subset needed for ZTLP-NS record data serialization.
  Keys are sorted by encoded byte representation per RFC 8949 §4.2.1
  (Core Deterministic Encoding Requirements).
  """

  import Bitwise

  # Major types
  @mt_uint    0
  @mt_negint  1
  @mt_bytes   2
  @mt_text    3
  @mt_array   4
  @mt_map     5
  @mt_simple  7

  # ── Encoding ─────────────────────────────────────────────────────

  @doc "Encode an Elixir term to deterministic CBOR bytes."
  @spec encode(term()) :: binary()
  def encode(term), do: do_encode(term)

  defp do_encode(n) when is_integer(n) and n >= 0, do: encode_head(@mt_uint, n)
  defp do_encode(n) when is_integer(n) and n < 0, do: encode_head(@mt_negint, -1 - n)

  defp do_encode(b) when is_binary(b) do
    if String.valid?(b) do
      encode_head(@mt_text, byte_size(b)) <> b
    else
      encode_head(@mt_bytes, byte_size(b)) <> b
    end
  end

  defp do_encode(list) when is_list(list) do
    encoded_items = Enum.map(list, &do_encode/1) |> IO.iodata_to_binary()
    encode_head(@mt_array, length(list)) <> encoded_items
  end

  defp do_encode(%{} = map) do
    # RFC 8949 §4.2.1: sort by encoded key bytes (length-first)
    sorted_pairs =
      map
      |> Enum.map(fn {k, v} ->
        key_bytes = do_encode(to_string(k))
        val_bytes = do_encode(v)
        {key_bytes, val_bytes}
      end)
      |> Enum.sort_by(fn {k, _} -> {byte_size(k), k} end)

    encoded = Enum.map(sorted_pairs, fn {k, v} -> <<k::binary, v::binary>> end) |> IO.iodata_to_binary()
    encode_head(@mt_map, map_size(map)) <> encoded
  end

  defp do_encode(true), do: <<(7 <<< 5) ||| 21>>
  defp do_encode(false), do: <<(7 <<< 5) ||| 20>>
  defp do_encode(nil), do: <<(7 <<< 5) ||| 22>>

  defp do_encode(atom) when is_atom(atom), do: do_encode(Atom.to_string(atom))

  defp encode_head(major, n) when n < 24, do: <<(major <<< 5) ||| n::8>>
  defp encode_head(major, n) when n < 0x100, do: <<(major <<< 5) ||| 24, n::8>>
  defp encode_head(major, n) when n < 0x10000, do: <<(major <<< 5) ||| 25, n::16>>
  defp encode_head(major, n) when n < 0x100000000, do: <<(major <<< 5) ||| 26, n::32>>
  defp encode_head(major, n), do: <<(major <<< 5) ||| 27, n::64>>

  # ── Decoding ─────────────────────────────────────────────────────

  @doc "Decode CBOR bytes to an Elixir term."
  @spec decode(binary()) :: {:ok, term()} | {:error, atom()}
  def decode(data) when is_binary(data) do
    case do_decode(data) do
      {term, <<>>} -> {:ok, term}
      {term, _rest} -> {:ok, term}
      :error -> {:error, :invalid_cbor}
    end
  rescue
    _ -> {:error, :invalid_cbor}
  end

  defp do_decode(<<initial::8, rest::binary>>) do
    major = initial >>> 5
    additional = initial &&& 0x1F
    decode_value(major, additional, rest)
  end

  defp do_decode(<<>>), do: :error

  defp decode_value(major, additional, rest) when additional < 24 do
    decode_payload(major, additional, rest)
  end

  defp decode_value(major, 24, <<val::8, rest::binary>>), do: decode_payload(major, val, rest)
  defp decode_value(major, 25, <<val::16, rest::binary>>), do: decode_payload(major, val, rest)
  defp decode_value(major, 26, <<val::32, rest::binary>>), do: decode_payload(major, val, rest)
  defp decode_value(major, 27, <<val::64, rest::binary>>), do: decode_payload(major, val, rest)
  defp decode_value(_, _, _), do: :error

  defp decode_payload(@mt_uint, n, rest), do: {n, rest}
  defp decode_payload(@mt_negint, n, rest), do: {-1 - n, rest}

  defp decode_payload(@mt_bytes, len, rest) do
    <<bytes::binary-size(len), remaining::binary>> = rest
    {bytes, remaining}
  end

  defp decode_payload(@mt_text, len, rest) do
    <<text::binary-size(len), remaining::binary>> = rest
    {text, remaining}
  end

  defp decode_payload(@mt_array, count, rest) do
    decode_array(count, rest, [])
  end

  defp decode_payload(@mt_map, count, rest) do
    decode_map(count, rest, %{})
  end

  defp decode_payload(@mt_simple, 20, rest), do: {false, rest}
  defp decode_payload(@mt_simple, 21, rest), do: {true, rest}
  defp decode_payload(@mt_simple, 22, rest), do: {nil, rest}
  defp decode_payload(_, _, _), do: :error

  defp decode_array(0, rest, acc), do: {Enum.reverse(acc), rest}

  defp decode_array(n, rest, acc) do
    case do_decode(rest) do
      {item, remaining} -> decode_array(n - 1, remaining, [item | acc])
      :error -> :error
    end
  end

  defp decode_map(0, rest, acc), do: {acc, rest}

  defp decode_map(n, rest, acc) do
    case do_decode(rest) do
      {key, remaining1} ->
        case do_decode(remaining1) do
          {val, remaining2} -> decode_map(n - 1, remaining2, Map.put(acc, key, val))
          :error -> :error
        end
      :error -> :error
    end
  end
end
