# frozen_string_literal: true

module Ztlp
  # Minimal deterministic CBOR encoder (RFC 8949 §4.2.1 core deterministic
  # encoding), the Ruby twin of `ns/lib/ztlp_ns/cbor.ex`. Same subset the NS
  # record data needs: unsigned ints, byte strings, text strings, arrays,
  # maps and booleans.
  #
  # Maps with text keys are sorted by the ENCODED key bytes — (byte_size,
  # bytes), header byte included — exactly as cbor.ex:43-56 does, so bytes
  # signed here verify on the NS. Every returned value is ASCII-8BIT.
  class Cbor
    MAJOR_UINT = 0x00
    MAJOR_BYTES = 0x40
    MAJOR_TEXT = 0x60
    MAJOR_ARRAY = 0x80
    MAJOR_MAP = 0xA0

    # True iff the byte sequence is valid UTF-8 (Elixir `String.valid?`).
    def self.valid_utf8?(raw)
      raw.dup.force_encoding(Encoding::UTF_8).valid_encoding?
    rescue StandardError
      false
    end

    def self.encode(value)
      do_encode(value).b
    end

    def self.head(major, n)
      if n <= 23
        [ major | n ].pack("C*")
      elsif n <= 0xFF
        [ major | 24, n ].pack("C*")
      elsif n <= 0xFFFF
        [ major | 25, n ].pack("Cn")
      else
        [ major | 26, n ].pack("CN")
      end
    end

    def self.do_encode(value)
      case value
      when true
        "\xF5".b
      when false
        "\xF4".b
      when Integer
        raise ArgumentError, "negative integers not supported" if value.negative?

        head(MAJOR_UINT, value)
      when String
        raw = value.b
        if valid_utf8?(raw)
          head(MAJOR_TEXT, raw.bytesize) + raw
        else
          head(MAJOR_BYTES, raw.bytesize) + raw
        end
      when Array
        items = value.map { |v| do_encode(v) }
        head(MAJOR_ARRAY, value.size) + items.join
      when Hash
        pairs = value.map do |k, v|
          [ do_encode(key_to_text(k)), do_encode(v) ]
        end
        sorted = pairs.sort_by { |kb, _| [ kb.bytesize, kb ] }
        head(MAJOR_MAP, value.size) + sorted.map { |kb, vb| kb + vb }.join
      else
        raise ArgumentError, "cannot CBOR-encode #{value.class}"
      end
    end

    class << self
      private

      # Elixir maps may carry atom keys; the NS encodes them as text.
      def key_to_text(key)
        key.to_s
      end
    end
  end
end
