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
        # NOTE: Ruby `pack("CN")` packs only the 1-byte header — the
        # 4-byte length would be dropped (no implicit C+N alignment).
        [ major | 26 ].pack("C*") + [ n ].pack("N")
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

    # Minimal deterministic CBOR decoder for the record-data subset the NS
    # stores (RFC 8949): unsigned ints, byte strings, text strings, arrays,
    # maps and booleans. Text maps decode to String keys.
    def self.decode(raw)
      raw = raw.b
      value, _pos = do_decode(raw, 0)
      value
    end

    # Extra header bytes BEYOND the initial 1-byte header.
    # n<=23: 0 extra (info is in the header byte itself)
    # n<=0xFF: 1 extra (info=24)
    # n<=0xFFFF: 2 extra (info=25)
    # larger: 4 extra (info=26)
    def self.header_size(n)
      n <= 23 ? 0 : (n <= 0xFF ? 1 : (n <= 0xFFFF ? 2 : 4))
    end

    # Major types as 3-bit values (the field actually stored in the header
    # byte's top 3 bits). MAJOR_UINT=0, MAJOR_BYTES=0x40(2), MAJOR_TEXT=0x60(3),
    # MAJOR_ARRAY=0x80(4), MAJOR_MAP=0xA0(5). The case below matches on `major`
    # (byte >> 5), NOT on the full head-byte constant.
    MAJOR_TYPE_UINT   = 0
    MAJOR_TYPE_BYTES  = 2
    MAJOR_TYPE_TEXT   = 3
    MAJOR_TYPE_ARRAY  = 4
    MAJOR_TYPE_MAP    = 5

    def self.do_decode(raw, pos)
      byte = raw.getbyte(pos)
      raise ArgumentError, "truncated CBOR at byte #{pos}" if byte.nil?

      major = byte >> 5
      info = byte & 0x1f
      case major
      when MAJOR_TYPE_UINT
        [ read_info(raw, pos + 1, info), pos + 1 + header_size(read_info(raw, pos + 1, info)) ]
      when MAJOR_TYPE_BYTES
        n = read_info(raw, pos + 1, info)
        start = pos + 1 + header_size(n)
        [ raw.byteslice(start, n), start + n ]
      when MAJOR_TYPE_TEXT
        n = read_info(raw, pos + 1, info)
        start = pos + 1 + header_size(n)
        [ raw.byteslice(start, n).force_encoding(Encoding::UTF_8), start + n ]
      when MAJOR_TYPE_ARRAY
        n = read_info(raw, pos + 1, info)
        i = pos + 1 + header_size(n)
        items = []
        n.times do
          value, i = do_decode(raw, i)
          items << value
        end
        [ items, i ]
      when MAJOR_TYPE_MAP
        n = read_info(raw, pos + 1, info)
        i = pos + 1 + header_size(n)
        map = {}
        n.times do
          key, i = do_decode(raw, i)
          value, i = do_decode(raw, i)
          map[key] = value
        end
        [ map, i ]
      else
        if byte == 0xF5 then [ true, pos + 1 ]
        elsif byte == 0xF4 then [ false, pos + 1 ]
        else
          raise ArgumentError, "unsupported CBOR item at byte #{pos}"
        end
      end
    end

    def self.read_info(raw, pos, info)
      case info
      when 24 then raw.getbyte(pos) || raise(ArgumentError, "truncated CBOR at byte #{pos}")
      when 25
        raise ArgumentError, "truncated CBOR at byte #{pos}" if raw.bytesize < pos + 2

        raw.byteslice(pos, 2).unpack1("n")
      when 26
        raise ArgumentError, "truncated CBOR at byte #{pos}" if raw.bytesize < pos + 4

        raw.byteslice(pos, 4).unpack1("N")
      else info
      end
    end
    private_class_method :read_info

  end
end
