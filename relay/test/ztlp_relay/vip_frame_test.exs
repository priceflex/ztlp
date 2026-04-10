defmodule ZtlpRelay.VipFrameTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.VipFrame

  describe "parse/1" do
    test "parses a SYN frame" do
{:ok, frame} = VipFrame.parse(<<1::16, 0x01::8, "hello">>)

      assert frame.connection_id == 1
      assert frame.frame_type == :syn
      assert frame.flags == 0x01
      assert frame.payload == "hello"
    end

    test "parses a DATA frame" do
      {:ok, frame} = VipFrame.parse(<<0xFF::16, 0x02::8, "data_payload">>)

      assert frame.connection_id == 0xFF
      assert frame.frame_type == :data
      assert frame.payload == "data_payload"
    end

    test "parses a FIN frame" do
      {:ok, frame} = VipFrame.parse(<<5::16, 0x04::8, "">>)

      assert frame.connection_id == 5
      assert frame.frame_type == :fin
      assert frame.payload == <<>>
    end

    test "parses a RST frame" do
      {:ok, frame} = VipFrame.parse(<<42::16, 0x08::8, "">>)

      assert frame.connection_id == 42
      assert frame.frame_type == :rst
    end

    test "returns error for too-short frame" do
      assert VipFrame.parse(<<0::16>>) == {:error, :frame_too_short}
      assert VipFrame.parse(<<>> ) == {:error, :frame_too_short}
    end

    test "classifies combined flags (DATA + FIN)" do
      {:ok, frame} = VipFrame.parse(<<1::16, 0x06::8, "fin_data">>)

      assert frame.flags == 0x06
      # FIN takes priority over DATA
      assert frame.frame_type == :fin
    end

    test "classifies combined flags (DATA + SYN)" do
      {:ok, frame} = VipFrame.parse(<<1::16, 0x03::8, "">>)

      assert frame.frame_type == :syn
    end
  end

  describe "encode/3" do
    test "encodes a SYN frame" do
      result = VipFrame.encode(1, :syn, "hello")
      assert result == <<1::16, 0x01::8, "hello">>
    end

    test "encodes a DATA frame" do
      result = VipFrame.encode(2, :data, "payload")
      assert result == <<2::16, 0x02::8, "payload">>
    end

    test "encodes a FIN frame" do
      result = VipFrame.encode(3, :fin, <<>>)
      assert result == <<3::16, 0x04::8>>
    end

    test "encodes with raw flags" do
      result = VipFrame.encode(1, 0x03, "data")
      assert result == <<1::16, 0x03::8, "data">>
    end
  end

  describe "classify_flags/1" do
    test "returns correct types for each flag" do
      assert VipFrame.classify_flags(0x01) == :syn
      assert VipFrame.classify_flags(0x02) == :data
      assert VipFrame.classify_flags(0x04) == :fin
      assert VipFrame.classify_flags(0x08) == :rst
    end

    test "RST takes priority" do
      assert VipFrame.classify_flags(0x0F) == :rst
    end
  end

  describe "min_frame_size/0" do
    test "returns 3" do
      assert VipFrame.min_frame_size() == 3
    end
  end
end
