defmodule ZtlpGateway.SackTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.Sack

  # ---------------------------------------------------------------------------
  # chunk_contiguous/1
  # ---------------------------------------------------------------------------

  describe "chunk_contiguous/1" do
    test "empty list returns empty" do
      assert Sack.chunk_contiguous([]) == []
    end

    test "single element returns single range" do
      assert Sack.chunk_contiguous([5]) == [{5, 5}]
    end

    test "fully contiguous returns one range" do
      assert Sack.chunk_contiguous([3, 4, 5, 6, 7]) == [{3, 7}]
    end

    test "two separate ranges" do
      assert Sack.chunk_contiguous([1, 2, 3, 7, 8, 9]) == [{1, 3}, {7, 9}]
    end

    test "multiple gaps" do
      assert Sack.chunk_contiguous([6, 7, 8, 11, 12, 13, 14, 15]) == [{6, 8}, {11, 15}]
    end

    test "all singletons" do
      assert Sack.chunk_contiguous([2, 5, 9]) == [{2, 2}, {5, 5}, {9, 9}]
    end
  end

  # ---------------------------------------------------------------------------
  # build_sack_blocks/2
  # ---------------------------------------------------------------------------

  describe "build_sack_blocks/2" do
    test "no gaps — empty SACK blocks" do
      # All packets at or below base → no out-of-order → no SACK blocks
      recv_window = MapSet.new([10, 11, 12])
      recv_window_base = 13
      assert Sack.build_sack_blocks(recv_window, recv_window_base) == []
    end

    test "no packets in window — empty SACK blocks" do
      recv_window = MapSet.new()
      recv_window_base = 5
      assert Sack.build_sack_blocks(recv_window, recv_window_base) == []
    end

    test "one gap → one SACK block" do
      # Received 1-4 (delivered), base=5, and 6-8 received out of order
      recv_window = MapSet.new([6, 7, 8])
      recv_window_base = 5
      assert Sack.build_sack_blocks(recv_window, recv_window_base) == [{6, 8}]
    end

    test "multiple gaps → multiple SACK blocks" do
      # base=5, gaps at 5 and 9-10, received [6,7,8] and [11,12,13,14,15]
      recv_window = MapSet.new([6, 7, 8, 11, 12, 13, 14, 15])
      recv_window_base = 5
      assert Sack.build_sack_blocks(recv_window, recv_window_base) == [{6, 8}, {11, 15}]
    end

    test "capped at 3 blocks" do
      # 5 separate ranges but only 3 should be returned
      recv_window = MapSet.new([6, 10, 14, 18, 22])
      recv_window_base = 5
      blocks = Sack.build_sack_blocks(recv_window, recv_window_base)
      assert length(blocks) == 3
      assert blocks == [{6, 6}, {10, 10}, {14, 14}]
    end

    test "ignores sequences at or below base" do
      recv_window = MapSet.new([3, 4, 5, 8, 9])
      recv_window_base = 5
      # Only 8, 9 are above base
      assert Sack.build_sack_blocks(recv_window, recv_window_base) == [{8, 9}]
    end
  end

  # ---------------------------------------------------------------------------
  # encode_sack_ack/2 — SACK ACK frame serialization
  # ---------------------------------------------------------------------------

  describe "encode_sack_ack/2" do
    test "no SACK blocks — just cumulative ACK + count 0" do
      result = Sack.encode_sack_ack(42, [])
      assert result == <<42::big-64, 0::8>>
    end

    test "one SACK block" do
      result = Sack.encode_sack_ack(4, [{6, 8}])
      assert result == <<4::big-64, 1::8, 6::big-64, 8::big-64>>
    end

    test "two SACK blocks" do
      result = Sack.encode_sack_ack(4, [{6, 8}, {11, 15}])
      expected = <<4::big-64, 2::8, 6::big-64, 8::big-64, 11::big-64, 15::big-64>>
      assert result == expected
    end

    test "three SACK blocks — correct wire format" do
      blocks = [{6, 8}, {11, 15}, {20, 25}]
      result = Sack.encode_sack_ack(4, blocks)

      expected =
        <<4::big-64, 3::8,
          6::big-64, 8::big-64,
          11::big-64, 15::big-64,
          20::big-64, 25::big-64>>

      assert result == expected
    end
  end

  # ---------------------------------------------------------------------------
  # parse_sack_blocks/2
  # ---------------------------------------------------------------------------

  describe "parse_sack_blocks/2" do
    test "count 0 returns empty" do
      assert Sack.parse_sack_blocks(0, <<>>) == []
      assert Sack.parse_sack_blocks(0, <<1, 2, 3>>) == []
    end

    test "parses one block" do
      data = <<6::big-64, 8::big-64>>
      assert Sack.parse_sack_blocks(1, data) == [{6, 8}]
    end

    test "parses two blocks" do
      data = <<6::big-64, 8::big-64, 11::big-64, 15::big-64>>
      assert Sack.parse_sack_blocks(2, data) == [{6, 8}, {11, 15}]
    end

    test "parses three blocks" do
      data = <<6::big-64, 8::big-64, 11::big-64, 15::big-64, 20::big-64, 25::big-64>>
      assert Sack.parse_sack_blocks(3, data) == [{6, 8}, {11, 15}, {20, 25}]
    end

    test "truncated data returns what it can parse" do
      # Claim 2 blocks but only provide data for 1
      data = <<6::big-64, 8::big-64>>
      assert Sack.parse_sack_blocks(2, data) == [{6, 8}]
    end

    test "empty data with positive count returns empty" do
      assert Sack.parse_sack_blocks(3, <<>>) == []
    end
  end

  # ---------------------------------------------------------------------------
  # Encode + parse roundtrip
  # ---------------------------------------------------------------------------

  describe "encode/parse roundtrip" do
    test "SACK ACK frame roundtrip" do
      blocks = [{6, 8}, {11, 15}]
      encoded = Sack.encode_sack_ack(4, blocks)

      # Frame format: <<cumulative_ack::64, sack_count::8, sack_data::binary>>
      <<cumulative_ack::big-64, sack_count::8, sack_data::binary>> = encoded
      assert cumulative_ack == 4
      assert sack_count == 2
      assert Sack.parse_sack_blocks(sack_count, sack_data) == blocks
    end

    test "legacy ACK roundtrip (zero blocks)" do
      encoded = Sack.encode_sack_ack(100, [])
      <<cumulative_ack::big-64, sack_count::8, sack_data::binary>> = encoded
      assert cumulative_ack == 100
      assert sack_count == 0
      assert sack_data == <<>>
      assert Sack.parse_sack_blocks(sack_count, sack_data) == []
    end
  end

  # ---------------------------------------------------------------------------
  # add_to_sacked_set/2 and prune_sacked_set/2
  # ---------------------------------------------------------------------------

  describe "add_to_sacked_set/2" do
    test "adds ranges from SACK blocks" do
      sacked = []
      blocks = [{6, 8}, {11, 13}]
      result = Sack.add_to_sacked_set(sacked, blocks)
      assert result == [{6, 8}, {11, 13}]
    end

    test "merges with existing ranges" do
      sacked = [{1, 3}]
      blocks = [{5, 6}]
      result = Sack.add_to_sacked_set(sacked, blocks)
      assert result == [{1, 3}, {5, 6}]
    end

    test "empty blocks don't modify set" do
      sacked = [{1, 3}]
      result = Sack.add_to_sacked_set(sacked, [])
      assert result == [{1, 3}]
    end

    test "overlapping ranges are merged" do
      sacked = [{1, 5}]
      blocks = [{4, 8}]
      result = Sack.add_to_sacked_set(sacked, blocks)
      assert result == [{1, 8}]
    end

    test "adjacent ranges are merged" do
      sacked = [{1, 3}]
      blocks = [{4, 6}]
      result = Sack.add_to_sacked_set(sacked, blocks)
      assert result == [{1, 6}]
    end

    test "large ranges are stored compactly (algorithmic DoS protection)" do
      # A malicious client could send a huge range — it should NOT expand to individual elements
      sacked = []
      blocks = [{0, 1_000_000_000}]
      result = Sack.add_to_sacked_set(sacked, blocks)
      # Should be a single range tuple, not a billion MapSet entries
      assert result == [{0, 1_000_000_000}]
      assert length(result) == 1
    end

    test "multiple blocks are sorted and merged" do
      sacked = []
      blocks = [{10, 12}, {1, 3}, {2, 4}, {15, 20}]
      result = Sack.add_to_sacked_set(sacked, blocks)
      assert result == [{1, 4}, {10, 12}, {15, 20}]
    end
  end

  describe "prune_sacked_set/2" do
    test "removes ranges fully at or below cumulative ACK" do
      sacked = [{1, 3}, {5, 7}, {10, 12}]
      result = Sack.prune_sacked_set(sacked, 5)
      assert result == [{6, 7}, {10, 12}]
    end

    test "drops fully acknowledged range, keeps above" do
      sacked = [{1, 3}, {8, 12}]
      result = Sack.prune_sacked_set(sacked, 5)
      assert result == [{8, 12}]
    end

    test "empty set stays empty" do
      result = Sack.prune_sacked_set([], 10)
      assert result == []
    end

    test "straddle — range trimmed to above cumulative ACK" do
      sacked = [{5, 10}]
      result = Sack.prune_sacked_set(sacked, 7)
      assert result == [{8, 10}]
    end

    test "cumulative ACK beyond all ranges" do
      sacked = [{1, 3}, {5, 7}]
      result = Sack.prune_sacked_set(sacked, 100)
      assert result == []
    end
  end

  describe "seq_in_sacked_range/2" do
    test "nil or non-integer seq returns false" do
      assert Sack.seq_in_sacked_range([{1, 5}], nil) == false
      assert Sack.seq_in_sacked_range([{1, 5}], "abc") == false
    end

    test "empty ranges returns false" do
      assert Sack.seq_in_sacked_range([], 5) == false
    end

    test "seq within range" do
      assert Sack.seq_in_sacked_range([{1, 5}], 3) == true
      assert Sack.seq_in_sacked_range([{1, 5}], 1) == true
      assert Sack.seq_in_sacked_range([{1, 5}], 5) == true
    end

    test "seq outside range" do
      assert Sack.seq_in_sacked_range([{1, 5}], 0) == false
      assert Sack.seq_in_sacked_range([{1, 5}], 6) == false
    end

    test "multiple ranges — hit second" do
      assert Sack.seq_in_sacked_range([{1, 3}, {10, 15}], 12) == true
    end

    test "multiple ranges — in gap between ranges" do
      assert Sack.seq_in_sacked_range([{1, 3}, {10, 15}], 5) == false
    end

    test "large range is checked in O(1) not O(range_size)" do
      # This must not hang or OOM — the fix stores ranges, not individual elements
      sacked = [{0, 1_000_000_000}]
      assert Sack.seq_in_sacked_range(sacked, 500_000_000) == true
      assert Sack.seq_in_sacked_range(sacked, 1_000_000_001) == false
    end
  end

  # ---------------------------------------------------------------------------
  # Retransmit skips SACK'd sequences (integration-style test)
  # ---------------------------------------------------------------------------

  describe "retransmit skip logic" do
    test "SACK'd data_seqs would be skipped by retransmit" do
      # Simulate the retransmit check logic:
      # send_buffer has data_seqs 5, 6, 7, 8
      # sacked_set has {6, 8} from SACK blocks
      sacked_set = Sack.add_to_sacked_set([], [{6, 8}])

      send_buffer_data_seqs = [5, 6, 7, 8]

      # Filter: what would we actually retransmit?
      to_retransmit = Enum.reject(send_buffer_data_seqs, &Sack.seq_in_sacked_range(sacked_set, &1))

      # Only data_seq 5 needs retransmission (6, 7, 8 are SACK'd)
      assert to_retransmit == [5]
    end

    test "no SACK'd sequences means all get retransmitted" do
      sacked_set = []
      send_buffer_data_seqs = [5, 6, 7, 8]
      to_retransmit = Enum.reject(send_buffer_data_seqs, &Sack.seq_in_sacked_range(sacked_set, &1))
      assert to_retransmit == [5, 6, 7, 8]
    end

    test "large SACK range correctly covers all data_seqs in O(1)" do
      # Regression test: with the old MapSet approach this would OOM
      sacked_set = Sack.add_to_sacked_set([], [{0, 1_000_000_000}])
      send_buffer_data_seqs = [5, 6, 7, 8, 500_000_000, 999_999_999]
      to_retransmit = Enum.reject(send_buffer_data_seqs, &Sack.seq_in_sacked_range(sacked_set, &1))
      assert to_retransmit == []
    end
  end
end
