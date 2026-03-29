defmodule ZtlpGateway.RecvWindowTest do
  @moduledoc """
  Tests for the sliding receive window used for out-of-order packet acceptance.

  The receive window replaces the old strict `seq > recv_seq` check that
  silently dropped any out-of-order packets — catastrophic on cellular where
  packet reordering is common.
  """
  use ExUnit.Case, async: true

  alias ZtlpGateway.RecvWindow

  describe "in-order delivery" do
    test "delivers packets arriving in order (seq 0, 1, 2, 3)" do
      w = RecvWindow.new(0)

      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{0, "pkt0"}]
      assert w.recv_window_base == 1

      {:ok, w} = RecvWindow.accept(w, 1, "pkt1")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{1, "pkt1"}]
      assert w.recv_window_base == 2

      {:ok, w} = RecvWindow.accept(w, 2, "pkt2")
      {:ok, w} = RecvWindow.accept(w, 3, "pkt3")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{2, "pkt2"}, {3, "pkt3"}]
      assert w.recv_window_base == 4
    end

    test "in-order delivery starting at non-zero seq (unanchored window)" do
      # Simulates the real scenario: handshake uses seq 0,
      # first data packet arrives at seq 1
      w = RecvWindow.new()

      {:ok, w} = RecvWindow.accept(w, 1, "pkt1")
      # Window anchored at 1
      assert w.recv_window_base == 1

      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{1, "pkt1"}]
      assert w.recv_window_base == 2

      {:ok, w} = RecvWindow.accept(w, 2, "pkt2")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{2, "pkt2"}]
      assert w.recv_window_base == 3
    end
  end

  describe "out-of-order acceptance and reordering" do
    test "seq 0, 2, 1 → delivered as 0, 1, 2" do
      w = RecvWindow.new(0)

      # Packet 0 arrives — deliver immediately
      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{0, "pkt0"}]
      assert w.recv_window_base == 1

      # Packet 2 arrives (skipping 1) — buffered, can't deliver
      {:ok, w} = RecvWindow.accept(w, 2, "pkt2")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == []
      assert w.recv_window_base == 1
      assert RecvWindow.buffered_count(w) == 1

      # Packet 1 arrives — now 1 and 2 deliver in order
      {:ok, w} = RecvWindow.accept(w, 1, "pkt1")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{1, "pkt1"}, {2, "pkt2"}]
      assert w.recv_window_base == 3
      assert RecvWindow.buffered_count(w) == 0
    end

    test "heavily reordered burst (seq 5, 3, 4, 0, 1, 2) all delivered in order" do
      w = RecvWindow.new(0)

      {:ok, w} = RecvWindow.accept(w, 5, "pkt5")
      {:ok, w} = RecvWindow.accept(w, 3, "pkt3")
      {:ok, w} = RecvWindow.accept(w, 4, "pkt4")

      # None can deliver yet (0, 1, 2 missing)
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == []
      assert RecvWindow.buffered_count(w) == 3

      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      {:ok, w} = RecvWindow.accept(w, 1, "pkt1")
      {:ok, w} = RecvWindow.accept(w, 2, "pkt2")

      # Now 0-5 all deliver
      {delivered, w} = RecvWindow.deliver(w)
      assert length(delivered) == 6
      assert Enum.map(delivered, &elem(&1, 0)) == [0, 1, 2, 3, 4, 5]
      assert w.recv_window_base == 6
    end

    test "out-of-order with unanchored window" do
      # First packet arrives at seq 10, anchoring the window there
      w = RecvWindow.new()

      {:ok, w} = RecvWindow.accept(w, 10, "pkt10")
      assert w.recv_window_base == 10

      # seq 12 arrives (gap at 11)
      {:ok, w} = RecvWindow.accept(w, 12, "pkt12")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{10, "pkt10"}]
      assert w.recv_window_base == 11

      # seq 11 fills the gap
      {:ok, w} = RecvWindow.accept(w, 11, "pkt11")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{11, "pkt11"}, {12, "pkt12"}]
      assert w.recv_window_base == 13
    end
  end

  describe "duplicate rejection" do
    test "same seq received twice is rejected" do
      w = RecvWindow.new(0)

      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      assert {:duplicate, :already_received} = RecvWindow.accept(w, 0, "pkt0_dup")

      # Buffer still has the original
      {delivered, _w} = RecvWindow.deliver(w)
      assert delivered == [{0, "pkt0"}]
    end

    test "buffered out-of-order packet cannot be re-accepted" do
      w = RecvWindow.new(0)

      {:ok, w} = RecvWindow.accept(w, 5, "pkt5")
      assert {:duplicate, :already_received} = RecvWindow.accept(w, 5, "pkt5_dup")
    end
  end

  describe "below-window rejection" do
    test "seq already delivered is rejected" do
      w = RecvWindow.new(0)

      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      {:ok, w} = RecvWindow.accept(w, 1, "pkt1")
      {_delivered, w} = RecvWindow.deliver(w)
      assert w.recv_window_base == 2

      # Seq 0 and 1 are below window now
      assert {:duplicate, :below_window} = RecvWindow.accept(w, 0, "replay0")
      assert {:duplicate, :below_window} = RecvWindow.accept(w, 1, "replay1")
    end
  end

  describe "beyond-window rejection" do
    test "seq too far ahead is rejected" do
      w = RecvWindow.new(0)
      window_size = RecvWindow.window_size()

      # seq at exactly window_size (base + window_size) is beyond
      assert {:rejected, :beyond_window} = RecvWindow.accept(w, window_size, "too_far")

      # seq well beyond window
      assert {:rejected, :beyond_window} = RecvWindow.accept(w, window_size + 100, "way_too_far")
    end

    test "seq at window_size - 1 (last valid slot) is accepted" do
      w = RecvWindow.new(0)
      window_size = RecvWindow.window_size()

      {:ok, _w} = RecvWindow.accept(w, window_size - 1, "last_slot")
    end
  end

  describe "window advancement" do
    test "window base advances correctly after delivery" do
      w = RecvWindow.new(0)

      # Accept and deliver 0-9
      w = Enum.reduce(0..9, w, fn seq, acc ->
        {:ok, acc} = RecvWindow.accept(acc, seq, "pkt#{seq}")
        acc
      end)

      {delivered, w} = RecvWindow.deliver(w)
      assert length(delivered) == 10
      assert w.recv_window_base == 10

      # Now the window starts at 10 — old seqs are rejected
      assert {:duplicate, :below_window} = RecvWindow.accept(w, 5, "old")

      # New seqs from 10 onwards work
      {:ok, w} = RecvWindow.accept(w, 10, "pkt10")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{10, "pkt10"}]
      assert w.recv_window_base == 11
    end

    test "window slides as packets are delivered, allowing higher seqs" do
      w = RecvWindow.new(0)
      window_size = RecvWindow.window_size()

      # Initially, window_size is beyond window
      assert {:rejected, :beyond_window} = RecvWindow.accept(w, window_size, "pkt_ws")

      # Deliver packets 0-9 to advance base to 10
      w = Enum.reduce(0..9, w, fn seq, acc ->
        {:ok, acc} = RecvWindow.accept(acc, seq, "pkt#{seq}")
        acc
      end)
      {_delivered, w} = RecvWindow.deliver(w)
      assert w.recv_window_base == 10

      # Now window_size + 9 is within window (base=10, max=10+256-1=265)
      {:ok, _w} = RecvWindow.accept(w, window_size + 9, "pkt_ws9")
    end
  end

  describe "large gap" do
    test "seq 0 then seq 100 → 0 delivered, 100 buffered, 1-99 gap" do
      w = RecvWindow.new(0)

      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      {:ok, w} = RecvWindow.accept(w, 100, "pkt100")

      {delivered, w} = RecvWindow.deliver(w)
      # Only seq 0 can be delivered (gap at 1-99)
      assert delivered == [{0, "pkt0"}]
      assert w.recv_window_base == 1
      assert RecvWindow.buffered_count(w) == 1

      # Seq 100 is still buffered
      assert Map.has_key?(w.recv_buffer, 100)
    end

    test "filling the gap delivers everything" do
      w = RecvWindow.new(0)

      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      {:ok, w} = RecvWindow.accept(w, 10, "pkt10")
      {_delivered, w} = RecvWindow.deliver(w)
      assert w.recv_window_base == 1

      # Fill gap 1-9
      w = Enum.reduce(1..9, w, fn seq, acc ->
        {:ok, acc} = RecvWindow.accept(acc, seq, "pkt#{seq}")
        acc
      end)

      {delivered, w} = RecvWindow.deliver(w)
      assert length(delivered) == 10  # seqs 1-10
      assert Enum.map(delivered, &elem(&1, 0)) == Enum.to_list(1..10)
      assert w.recv_window_base == 11
      assert RecvWindow.buffered_count(w) == 0
    end
  end

  describe "cumulative ACK" do
    test "ACK reflects cumulative delivery (recv_window_base - 1)" do
      w = RecvWindow.new(0)

      # No delivery yet — no ACK
      assert RecvWindow.cumulative_ack(w, 0) == nil

      # Deliver seq 0
      {:ok, w} = RecvWindow.accept(w, 0, "pkt0")
      {_delivered, w} = RecvWindow.deliver(w)
      assert RecvWindow.cumulative_ack(w, 0) == 0

      # Deliver seq 1, 2
      {:ok, w} = RecvWindow.accept(w, 1, "pkt1")
      {:ok, w} = RecvWindow.accept(w, 2, "pkt2")
      {_delivered, w} = RecvWindow.deliver(w)
      assert RecvWindow.cumulative_ack(w, 0) == 2

      # Accept seq 5 (gap at 3, 4) — ACK doesn't change
      {:ok, w} = RecvWindow.accept(w, 5, "pkt5")
      {_delivered, w} = RecvWindow.deliver(w)
      assert RecvWindow.cumulative_ack(w, 0) == 2  # still 2, gap at 3

      # Fill gap
      {:ok, w} = RecvWindow.accept(w, 3, "pkt3")
      {:ok, w} = RecvWindow.accept(w, 4, "pkt4")
      {_delivered, w} = RecvWindow.deliver(w)
      assert RecvWindow.cumulative_ack(w, 0) == 5
    end

    test "ACK with unanchored window" do
      w = RecvWindow.new()

      # No delivery yet — no ACK
      assert RecvWindow.cumulative_ack(w) == nil

      # First packet anchors at seq 5
      {:ok, w} = RecvWindow.accept(w, 5, "pkt5")
      {_delivered, w} = RecvWindow.deliver(w)
      assert RecvWindow.cumulative_ack(w, 5) == 5

      {:ok, w} = RecvWindow.accept(w, 6, "pkt6")
      {_delivered, w} = RecvWindow.deliver(w)
      assert RecvWindow.cumulative_ack(w, 5) == 6
    end
  end

  describe "edge cases" do
    test "anchored at specific base" do
      # Window anchored at base=1 (e.g., if handshake uses seq 0)
      w = RecvWindow.new(1)
      assert w.recv_window_base == 1

      # Seq 0 is below window
      assert {:duplicate, :below_window} = RecvWindow.accept(w, 0, "handshake")

      # Seq 1 is the first valid
      {:ok, w} = RecvWindow.accept(w, 1, "first_data")
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{1, "first_data"}]
      assert w.recv_window_base == 2
    end

    test "unanchored window anchors on first accept" do
      w = RecvWindow.new()
      assert w.recv_window_base == :unset

      {:ok, w} = RecvWindow.accept(w, 42, "first")
      assert w.recv_window_base == 42

      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == [{42, "first"}]
      assert w.recv_window_base == 43
    end

    test "empty window deliver returns empty list" do
      w = RecvWindow.new(0)
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == []
      assert w.recv_window_base == 0
    end

    test "unanchored empty window deliver returns empty list" do
      w = RecvWindow.new()
      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == []
      assert w.recv_window_base == :unset
    end

    test "window with only gaps delivers nothing" do
      w = RecvWindow.new(0)
      {:ok, w} = RecvWindow.accept(w, 2, "pkt2")
      {:ok, w} = RecvWindow.accept(w, 5, "pkt5")
      {:ok, w} = RecvWindow.accept(w, 8, "pkt8")

      {delivered, w} = RecvWindow.deliver(w)
      assert delivered == []
      assert w.recv_window_base == 0
      assert RecvWindow.buffered_count(w) == 3
    end

    test "window boundary: accept at base + window_size - 1, reject at base + window_size" do
      w = RecvWindow.new(100)
      ws = RecvWindow.window_size()

      {:ok, _w} = RecvWindow.accept(w, 100 + ws - 1, "edge")
      assert {:rejected, :beyond_window} = RecvWindow.accept(w, 100 + ws, "beyond")
    end
  end
end
