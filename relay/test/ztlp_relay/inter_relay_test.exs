defmodule ZtlpRelay.InterRelayTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.InterRelay

  @test_node_id :crypto.strong_rand_bytes(16)
  @test_address {{10, 0, 0, 1}, 23096}

  defp our_info do
    %{
      node_id: @test_node_id,
      address: @test_address,
      role: :all,
      capabilities: 0
    }
  end

  describe "encode/decode RELAY_HELLO" do
    test "round-trips correctly" do
      encoded = InterRelay.encode_hello(our_info())
      assert {:ok, {:relay_hello, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == @test_node_id
      assert payload.address == @test_address
      assert payload.role == :all
      assert payload.capabilities == 0
    end

    test "encodes all roles correctly" do
      for role <- [:ingress, :transit, :service, :all] do
        info = %{our_info() | role: role}
        encoded = InterRelay.encode_hello(info)
        {:ok, {:relay_hello, _, _, payload}} = InterRelay.decode(encoded)
        assert payload.role == role
      end
    end

    test "preserves capabilities" do
      info = %{our_info() | capabilities: 0xFF00}
      encoded = InterRelay.encode_hello(info)
      {:ok, {:relay_hello, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.capabilities == 0xFF00
    end

    test "preserves various addresses" do
      info = %{our_info() | address: {{192, 168, 1, 100}, 9999}}
      encoded = InterRelay.encode_hello(info)
      {:ok, {:relay_hello, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.address == {{192, 168, 1, 100}, 9999}
    end
  end

  describe "encode/decode RELAY_HELLO_ACK" do
    test "round-trips correctly" do
      encoded = InterRelay.encode_hello_ack(our_info())
      assert {:ok, {:relay_hello_ack, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == @test_node_id
      assert payload.address == @test_address
      assert payload.role == :all
    end
  end

  describe "encode/decode RELAY_PING" do
    test "round-trips correctly" do
      encoded = InterRelay.encode_ping(@test_node_id)
      assert {:ok, {:relay_ping, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == @test_node_id
      assert payload == %{}
    end

    test "includes timestamp" do
      before = System.system_time(:millisecond)
      encoded = InterRelay.encode_ping(@test_node_id)
      after_ts = System.system_time(:millisecond)

      {:ok, {:relay_ping, _, ts, _}} = InterRelay.decode(encoded)
      assert ts >= before
      assert ts <= after_ts
    end
  end

  describe "encode/decode RELAY_PONG" do
    test "round-trips with metrics" do
      metrics = %{active_sessions: 150, max_sessions: 10_000, uptime_seconds: 86400}
      encoded = InterRelay.encode_pong(@test_node_id, metrics)
      assert {:ok, {:relay_pong, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == @test_node_id
      assert payload.active_sessions == 150
      assert payload.max_sessions == 10_000
      assert payload.uptime_seconds == 86400
    end

    test "handles zero metrics" do
      metrics = %{active_sessions: 0, max_sessions: 0, uptime_seconds: 0}
      encoded = InterRelay.encode_pong(@test_node_id, metrics)
      {:ok, {:relay_pong, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.active_sessions == 0
    end
  end

  describe "encode/decode RELAY_FORWARD" do
    test "wraps and unwraps inner packet" do
      inner = :crypto.strong_rand_bytes(200)
      encoded = InterRelay.encode_forward(@test_node_id, inner)
      assert {:ok, {:relay_forward, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == @test_node_id
      assert payload.inner_packet == inner
    end

    test "handles empty inner packet" do
      encoded = InterRelay.encode_forward(@test_node_id, <<>>)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.inner_packet == <<>>
    end

    test "handles large inner packet" do
      inner = :crypto.strong_rand_bytes(1400)  # near MTU size
      encoded = InterRelay.encode_forward(@test_node_id, inner)
      {:ok, {:relay_forward, _, _, payload}} = InterRelay.decode(encoded)
      assert payload.inner_packet == inner
    end

    test "length mismatch returns error" do
      inner = "hello"
      encoded = InterRelay.encode_forward(@test_node_id, inner)

      # Corrupt: truncate the encoded data to create length mismatch
      truncated = binary_part(encoded, 0, byte_size(encoded) - 2)
      assert {:error, :forward_length_mismatch} = InterRelay.decode(truncated)
    end
  end

  describe "encode/decode RELAY_SESSION_SYNC" do
    test "round-trips with session info" do
      session_id = :crypto.strong_rand_bytes(12)
      sync = %{
        session_id: session_id,
        peer_a: {{10, 0, 0, 1}, 5000},
        peer_b: {{10, 0, 0, 2}, 6000}
      }

      encoded = InterRelay.encode_session_sync(@test_node_id, sync)
      assert {:ok, {:relay_session_sync, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == @test_node_id
      assert payload.session_id == session_id
      assert payload.peer_a == {{10, 0, 0, 1}, 5000}
      assert payload.peer_b == {{10, 0, 0, 2}, 6000}
    end
  end

  describe "encode/decode RELAY_LEAVE" do
    test "round-trips correctly" do
      encoded = InterRelay.encode_leave(@test_node_id)
      assert {:ok, {:relay_leave, sender, _ts, payload}} = InterRelay.decode(encoded)

      assert sender == @test_node_id
      assert payload == %{}
    end
  end

  describe "decode error handling" do
    test "unknown message type" do
      node_id = @test_node_id
      data = <<0xAA::8, node_id::binary-size(16), 0::64>>
      assert {:error, :unknown_message_type} = InterRelay.decode(data)
    end

    test "malformed message — too short" do
      assert {:error, :malformed_message} = InterRelay.decode(<<0x01>>)
      assert {:error, :malformed_message} = InterRelay.decode(<<>>)
    end
  end

  describe "handle_message/2" do
    test "decodes and returns message" do
      encoded = InterRelay.encode_ping(@test_node_id)
      sender = {{127, 0, 0, 1}, 12345}

      assert {:ok, {:relay_ping, _, _, _}} = InterRelay.handle_message(encoded, sender)
    end
  end

  describe "forward_packet/2" do
    test "wraps a packet for forwarding" do
      inner = :crypto.strong_rand_bytes(100)
      wrapped = InterRelay.forward_packet(inner, @test_node_id)

      # Should be decodable as RELAY_FORWARD
      {:ok, {:relay_forward, _, _, %{inner_packet: unwrapped}}} = InterRelay.decode(wrapped)
      assert unwrapped == inner
    end
  end

  describe "unwrap_forward/1" do
    test "unwraps a forward message" do
      inner = "test-ztlp-packet"
      encoded = InterRelay.encode_forward(@test_node_id, inner)
      assert {:ok, ^inner} = InterRelay.unwrap_forward(encoded)
    end

    test "returns error for non-forward message" do
      encoded = InterRelay.encode_ping(@test_node_id)
      assert {:error, {:not_forward, :relay_ping}} = InterRelay.unwrap_forward(encoded)
    end
  end

  describe "inter_relay_message?/1" do
    test "identifies inter-relay messages" do
      assert InterRelay.inter_relay_message?(InterRelay.encode_hello(our_info()))
      assert InterRelay.inter_relay_message?(InterRelay.encode_hello_ack(our_info()))
      assert InterRelay.inter_relay_message?(InterRelay.encode_ping(@test_node_id))
      assert InterRelay.inter_relay_message?(InterRelay.encode_pong(@test_node_id, %{active_sessions: 0, max_sessions: 0, uptime_seconds: 0}))
      assert InterRelay.inter_relay_message?(InterRelay.encode_forward(@test_node_id, <<>>))
      assert InterRelay.inter_relay_message?(InterRelay.encode_leave(@test_node_id))
    end

    test "rejects non-inter-relay messages" do
      refute InterRelay.inter_relay_message?(<<0x5A, 0x37, 0::8>>)  # ZTLP magic
      refute InterRelay.inter_relay_message?(<<0xAA::8, 0::128>>)
      refute InterRelay.inter_relay_message?(<<>>)
    end
  end
end
