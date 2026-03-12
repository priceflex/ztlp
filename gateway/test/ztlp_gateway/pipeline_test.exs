defmodule ZtlpGateway.PipelineTest do
  use ExUnit.Case

  alias ZtlpGateway.{Pipeline, Packet, SessionRegistry}

  describe "layer1_magic/1" do
    test "accepts valid magic" do
      assert :ok = Pipeline.layer1_magic(<<0x5A, 0x37, 0, 0>>)
    end

    test "rejects bad magic" do
      assert {:reject, :bad_magic} = Pipeline.layer1_magic(<<0xFF, 0x00>>)
    end

    test "rejects empty" do
      assert {:reject, :bad_magic} = Pipeline.layer1_magic(<<>>)
    end
  end

  describe "admit/1" do
    test "admits HELLO packet as new session" do
      hello = Packet.build_hello("ephemeral_key")
      assert {:ok, :new_session} = Pipeline.admit(hello)
    end

    test "rejects non-ZTLP traffic" do
      assert {:reject, :bad_magic} = Pipeline.admit(<<"HTTP/1.1 200 OK">>)
    end

    test "rejects unknown SessionID" do
      sid = :crypto.strong_rand_bytes(12)
      auth = :crypto.strong_rand_bytes(16)
      pkt = Packet.build_data(sid, 1, payload: "data", header_auth_tag: auth)
      raw = Packet.serialize(pkt)
      assert {:reject, :unknown_session} = Pipeline.admit(raw)
    end

    test "admits packet for registered session" do
      sid = :crypto.strong_rand_bytes(12)

      # Spawn a dummy process to register
      {:ok, pid} = Agent.start_link(fn -> nil end)
      :ok = SessionRegistry.register(sid, pid)

      auth = :crypto.strong_rand_bytes(16)
      pkt = Packet.build_data(sid, 1, payload: "data", header_auth_tag: auth)
      raw = Packet.serialize(pkt)
      assert {:ok, :known_session, ^pid} = Pipeline.admit(raw)

      # Clean up
      SessionRegistry.unregister(sid)
      Agent.stop(pid)
    end

    test "rejects truncated packet" do
      assert {:reject, :bad_magic} = Pipeline.admit(<<0x5A>>)
    end
  end
end
