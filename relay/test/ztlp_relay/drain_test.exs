defmodule ZtlpRelay.DrainTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.Drain

  setup do
    # Ensure clean state
    :persistent_term.put({Drain, :draining}, false)
    :ok
  end

  describe "draining?/0" do
    test "returns false by default" do
      refute Drain.draining?()
    end
  end

  describe "start_drain/1" do
    test "transitions to draining or drained state" do
      assert :ok = Drain.start_drain(timeout_ms: 60_000)

      {state, _info} = Drain.status()
      assert state in [:draining, :drained]

      # Clean up
      Drain.cancel_drain()
    end

    test "returns error if already draining" do
      assert :ok = Drain.start_drain(timeout_ms: 60_000)
      assert {:error, :already_draining} = Drain.start_drain()

      Drain.cancel_drain()
    end
  end

  describe "cancel_drain/0" do
    test "returns to normal state" do
      assert :ok = Drain.start_drain(timeout_ms: 60_000)
      assert :ok = Drain.cancel_drain()
      refute Drain.draining?()

      {state, _info} = Drain.status()
      assert state == :normal
    end

    test "returns error if not draining" do
      assert {:error, :not_draining} = Drain.cancel_drain()
    end
  end

  describe "status/0" do
    test "returns normal state by default" do
      {state, info} = Drain.status()
      assert state == :normal
      assert info.active_sessions == 0
      assert info.drain_started_at == nil
      assert info.timeout_at == nil
    end
  end

  describe "session_closed/0" do
    test "is a no-op in normal mode" do
      assert :ok = Drain.session_closed()
    end
  end
end
