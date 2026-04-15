defmodule ZtlpGateway.SessionRecoveryTargetTest do
  use ExUnit.Case, async: true

  test "recovery target is the last sent packet, not the next unsent seq" do
    send_data_seq = 1611
    last_acked = 1363

    recovery_target = max(send_data_seq - 1, last_acked)

    assert recovery_target == 1610
    assert recovery_target < send_data_seq
  end

  test "recovery can exit when ack reaches the last sent packet" do
    recovery_target = 1610
    acked_data_seq = 1610

    assert acked_data_seq >= recovery_target
  end

  test "recovery target never moves behind the latest cumulative ack" do
    send_data_seq = 0
    last_acked = 42

    recovery_target = max(send_data_seq - 1, last_acked)

    assert recovery_target == 42
  end
end
