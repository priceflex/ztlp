defmodule ZtlpGateway.SessionPendingPacketsCapTest do
  @moduledoc """
  Regression test for finding cjm-gxet (CWE-770): before this fix,
  ZtlpGateway.Session buffered every non-handshake packet received
  during the pre-auth phases (:awaiting_msg1 / :awaiting_msg3) into
  state.pending_packets with no count limit, letting an unauthenticated
  sender grow it without bound while the session's idle timer kept
  getting reset on every packet.

  This test drives a real Session GenServer (not a mock) through
  handle_packet/3 with a flood of non-handshake packets while it sits
  in :awaiting_msg1, and asserts pending_packets never exceeds the
  configured cap.
  """
  use ExUnit.Case, async: true

  alias ZtlpGateway.{Session, Crypto}

  defp start_session(session_id) do
    {static_pub, static_priv} = Crypto.generate_keypair()

    Session.start_link(%{
      session_id: session_id,
      client_addr: {{127, 0, 0, 1}, 40000},
      udp_socket: nil,
      static_pub: static_pub,
      static_priv: static_priv,
      service: "default"
    })
  end

  test "pending_packets stops growing past the cap during :awaiting_msg1" do
    session_id = :crypto.strong_rand_bytes(12)
    {:ok, pid} = start_session(session_id)

    # None of these are valid handshake packets (Packet.handshake?/1
    # requires a specific magic/type byte at the front), so every one
    # of them takes the "buffer it" branch of :awaiting_msg1.
    for i <- 1..200 do
      Session.handle_packet(pid, <<0xFF, i::16>>, {{10, 0, 0, 1}, 12345})
    end

    # Casts are async — give the GenServer's mailbox a moment to drain.
    :sys.get_state(pid)

    state = :sys.get_state(pid)
    assert state.phase == :awaiting_msg1
    assert length(state.pending_packets) <= 32,
      "pending_packets should never exceed the CWE-770 cap (32), got #{length(state.pending_packets)}"

    Process.exit(pid, :kill)
  end

  test "pending_packets stops growing past the cap during :awaiting_msg3" do
    session_id = :crypto.strong_rand_bytes(12)
    {:ok, pid} = start_session(session_id)

    # Force the phase to :awaiting_msg3 directly via :sys.replace_state —
    # driving a real Noise handshake to msg3 here would add a lot of
    # unrelated setup for a test whose only job is to check the cap
    # applies identically in both pre-auth phases.
    :sys.replace_state(pid, fn state -> %{state | phase: :awaiting_msg3} end)

    for i <- 1..200 do
      Session.handle_packet(pid, <<0xFF, i::16>>, {{10, 0, 0, 2}, 12345})
    end

    :sys.get_state(pid)

    state = :sys.get_state(pid)
    assert state.phase == :awaiting_msg3
    assert length(state.pending_packets) <= 32,
      "pending_packets should never exceed the CWE-770 cap (32), got #{length(state.pending_packets)}"

    Process.exit(pid, :kill)
  end
end
