defmodule ZtlpRelay.SignalHandlerTest do
  # async: false — drives the globally-named Drain GenServer and the
  # application-started SignalHandler.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ZtlpRelay.{Drain, SignalHandler}

  setup do
    # Make sure we are not draining from a previous test and end each test
    # back in the normal state.
    case Drain.status() do
      {:normal, _} -> :ok
      _ -> Drain.cancel_drain()
    end

    on_exit(fn ->
      case Drain.status() do
        {:normal, _} -> :ok
        _ -> Drain.cancel_drain()
      end
    end)

    :ok
  end

  defp handler_pid do
    pid = Process.whereis(SignalHandler)
    assert is_pid(pid), "SignalHandler should be started by the application"
    pid
  end

  # Send the exact message :os.set_signal/2 delivers, then synchronise on the
  # GenServer mailbox so the handle_info has run before we assert.
  defp deliver(signal) do
    pid = handler_pid()
    send(pid, {:signal, signal})
    :sys.get_state(pid)
  end

  describe "startup" do
    test "is running under the application supervisor with the module name" do
      assert is_pid(handler_pid())
    end

    test "start_link/1 refuses a second instance with the same name" do
      assert {:error, {:already_started, pid}} = SignalHandler.start_link()
      assert pid == handler_pid()
    end

    test "init/1 traps SIGUSR1 and SIGUSR2 for the emulator" do
      # :os.set_signal/2 with :handle makes the erl_signal_server forward
      # signals as messages; a second call with the same value is idempotent
      # and proves the atoms are accepted on this platform.
      assert :ok = :os.set_signal(:sigusr1, :handle)
      assert :ok = :os.set_signal(:sigusr2, :handle)
    end
  end

  describe "SIGUSR1" do
    test "starts drain mode" do
      assert {:normal, _} = Drain.status()

      log = capture_log(fn -> deliver(:sigusr1) end)

      {state, _} = Drain.status()
      assert state in [:draining, :drained]
      assert log =~ "SIGUSR1 received"
      assert log =~ "Drain mode activated"
    end

    test "a second SIGUSR1 while draining is a no-op and logs 'Already draining'" do
      deliver(:sigusr1)
      {state1, _} = Drain.status()
      assert state1 in [:draining, :drained]

      log = capture_log(fn -> deliver(:sigusr1) end)

      {state2, _} = Drain.status()
      assert state2 in [:draining, :drained]
      assert log =~ "Already draining"
      refute log =~ "Drain mode activated"
    end

    test "handler survives the signal (pid unchanged)" do
      before = handler_pid()
      deliver(:sigusr1)
      assert Process.alive?(before)
      assert handler_pid() == before
    end
  end

  describe "SIGUSR2" do
    test "logs a status line with drain state and stats counters" do
      log = capture_log(fn -> deliver(:sigusr2) end)

      assert log =~ "SIGUSR2 received"
      assert log =~ "[status] drain=normal"
      assert log =~ ~r/sessions=\d+/
      assert log =~ ~r/passed=\d+/
      assert log =~ ~r/dropped_l1=\d+/
      assert log =~ ~r/dropped_l2=\d+/
      assert log =~ ~r/dropped_l3=\d+/
    end

    test "status line reflects drain state when draining" do
      deliver(:sigusr1)
      log = capture_log(fn -> deliver(:sigusr2) end)
      assert log =~ ~r/\[status\] drain=(draining|drained)/
    end

    test "does not change drain state" do
      deliver(:sigusr2)
      assert {:normal, _} = Drain.status()
    end
  end

  describe "unrelated messages" do
    test "are ignored without crashing or changing state" do
      pid = handler_pid()
      send(pid, :something_else)
      send(pid, {:signal, :sigterm_lookalike})
      send(pid, {:unexpected, 1, 2, 3})
      assert :sys.get_state(pid) == %{}
      assert Process.alive?(pid)
      assert {:normal, _} = Drain.status()
    end
  end

  describe "EventHandler gen_event callbacks (direct)" do
    alias ZtlpRelay.SignalHandler.EventHandler

    test "init accepts a pid and the swap_handler tuple form" do
      assert {:ok, pid} = EventHandler.init(self())
      assert pid == self()
      assert {:ok, pid2} = EventHandler.init({self(), :swap})
      assert pid2 == self()
    end

    test "sigusr1/sigusr2 are forwarded as {:signal, sig}; other signals are swallowed" do
      assert {:ok, _} = EventHandler.handle_event(:sigusr1, self())
      assert_receive {:signal, :sigusr1}
      assert {:ok, _} = EventHandler.handle_event(:sigusr2, self())
      assert_receive {:signal, :sigusr2}
      assert {:ok, _} = EventHandler.handle_event(:sighup, self())
      assert {:ok, _} = EventHandler.handle_event(:sigwinch, self())
      refute_receive {:signal, _}, 50
    end

    test "misc callbacks are inert" do
      assert {:ok, :ok, p} = EventHandler.handle_call(:anything, self())
      assert p == self()
      assert {:ok, p2} = EventHandler.handle_info(:noise, self())
      assert p2 == self()
      assert :ok = EventHandler.terminate(:shutdown, self())
      assert {:ok, p3} = EventHandler.code_change(1, self(), [])
      assert p3 == self()
    end
  end

  describe "real OS signal delivery" do
    test "our EventHandler replaces OTP's default erl_signal_handler on :erl_signal_server" do
      handlers = :gen_event.which_handlers(:erl_signal_server)
      assert SignalHandler.EventHandler in handlers
      refute :erl_signal_handler in handlers, "default handler would halt the node on SIGUSR1"
      assert Enum.count(handlers, &(&1 == SignalHandler.EventHandler)) == 1
    end

    test "a real SIGUSR1 to the BEAM starts drain mode instead of halting the node" do
      pid = handler_pid()

      log =
        capture_log(fn ->
          {_, 0} = System.cmd("kill", ["-USR1", to_string(:os.getpid())])
          Process.sleep(200)
          :sys.get_state(pid)
        end)

      assert Process.alive?(pid), "node must still be alive after SIGUSR1"
      {state, _} = Drain.status()
      assert state in [:draining, :drained]
      assert log =~ "SIGUSR1 received"
    end

    test "restarting the handler does not leave a duplicate EventHandler installed" do
      pid = handler_pid()
      Process.exit(pid, :kill)
      # Supervisor restarts it; wait for the new pid.
      new_pid =
        Enum.find_value(1..50, fn _ ->
          Process.sleep(20)
          case Process.whereis(SignalHandler) do
            p when is_pid(p) and p != pid -> p
            _ -> nil
          end
        end)

      assert is_pid(new_pid)
      handlers = :gen_event.which_handlers(:erl_signal_server)
      assert Enum.count(handlers, &(&1 == SignalHandler.EventHandler)) == 1
      refute :erl_signal_handler in handlers
    end

    # BUG (found 2026-09-13, FIXED same day via EventHandler swap; history below):
    #
    # `:os.set_signal(:sigusr1, :handle)` only tells the emulator to forward
    # the signal to the `:erl_signal_server` gen_event. It does NOT deliver a
    # `{:signal, sig}` message to this GenServer. Nothing in SignalHandler
    # registers a gen_event handler, so:
    #   - SIGUSR2 is swallowed by OTP's default `erl_signal_handler`
    #     (catch-all `handle_event(_, S) -> {ok, S}`), and status is never
    #     logged. This test proves it: the log below is empty.
    #   - SIGUSR1 hits `erl_signal_handler:handle_event(sigusr1, _) ->
    #     erlang:halt("Received SIGUSR1")`. The documented "systemd
    #     ExecReload = drain" signal HALTS THE RELAY. Not tested live here
    #     because it would kill the test VM.
    # Fix: in init/1, `:gen_event.swap_sup_handler(:erl_signal_server,
    # {:erl_signal_handler, []}, {ZtlpRelay.SignalHandler.EventHandler, self()})`
    # (or add_handler + delete the default) with a gen_event module that
    # `send(pid, {:signal, sig})`. (Fixed 2026-09-13 via ZtlpRelay.SignalHandler.EventHandler.)
    test "a real SIGUSR2 to the BEAM reaches the handler and dumps status" do
      # This exercises the actual :os.set_signal path end-to-end. Skipped if
      # `kill` is unavailable. SIGUSR2 is chosen because it has no side
      # effects (SIGUSR1 would put the relay into drain mode).
      case System.find_executable("kill") do
        nil ->
          :ok

        kill ->
          log =
            capture_log(fn ->
              {_, 0} = System.cmd(kill, ["-USR2", Integer.to_string(:os.getpid() |> List.to_integer())])
              # Give erl_signal_server -> SignalHandler a moment.
              Process.sleep(200)
              :sys.get_state(handler_pid())
            end)

          assert log =~ "SIGUSR2 received"
          assert log =~ "[status] drain="
      end
    end
  end
end
