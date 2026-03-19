defmodule ZtlpRelay.GatewayForwarderTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.GatewayForwarder

  setup do
    # GatewayForwarder may or may not be started by the application
    case GenServer.whereis(GatewayForwarder) do
      nil ->
        {:ok, pid} = GatewayForwarder.start_link()

        on_exit(fn ->
          try do
            GenServer.stop(pid, :normal, 1000)
          catch
            :exit, _ -> :ok
          end
        end)

        :ok

      _pid ->
        :ok
    end
  end

  test "count starts at 0" do
    assert GatewayForwarder.count() == 0
  end

  test "register and lookup forwarded session" do
    session_id = :crypto.strong_rand_bytes(12)
    client = {{10, 0, 0, 1}, 5000}
    gateway = {{10, 0, 0, 2}, 23098}

    GatewayForwarder.register_forwarded_session(session_id, client, gateway)
    # Cast is async, give it a moment
    Process.sleep(10)

    assert {:ok, session} = GatewayForwarder.lookup(session_id)
    assert session.client == client
    assert session.gateway == gateway
    assert GatewayForwarder.count() == 1
  end

  test "lookup returns error for unknown session" do
    assert :error == GatewayForwarder.lookup(:crypto.strong_rand_bytes(12))
  end

  test "multiple sessions tracked independently" do
    s1 = :crypto.strong_rand_bytes(12)
    s2 = :crypto.strong_rand_bytes(12)
    c1 = {{10, 0, 0, 1}, 5000}
    c2 = {{10, 0, 0, 3}, 6000}
    gw = {{10, 0, 0, 2}, 23098}

    GatewayForwarder.register_forwarded_session(s1, c1, gw)
    GatewayForwarder.register_forwarded_session(s2, c2, gw)
    Process.sleep(10)

    assert {:ok, session1} = GatewayForwarder.lookup(s1)
    assert {:ok, session2} = GatewayForwarder.lookup(s2)
    assert session1.client == c1
    assert session2.client == c2
    assert GatewayForwarder.count() == 2
  end
end
