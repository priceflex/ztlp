defmodule ZtlpGateway.BackendTest do
  use ExUnit.Case

  alias ZtlpGateway.Backend

  # Start a simple TCP echo server for testing.
  # Receives data, echoes it back prefixed with "ECHO:".
  defp start_echo_server do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)

    # Accept one connection in a spawned process
    parent = self()

    pid =
      spawn_link(fn ->
        {:ok, client} = :gen_tcp.accept(listen, 5_000)
        send(parent, {:echo_server_ready, self()})
        echo_loop(client)
      end)

    {listen, port, pid}
  end

  defp echo_loop(socket) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} ->
        :gen_tcp.send(socket, "ECHO:" <> data)
        echo_loop(socket)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        :ok
    end
  end

  describe "Backend TCP connection" do
    test "connects and sends/receives data" do
      {listen, port, _echo_pid} = start_echo_server()

      {:ok, backend} = Backend.start_link({{127, 0, 0, 1}, port, self()})

      # Wait for echo server to accept
      receive do
        {:echo_server_ready, _} -> :ok
      after
        2_000 -> flunk("Echo server didn't accept")
      end

      # Send data through the backend
      :ok = Backend.send_data(backend, "hello")

      # Should receive echoed response
      assert_receive {:backend_data, "ECHO:hello"}, 2_000

      Backend.close(backend)
      :gen_tcp.close(listen)
    end

    test "multiple send/receive cycles" do
      {listen, port, _echo_pid} = start_echo_server()
      {:ok, backend} = Backend.start_link({{127, 0, 0, 1}, port, self()})

      receive do
        {:echo_server_ready, _} -> :ok
      after
        2_000 -> flunk("Echo server didn't accept")
      end

      for i <- 1..5 do
        msg = "message_#{i}"
        :ok = Backend.send_data(backend, msg)
        assert_receive {:backend_data, <<"ECHO:", ^msg::binary>>}, 2_000
      end

      Backend.close(backend)
      :gen_tcp.close(listen)
    end

    test "notifies owner when backend closes" do
      # Use a custom server that closes the connection after first recv
      {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen)

      spawn_link(fn ->
        {:ok, client} = :gen_tcp.accept(listen, 5_000)
        # Wait for one message, then close
        {:ok, _data} = :gen_tcp.recv(client, 0, 5_000)
        :gen_tcp.close(client)
      end)

      {:ok, backend} = Backend.start_link({{127, 0, 0, 1}, port, self()})
      # Small delay to let the TCP connection establish
      Process.sleep(50)
      Backend.send_data(backend, "trigger_close")

      # Backend should notify us of the close
      assert_receive :backend_closed, 5_000

      :gen_tcp.close(listen)
    end

    test "fails to connect to non-existent service" do
      # Port 1 is almost certainly not listening
      result = Backend.start_link({{127, 0, 0, 1}, 1, self()})
      assert {:error, _} = result
    end
  end
end
