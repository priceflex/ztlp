defmodule ZtlpGateway.BackendPoolTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.BackendPool

  @host {127, 0, 0, 1}

  # Start a TCP listener on a random port and return {listener_socket, port}
  defp start_listener do
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(lsock)
    {lsock, port}
  end

  # Accept a connection on the listener
  defp accept(lsock) do
    {:ok, sock} = :gen_tcp.accept(lsock, 5_000)
    sock
  end

  setup do
    # Ensure BackendPool is running (started by application supervisor in tests)
    case GenServer.whereis(BackendPool) do
      nil ->
        {:ok, pid} = BackendPool.start_link()
        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
        end)

      _pid ->
        :ok
    end

    # Capture baseline metrics for relative assertions
    status = BackendPool.status()
    {:ok, baseline: status}
  end

  describe "checkout creates new connection when pool empty" do
    test "checkout opens a new TCP connection to the backend" do
      {lsock, port} = start_listener()

      # Checkout should create a new connection since pool is empty
      assert {:ok, pid} = BackendPool.checkout(@host, port, self())
      assert is_pid(pid)
      assert Process.alive?(pid)

      # The listener should have received a connection
      server = accept(lsock)
      assert is_port(server)

      # Clean up
      BackendPool.close(pid)
      :gen_tcp.close(lsock)
      :gen_tcp.close(server)
    end

    test "checkout returns error when backend is unreachable" do
      # Use a port that nothing is listening on
      assert {:error, _reason} = BackendPool.checkout(@host, 1, self(), nil, 500)
    end
  end

  describe "checkin returns connection, subsequent checkout reuses it" do
    test "checked-in connection is reused on next checkout" do
      {lsock, port} = start_listener()

      # First checkout — creates new connection
      assert {:ok, pid1} = BackendPool.checkout(@host, port, self())
      server1 = accept(lsock)

      # Checkin the connection
      BackendPool.checkin(pid1)
      Process.sleep(50)

      # Second checkout — should reuse the pooled socket (pool hit)
      assert {:ok, pid2} = BackendPool.checkout(@host, port, self())
      # pid2 is a new Conn process wrapping the same socket
      assert is_pid(pid2)
      assert pid2 != pid1

      # Verify the connection still works: send data through the reused socket
      :ok = :gen_tcp.send(server1, "hello from server")
      assert_receive {:backend_data, "hello from server"}, 1_000

      # Clean up
      BackendPool.close(pid2)
      :gen_tcp.close(lsock)
      :gen_tcp.close(server1)
    end

    test "checked-in socket can carry data in both directions" do
      {lsock, port} = start_listener()

      assert {:ok, pid1} = BackendPool.checkout(@host, port, self())
      server = accept(lsock)

      # Checkin and re-checkout
      BackendPool.checkin(pid1)
      Process.sleep(50)

      assert {:ok, pid2} = BackendPool.checkout(@host, port, self())

      # Send data from server to client (through pool)
      :ok = :gen_tcp.send(server, "server data")
      assert_receive {:backend_data, "server data"}, 1_000

      # Send data from client to server (through pool Conn)
      :ok = GenServer.call(pid2, {:send, "client data"})
      {:ok, data} = :gen_tcp.recv(server, 0, 1_000)
      assert data == "client data"

      # Clean up
      BackendPool.close(pid2)
      :gen_tcp.close(lsock)
      :gen_tcp.close(server)
    end
  end

  describe "pool respects max size" do
    test "excess connections are closed on checkin when pool is full" do
      # Set pool size to 2
      Application.put_env(:ztlp_gateway, :pool_size, 2)
      on_exit(fn -> Application.delete_env(:ztlp_gateway, :pool_size) end)

      {lsock, port} = start_listener()

      # Create 3 connections
      pids =
        for _ <- 1..3 do
          {:ok, pid} = BackendPool.checkout(@host, port, self())
          _server = accept(lsock)
          pid
        end

      # Checkin all 3 sequentially
      Enum.each(pids, fn pid ->
        BackendPool.checkin(pid)
      end)

      # Wait for all async casts to process
      # Force a synchronous call to ensure casts are processed
      _ = BackendPool.idle_count(@host, port)
      Process.sleep(50)

      # Only 2 should be in the pool (3rd was closed because pool is full)
      count = BackendPool.idle_count(@host, port)
      assert count == 2, "Expected 2 idle connections, got #{count}"

      # Checkout both and verify they're valid
      assert {:ok, _} = BackendPool.checkout(@host, port, self())
      assert {:ok, _} = BackendPool.checkout(@host, port, self())

      # Pool should now be empty for this backend
      assert BackendPool.idle_count(@host, port) == 0

      :gen_tcp.close(lsock)
    end
  end

  describe "idle timeout closes stale connections" do
    test "sweep closes old connections" do
      # Set a very short idle timeout
      Application.put_env(:ztlp_gateway, :pool_idle_timeout, 1)
      on_exit(fn -> Application.delete_env(:ztlp_gateway, :pool_idle_timeout) end)

      {lsock, port} = start_listener()

      assert {:ok, pid} = BackendPool.checkout(@host, port, self())
      _server = accept(lsock)

      # Checkin the connection
      BackendPool.checkin(pid)
      Process.sleep(50)

      # Verify it's in the pool
      assert BackendPool.idle_count(@host, port) >= 1

      # Trigger a sweep manually
      send(GenServer.whereis(BackendPool), :sweep_idle)
      Process.sleep(50)

      # Should be gone now
      assert BackendPool.idle_count(@host, port) == 0

      :gen_tcp.close(lsock)
    end
  end

  describe "dead connection removed from pool" do
    test "dead Conn process is removed from active monitors" do
      {lsock, port} = start_listener()

      assert {:ok, pid} = BackendPool.checkout(@host, port, self())
      server = accept(lsock)

      # Kill the server side — TCP close propagates to Conn
      :gen_tcp.close(server)
      Process.sleep(100)

      # The Conn process should have died
      refute Process.alive?(pid)

      # Status should show 0 active (monitor was cleaned up via :DOWN)
      status = BackendPool.status()
      assert status.active == 0

      :gen_tcp.close(lsock)
    end

    test "checkin of dead connection does not add to pool" do
      {lsock, port} = start_listener()

      assert {:ok, pid} = BackendPool.checkout(@host, port, self())
      server = accept(lsock)

      # Kill the server side
      :gen_tcp.close(server)
      Process.sleep(100)

      # Try to checkin the dead connection
      BackendPool.checkin(pid)
      Process.sleep(50)

      # Pool should be empty
      assert BackendPool.idle_count(@host, port) == 0

      :gen_tcp.close(lsock)
    end

    test "stale pooled socket is discarded on checkout" do
      {lsock, port} = start_listener()

      assert {:ok, pid} = BackendPool.checkout(@host, port, self())
      server = accept(lsock)

      # Checkin the connection
      BackendPool.checkin(pid)
      Process.sleep(50)

      # Verify it's in the pool
      assert BackendPool.idle_count(@host, port) == 1

      # Now close the server side — the pooled socket becomes dead
      :gen_tcp.close(server)
      Process.sleep(50)

      # Checkout should detect the dead socket and discard it.
      # Since no listener is available for a new connection, it should error.
      :gen_tcp.close(lsock)
      assert {:error, _reason} = BackendPool.checkout(@host, port, self(), nil, 500)

      # The stale socket should have been discarded from the pool
      assert BackendPool.idle_count(@host, port) == 0
    end
  end

  describe "multiple backends tracked independently" do
    test "different {host, port} backends are independent pools" do
      {lsock_a, port_a} = start_listener()
      {lsock_b, port_b} = start_listener()

      # Checkout from backend A
      assert {:ok, pid_a} = BackendPool.checkout(@host, port_a, self())
      _server_a = accept(lsock_a)

      # Checkout from backend B
      assert {:ok, pid_b} = BackendPool.checkout(@host, port_b, self())
      _server_b = accept(lsock_b)

      # Checkin both
      BackendPool.checkin(pid_a)
      BackendPool.checkin(pid_b)
      Process.sleep(50)

      # Each backend has exactly one idle connection
      assert BackendPool.idle_count(@host, port_a) == 1
      assert BackendPool.idle_count(@host, port_b) == 1

      # Checkout from backend A doesn't affect backend B
      assert {:ok, _} = BackendPool.checkout(@host, port_a, self())
      assert BackendPool.idle_count(@host, port_a) == 0
      assert BackendPool.idle_count(@host, port_b) == 1

      :gen_tcp.close(lsock_a)
      :gen_tcp.close(lsock_b)
    end
  end

  describe "status reports correct counts" do
    test "status shows correct metrics", %{baseline: baseline} do
      {lsock, port} = start_listener()

      # Checkout creates active connections
      assert {:ok, pid1} = BackendPool.checkout(@host, port, self())
      _server1 = accept(lsock)

      assert {:ok, _pid2} = BackendPool.checkout(@host, port, self())
      _server2 = accept(lsock)

      status = BackendPool.status()
      assert status.active >= baseline.active + 2
      assert status.pool_misses >= baseline.pool_misses + 2

      # Checkin one — it becomes idle
      BackendPool.checkin(pid1)
      Process.sleep(50)

      status = BackendPool.status()
      assert status.idle >= baseline.idle + 1
      assert status.total_checkins >= baseline.total_checkins + 1

      # Checkout again — reuse the idle one (pool hit)
      assert {:ok, _} = BackendPool.checkout(@host, port, self())
      Process.sleep(20)

      status = BackendPool.status()
      assert status.pool_hits >= baseline.pool_hits + 1
      assert status.total_checkouts >= baseline.total_checkouts + 3
      assert status.total_checkins >= baseline.total_checkins + 1

      :gen_tcp.close(lsock)
    end
  end

  describe "stream_id forwarding" do
    test "Conn process forwards backend data with stream_id" do
      {lsock, port} = start_listener()

      stream_id = 42
      assert {:ok, pid} = BackendPool.checkout(@host, port, self(), stream_id)
      server = accept(lsock)

      # Backend sends data
      :ok = :gen_tcp.send(server, "stream data")
      assert_receive {:backend_data, ^stream_id, "stream data"}, 1_000

      # Client sends data through Conn
      :ok = GenServer.call(pid, {:send, "client to server"})
      {:ok, data} = :gen_tcp.recv(server, 0, 1_000)
      assert data == "client to server"

      BackendPool.close(pid)
      :gen_tcp.close(lsock)
      :gen_tcp.close(server)
    end

    test "Conn without stream_id sends plain backend_data" do
      {lsock, port} = start_listener()

      assert {:ok, pid} = BackendPool.checkout(@host, port, self())
      server = accept(lsock)

      :ok = :gen_tcp.send(server, "plain data")
      assert_receive {:backend_data, "plain data"}, 1_000

      BackendPool.close(pid)
      :gen_tcp.close(lsock)
      :gen_tcp.close(server)
    end
  end

  describe "Conn lifecycle" do
    test "Conn sends backend_closed when server disconnects" do
      {lsock, port} = start_listener()

      stream_id = 7
      assert {:ok, pid} = BackendPool.checkout(@host, port, self(), stream_id)
      server = accept(lsock)

      # Close the server side
      :gen_tcp.close(server)

      # Conn should notify owner
      assert_receive {:backend_closed, ^stream_id}, 1_000
      Process.sleep(50)
      refute Process.alive?(pid)

      :gen_tcp.close(lsock)
    end

    test "Conn stops when owner dies" do
      {lsock, port} = start_listener()

      # Start a separate owner process
      owner = spawn(fn -> Process.sleep(:infinity) end)
      assert {:ok, pid} = BackendPool.checkout(@host, port, owner)
      _server = accept(lsock)

      assert Process.alive?(pid)

      # Kill the owner
      Process.exit(owner, :kill)
      Process.sleep(100)

      # Conn should have stopped
      refute Process.alive?(pid)

      :gen_tcp.close(lsock)
    end
  end
end
