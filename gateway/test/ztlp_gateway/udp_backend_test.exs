defmodule ZtlpGateway.UdpBackendTest do
  @moduledoc """
  Tests for the UDP backend connector.

  The UDP backend is the egress counterpart of the (TCP-only) `Backend`
  module. It exists so the gateway can forward decrypted ZTLP payloads
  to backend services that speak plain UDP (DNS, syslog, NTP, raw game
  traffic, etc.).

  Lifecycle model is **request-response (Model A)**:
    * `start_link/1` opens an ephemeral UDP socket via `:gen_udp.open/2`.
    * `send_data/2` calls `:gen_udp.send/4` to the configured (host, port).
    * Replies on that socket are forwarded to the owner as
      `{:backend_data, data}` (same message shape as the TCP backend, so
      the Session GenServer can stay protocol-agnostic).
    * If no reply arrives within the per-call timeout, the owner gets
      `:backend_timeout` and the backend stops (one query, one reply).
    * If the owner dies, the socket is closed and the backend stops.

  Notes
  -----
  * No connection pool: UDP has no connection. Each session gets a fresh
    ephemeral local port. This matches what stub resolvers do.
  * The per-call timeout defaults to 5_000 ms (configurable via opts) and
    is enforced by a `Process.send_after/3` timer that is cancelled when
    a reply arrives.
  * Multi-reply scenarios (e.g. some VoIP, syslog with ACKs) are out of
    scope for Model A. They will need Model B ("UDP pipe") which is a
    future PR.
  """

  use ExUnit.Case, async: true

  alias ZtlpGateway.UdpBackend

  # ── UDP echo fixture ────────────────────────────────────────────
  # Spawns a small UDP echo server bound to ephemeral port and returns
  # `{socket, port}`. Each datagram is echoed back to the sender with
  # the literal prefix `"ECHO:"`. The server lives until the calling
  # process exits or `stop_echo_server/1` is called.
  defp start_echo_server do
    parent = self()

    pid =
      spawn_link(fn ->
        {:ok, sock} = :gen_udp.open(0, [:binary, active: false, reuseaddr: true])
        {:ok, port} = :inet.port(sock)
        send(parent, {:udp_echo_ready, port, sock})
        echo_loop(sock)
      end)

    receive do
      {:udp_echo_ready, port, sock} -> {pid, sock, port}
    after
      2_000 -> flunk("UDP echo fixture did not start within 2s")
    end
  end

  defp echo_loop(sock) do
    case :gen_udp.recv(sock, 0, 5_000) do
      {:ok, {ip, port, data}} ->
        :gen_udp.send(sock, ip, port, "ECHO:" <> data)
        echo_loop(sock)

      {:error, :timeout} ->
        # No traffic for 5 seconds — exit so test runner doesn't hang.
        :ok

      {:error, _other} ->
        :ok
    end
  end

  defp stop_echo_server({_pid, sock, _port}), do: :gen_udp.close(sock)

  # ── Tests ───────────────────────────────────────────────────────

  describe "start_link/1" do
    test "opens an ephemeral UDP socket and accepts send_data" do
      fixture = start_echo_server()
      {_pid, _sock, port} = fixture

      {:ok, backend} = UdpBackend.start_link({{127, 0, 0, 1}, port, self()})

      assert is_pid(backend)
      assert Process.alive?(backend)

      UdpBackend.close(backend)
      stop_echo_server(fixture)
    end
  end

  describe "send/receive" do
    test "forwards a datagram to the backend and routes the reply to the owner" do
      fixture = start_echo_server()
      {_pid, _sock, port} = fixture

      {:ok, backend} = UdpBackend.start_link({{127, 0, 0, 1}, port, self()})
      :ok = UdpBackend.send_data(backend, "ping")

      assert_receive {:backend_data, "ECHO:ping"}, 2_000

      UdpBackend.close(backend)
      stop_echo_server(fixture)
    end

    test "owner can issue multiple sequential queries on the same backend" do
      # Model A says one query → one reply → stop. But many real-world UDP
      # protocols (DNS-over-UDP within a single transaction, RADIUS retries)
      # benefit from allowing the owner to send a follow-up query on the
      # same ephemeral socket before terminating. The contract is therefore
      # "as long as the owner keeps the backend alive, send_data is valid".
      fixture = start_echo_server()
      {_pid, _sock, port} = fixture

      {:ok, backend} = UdpBackend.start_link({{127, 0, 0, 1}, port, self()})

      for i <- 1..3 do
        msg = "q#{i}"
        :ok = UdpBackend.send_data(backend, msg)
        assert_receive {:backend_data, <<"ECHO:", ^msg::binary>>}, 2_000
      end

      UdpBackend.close(backend)
      stop_echo_server(fixture)
    end
  end

  describe "timeout" do
    test "notifies owner of backend_timeout when no reply arrives" do
      # Bind a UDP socket but never read from it — the backend's datagram
      # will be queued in the kernel buffer but no reply will come. The
      # owner must hear about that within the configured timeout.
      {:ok, dead} = :gen_udp.open(0, [:binary, active: false])
      {:ok, port} = :inet.port(dead)

      {:ok, backend} =
        UdpBackend.start_link({{127, 0, 0, 1}, port, self(), [timeout_ms: 200]})

      :ok = UdpBackend.send_data(backend, "no_reply_please")

      assert_receive :backend_timeout, 1_000

      UdpBackend.close(backend)
      :gen_udp.close(dead)
    end
  end

  describe "owner-death cleanup" do
    test "closes the UDP socket and stops when the owning process exits" do
      fixture = start_echo_server()
      {_pid, _sock, port} = fixture

      # Create a transient owner that dies on demand so we can observe
      # the backend's monitored-DOWN path.
      test_pid = self()

      owner =
        spawn_link(fn ->
          {:ok, b} = UdpBackend.start_link({{127, 0, 0, 1}, port, self()})
          send(test_pid, {:owner_backend, b})

          receive do
            :die -> :ok
          after
            5_000 -> :ok
          end
        end)

      backend =
        receive do
          {:owner_backend, b} -> b
        after
          2_000 -> flunk("owner never reported its backend pid")
        end

      ref = Process.monitor(backend)
      send(owner, :die)

      assert_receive {:DOWN, ^ref, :process, ^backend, _reason}, 2_000
      stop_echo_server(fixture)
    end
  end

  describe "error paths" do
    test "send_data returns {:error, _} when the backend is already closed" do
      fixture = start_echo_server()
      {_pid, _sock, port} = fixture

      {:ok, backend} = UdpBackend.start_link({{127, 0, 0, 1}, port, self()})
      UdpBackend.close(backend)
      # Give the GenServer.stop a tick.
      Process.sleep(20)
      refute Process.alive?(backend)

      # send_data should not crash the caller — UdpBackend traps :exit so
      # the GenServer.call on a dead pid returns an :error tuple.
      assert {:error, _} = UdpBackend.send_data(backend, "after_close")

      stop_echo_server(fixture)
    end
  end
end
