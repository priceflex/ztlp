defmodule ZtlpGateway.Session.BackendDispatchTest do
  @moduledoc """
  Tests for `ZtlpGateway.Session.start_backend_for/2`, the small dispatcher
  introduced alongside UdpBackend.

  The dispatcher's only job is to look at the `:protocol` field on a backend
  map (returned by `Config.get(:backends)` / `find_backend/2`) and call
  `ZtlpGateway.Backend.start_link/1` (TCP, default) or
  `ZtlpGateway.UdpBackend.start_link/1` (UDP). This file pins that mapping
  end-to-end so a future refactor cannot silently break protocol selection.

  Why a focused dispatch test rather than a full session integration test:
  the full session path requires Listener + Noise handshake setup that the
  rest of the suite already exercises for the TCP path (~860 tests). Once
  dispatch is correct, the existing path tests cover the TCP side and the
  Phase-1 udp_backend_test.exs covers the UDP side. The dispatcher is the
  only new code on the path, so it gets its own test.
  """

  use ExUnit.Case, async: true

  alias ZtlpGateway.Session

  # Tiny TCP echo for the :tcp dispatch path.
  defp start_tcp_echo do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)

    spawn_link(fn ->
      case :gen_tcp.accept(listen, 5_000) do
        {:ok, sock} -> tcp_echo_loop(sock)
        {:error, _} -> :ok
      end
    end)

    {listen, port}
  end

  defp tcp_echo_loop(sock) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, data} ->
        :gen_tcp.send(sock, "ECHO:" <> data)
        tcp_echo_loop(sock)

      _ ->
        :ok
    end
  end

  defp stop_tcp_echo({listen, _port}), do: :gen_tcp.close(listen)

  # Tiny UDP echo for the :udp dispatch path.
  defp start_udp_echo do
    parent = self()

    spawn_link(fn ->
      {:ok, sock} = :gen_udp.open(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(sock)
      send(parent, {:udp_echo_ready, port, sock})
      udp_echo_loop(sock)
    end)

    receive do
      {:udp_echo_ready, port, sock} -> {sock, port}
    after
      2_000 -> flunk("UDP echo did not start within 2s")
    end
  end

  defp udp_echo_loop(sock) do
    case :gen_udp.recv(sock, 0, 5_000) do
      {:ok, {ip, port, data}} ->
        :gen_udp.send(sock, ip, port, "ECHO:" <> data)
        udp_echo_loop(sock)

      _ ->
        :ok
    end
  end

  defp stop_udp_echo({sock, _port}), do: :gen_udp.close(sock)

  describe "start_backend_for/2" do
    test ":tcp protocol (or no :protocol field) routes to the TCP Backend module" do
      {_listen, port} = fixture = start_tcp_echo()

      # No :protocol key — back-compat path. find_backend/2 produces this
      # shape from a pre-feature operator config.
      backend_map = %{name: "web", host: ~c"127.0.0.1", port: port}

      assert {:ok, pid} = Session.start_backend_for(backend_map, self())
      assert is_pid(pid)

      # Exercise the connection to prove it really is a TCP backend.
      :ok = ZtlpGateway.Backend.send_data(pid, "hello")
      assert_receive {:backend_data, "ECHO:hello"}, 2_000

      ZtlpGateway.Backend.close(pid)
      stop_tcp_echo(fixture)
    end

    test "explicit :tcp protocol also routes to the TCP Backend module" do
      {_listen, port} = fixture = start_tcp_echo()
      backend_map = %{name: "ssh", host: ~c"127.0.0.1", port: port, protocol: :tcp}

      assert {:ok, pid} = Session.start_backend_for(backend_map, self())
      :ok = ZtlpGateway.Backend.send_data(pid, "x")
      assert_receive {:backend_data, "ECHO:x"}, 2_000

      ZtlpGateway.Backend.close(pid)
      stop_tcp_echo(fixture)
    end

    test ":udp protocol routes to the UdpBackend module" do
      {_sock, port} = fixture = start_udp_echo()
      backend_map = %{name: "dns", host: {127, 0, 0, 1}, port: port, protocol: :udp}

      assert {:ok, pid} = Session.start_backend_for(backend_map, self())
      :ok = ZtlpGateway.UdpBackend.send_data(pid, "query")
      assert_receive {:backend_data, "ECHO:query"}, 2_000

      ZtlpGateway.UdpBackend.close(pid)
      stop_udp_echo(fixture)
    end

    test "unknown :protocol value returns {:error, :unsupported_protocol}" do
      # Defensive: if someone hand-crafts a backend map with a bogus
      # protocol (or a typo flows through future config), the dispatcher
      # should fail fast — not silently default to TCP, which could send
      # a UDP-only payload over TCP and corrupt the application protocol.
      backend_map = %{name: "weird", host: ~c"127.0.0.1", port: 22, protocol: :sctp}

      assert {:error, :unsupported_protocol} = Session.start_backend_for(backend_map, self())
    end
  end
end
