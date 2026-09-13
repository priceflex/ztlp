# R1 spike: can a gen_udp socket with SO_REUSEPORT share the QUIC listener's
# port purely for SENDING, without stealing inbound QUIC datagrams?
# Run: mix run test/support/r1_reuseport_spike.exs  (inside the builder image)

alias ZtlpGateway.Quic.{Frame, Listener}
alias ZtlpGateway.Handshake, as: Noise
alias ZtlpGateway.{Crypto, Packet, PolicyEngine}

{:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
{:ok, bport} = :inet.port(lsock)

spawn_link(fn ->
  loop = fn loop ->
    {:ok, s} = :gen_tcp.accept(lsock)
    spawn_link(fn ->
      {:ok, req} = :gen_tcp.recv(s, 0, 5000)
      :gen_tcp.send(s, "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(req)}\r\nConnection: close\r\n\r\n" <> req)
      :gen_tcp.shutdown(s, :write)
      _ = :gen_tcp.recv(s, 0, 2000)
      :gen_tcp.close(s)
    end)
    loop.(loop)
  end
  loop.(loop)
end)

Application.put_env(:ztlp_gateway, :backends, [%{name: "svc", host: ~c"127.0.0.1", port: bport, protocol: :tcp}])
PolicyEngine.put_rule("svc", :all)
dir = "/tmp/r1-spike-#{System.unique_integer([:positive])}"
{:ok, l} = Listener.start_link(port: 0, data_dir: dir, acceptors: 2)
port = Listener.port(l)
IO.puts("quic listener on #{port}")

# --- the contested socket ---------------------------------------------------
sol_socket = 1
so_reuseport = 15
reuse = case :gen_udp.open(port, [:binary, {:reuseaddr, true}, {:raw, sol_socket, so_reuseport, <<1::32-native>>}, {:ip, {0,0,0,0}}]) do
  {:ok, s} -> IO.puts("gen_udp SO_REUSEPORT bind on #{port}: OK"); s
  {:error, r} -> IO.puts("gen_udp SO_REUSEPORT bind on #{port}: #{inspect(r)}"); nil
end

# also try binding on 127.0.0.1 specifically (msquic may bind wildcard)
_ = if reuse == nil do
  case :gen_udp.open(port, [:binary, {:reuseaddr, true}, {:raw, sol_socket, so_reuseport, <<1::32-native>>}, {:ip, {127,0,0,1}}]) do
    {:ok, s} -> IO.puts("gen_udp SO_REUSEPORT bind 127.0.0.1:#{port}: OK"); s
    {:error, r} -> IO.puts("gen_udp SO_REUSEPORT bind 127.0.0.1:#{port}: #{inspect(r)}"); nil
  end
end

stolen_counter = :counters.new(1, [])
if reuse do
  :inet.setopts(reuse, active: true)
  spawn_link(fn ->
    recv = fn recv ->
      receive do
        {:udp, _, _ip, _p, _data} ->
          :counters.add(stolen_counter, 1, 1)
          recv.(recv)
      end
    end
    recv.(recv)
  end)
end

# --- client: N connections, each handshake + 1 HTTP round trip -----------------
collect = fn collect, stream, acc, deadline ->
  receive do
    {:quic, bin, ^stream, _} when is_binary(bin) -> collect.(collect, stream, acc <> bin, deadline)
    {:quic, :peer_send_shutdown, ^stream, _} -> {:fin, acc}
    {:quic, :stream_closed, ^stream, _} -> {:fin, acc}
  after
    deadline -> {:timeout, acc}
  end
end

one = fn ->
  case :quicer.connect(~c"127.0.0.1", port, %{alpn: [~c"ztlp/1"], verify: :none, peer_bidi_stream_count: 4, idle_timeout_ms: 5000}, 3000) do
    {:ok, conn} ->
      {c_pub, c_priv} = Crypto.generate_keypair()
      nid = :crypto.strong_rand_bytes(16)
      {:ok, s0} = :quicer.start_stream(conn, %{active: true})
      init = Noise.init_initiator(c_pub, c_priv)
      {init, m1} = Noise.create_msg1(init, nid)
      {:ok, _} = :quicer.send(s0, Packet.service_hash("svc") <> Frame.encode(m1))
      wait = fn wait, acc ->
        if byte_size(acc) >= 12 + 3 + 112 do {:ok, acc} else
          receive do
            {:quic, bin, ^s0, _} when is_binary(bin) -> wait.(wait, acc <> bin)
          after 3000 -> {:timeout, acc} end
        end
      end
      case wait.(wait, <<>>) do
        {:ok, <<_sid::binary-size(12), framed::binary>>} ->
          {:ok, m2, <<>>} = Frame.decode(framed)
          {init, _} = Noise.process_msg2(init, m2)
          {_init, m3} = Noise.create_msg3(init, nid)
          {:ok, _} = :quicer.send(s0, Frame.encode(m3))
          {:ok, s} = :quicer.start_stream(conn, %{active: true})
          {:ok, _} = :quicer.send(s, Frame.encode("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
          r = case collect.(collect, s, <<>>, 3000) do
            {:fin, bytes} when byte_size(bytes) > 0 -> :ok
            other -> {:fail, other}
          end
          :quicer.async_shutdown_connection(conn, 0, 0)
          r
        other -> {:fail, {:handshake, other}}
      end
    {:error, _} = e -> {:fail, e}
    {:error, a, b} -> {:fail, {a, b}}
  end
end

n = 100

# Baseline first: with the reuseport socket CLOSED, all round trips must pass.
if reuse, do: :inet.setopts(reuse, active: false)
baseline_sock = reuse
if baseline_sock, do: :gen_udp.close(baseline_sock)
base = for _ <- 1..20, do: one.()
IO.puts("baseline (no reuseport socket): #{Enum.count(base, &(&1 == :ok))}/20 ok")

parent = self()
spawn_link(fn ->
  case :gen_udp.open(port, [:binary, {:reuseaddr, true}, {:raw, sol_socket, so_reuseport, <<1::32-native>>}, {:ip, {0,0,0,0}}, {:active, true}]) do
    {:ok, s} ->
      send(parent, {:reuse, s})
      recv = fn recv ->
        receive do
          {:udp, _, _ip, _p, _data} -> :counters.add(stolen_counter, 1, 1); recv.(recv)
        end
      end
      recv.(recv)
    {:error, r} ->
      IO.puts("re-bind failed: #{inspect(r)}"); send(parent, {:reuse, nil})
  end
end)
reuse = receive do {:reuse, s} -> s end
sender = if reuse do
  spawn_link(fn ->
    for _ <- 1..500 do
      :gen_udp.send(reuse, {127,0,0,1}, 9, <<0x5A,0x37,0x0A, 0::76*8>>)  # 79-byte register-shaped frame to discard port
      Process.sleep(2)
    end
  end)
end
_ = sender

results = for _ <- 1..n, do: one.()
ok = Enum.count(results, &(&1 == :ok))
IO.puts("round trips: #{ok}/#{n} ok")
IO.puts("inbound datagrams STOLEN by gen_udp socket: #{:counters.get(stolen_counter, 1)}")
fails = results |> Enum.reject(&(&1 == :ok)) |> Enum.frequencies()
IO.puts("failures: #{inspect(fails, limit: 5)}")
File.rm_rf!(dir)
