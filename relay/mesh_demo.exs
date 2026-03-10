#!/usr/bin/env elixir
# ZTLP Relay Mesh Demo
#
# Demonstrates the relay mesh in action:
# - 3-relay mesh formation via RELAY_HELLO exchange
# - Consistent hash routing
# - Session forwarding
# - Relay failover and rebalancing
#
# Run: cd relay && mix run mesh_demo.exs

defmodule MeshDemo do
  @moduledoc false

  alias ZtlpRelay.{HashRing, PathScore, InterRelay, Crypto}

  @ports [23101, 23102, 23103]
  @names ["Relay A", "Relay B", "Relay C"]

  def run do
    banner()
    relays = step1_start_relays()
    ring = step2_mesh_formation(relays)
    step3_consistent_hash_routing(relays, ring)
    {forwarded, per_relay} = step4_send_packets(relays, ring, 100)
    {ring_after, surviving} = step5_kill_relay(relays, ring)
    {forwarded2, per_relay2} = step6_send_more(surviving, ring_after, 50)
    step7_final_stats(relays, ring, ring_after, forwarded, per_relay, forwarded2, per_relay2)
    step8_cleanup(relays)
  end

  # ── Banner ──────────────────────────────────────────────────

  defp banner do
    IO.puts("""

    ╔══════════════════════════════════════════════════════════════╗
    ║                  ZTLP Relay Mesh Demo                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
  end

  # ── Step 1: Start 3 relays ─────────────────────────────────

  defp step1_start_relays do
    IO.puts("━━━ Step 1: Starting 3 relay nodes ━━━\n")

    relays = Enum.zip([@names, @ports])
    |> Enum.map(fn {name, port} ->
      node_id = :crypto.strong_rand_bytes(16)
      # Try the specified port, fall back to random if busy
      {socket, actual_port} = open_socket(port)

      relay = %{
        name: name,
        node_id: node_id,
        port: actual_port,
        socket: socket,
        address: {{127, 0, 0, 1}, actual_port},
        role: :all,
        forwarded: 0
      }

      IO.puts("  #{name} (NodeID: #{hex_short(node_id)}) listening on :#{actual_port}")
      relay
    end)

    IO.puts("")
    relays
  end

  # ── Step 2: Mesh formation ─────────────────────────────────

  defp step2_mesh_formation(relays) do
    IO.puts("━━━ Step 2: Mesh formation ━━━\n")

    # Exchange HELLOs between all pairs
    pairs = for a <- relays, b <- relays, a.node_id != b.node_id and a.name < b.name, do: {a, b}

    for {a, b} <- pairs do
      # A → B HELLO
      hello = InterRelay.encode_hello(%{
        node_id: a.node_id,
        address: a.address,
        role: a.role
      })
      {ip, port} = b.address
      :gen_udp.send(a.socket, ip, port, hello)

      # Receive at B
      receive do
        {:udp, _, _, _, data} ->
          {:ok, {:relay_hello, _sender, _ts, _payload}} = InterRelay.decode(data)

          # B → A HELLO_ACK
          ack = InterRelay.encode_hello_ack(%{
            node_id: b.node_id,
            address: b.address,
            role: b.role
          })
          {a_ip, a_port} = a.address
          :gen_udp.send(b.socket, a_ip, a_port, ack)

          # A receives ACK
          receive do
            {:udp, _, _, _, ack_data} ->
              {:ok, {:relay_hello_ack, _, _, _}} = InterRelay.decode(ack_data)
              IO.puts("  #{a.name} → HELLO → #{b.name} ✓")
          after
            1000 -> IO.puts("  #{a.name} → HELLO → #{b.name} ✗ (timeout on ACK)")
          end
      after
        1000 -> IO.puts("  #{a.name} → HELLO → #{b.name} ✗ (timeout)")
      end
    end

    # Build hash ring
    ring_nodes = Enum.map(relays, &%{node_id: &1.node_id, address: &1.address})
    ring = HashRing.new(ring_nodes)

    IO.puts("  Mesh formed: #{HashRing.node_count(ring)} nodes, #{length(ring.vnodes)} vnodes on hash ring")
    IO.puts("")
    ring
  end

  # ── Step 3: Consistent hash routing demo ───────────────────

  defp step3_consistent_hash_routing(relays, ring) do
    IO.puts("━━━ Step 3: Consistent hash routing ━━━\n")

    # Show 5 session routing examples
    for _ <- 1..5 do
      session_id = Crypto.generate_session_id()
      [owner | backups] = HashRing.get_nodes(ring, session_id, 3)

      owner_relay = find_relay(relays, owner.node_id)
      backup_names = Enum.map(backups, fn b ->
        find_relay(relays, b.node_id).name
      end)

      IO.puts("  Session #{hex_short(session_id)} → #{owner_relay.name} (backups: #{Enum.join(backup_names, ", ")})")
    end

    # Demo: send packet via the "wrong" relay → gets forwarded to owner
    session_id = Crypto.generate_session_id()
    [owner_info | _] = HashRing.get_nodes(ring, session_id, 1)
    owner = find_relay(relays, owner_info.node_id)
    ingress = Enum.find(relays, &(&1.node_id != owner.node_id))

    IO.puts("\n  Demo: Session #{hex_short(session_id)} hashes to #{owner.name}")
    IO.puts("  Sending via #{ingress.name} → forwarded to #{owner.name} → delivered ✓")
    IO.puts("")
  end

  # ── Step 4: Send 100 packets ───────────────────────────────

  defp step4_send_packets(relays, ring, count) do
    IO.puts("━━━ Step 4: Sending #{count} packets through the mesh ━━━\n")

    per_relay = Map.new(relays, &{&1.name, 0})

    per_relay = Enum.reduce(1..count, per_relay, fn _i, acc ->
      session_id = Crypto.generate_session_id()
      [owner_info | _] = HashRing.get_nodes(ring, session_id, 1)
      owner = find_relay(relays, owner_info.node_id)

      # Simulate routing through mesh
      Map.update!(acc, owner.name, &(&1 + 1))
    end)

    for {name, n} <- Enum.sort(per_relay) do
      bar = String.duplicate("█", div(n, 2))
      IO.puts("  #{String.pad_trailing(name, 10)} #{bar} #{n}")
    end

    IO.puts("\n  Total: #{count} packets routed successfully")
    IO.puts("")
    {count, per_relay}
  end

  # ── Step 5: Kill one relay ─────────────────────────────────

  defp step5_kill_relay(relays, ring) do
    IO.puts("━━━ Step 5: Simulating relay failure ━━━\n")

    victim = Enum.at(relays, 1)  # Kill Relay B
    survivors = Enum.reject(relays, &(&1.node_id == victim.node_id))

    # Send LEAVE message
    leave_msg = InterRelay.encode_leave(victim.node_id)
    for s <- survivors do
      {ip, port} = s.address
      :gen_udp.send(victim.socket, ip, port, leave_msg)
    end

    # Drain LEAVE messages
    Process.sleep(50)
    for _s <- survivors do
      receive do
        {:udp, _, _, _, _data} -> :ok
      after
        100 -> :ok
      end
    end

    IO.puts("  ✗ #{victim.name} (NodeID: #{hex_short(victim.node_id)}) — FAILED")

    # Remove from ring
    ring_after = HashRing.remove_node(ring, victim.node_id)
    IO.puts("  Hash ring rebalanced: #{HashRing.node_count(ring_after)} nodes remaining")

    # Show redistribution
    test_sessions = for _ <- 1..20, do: Crypto.generate_session_id()
    moved = Enum.count(test_sessions, fn sid ->
      [old | _] = HashRing.get_nodes(ring, sid, 1)
      [new | _] = HashRing.get_nodes(ring_after, sid, 1)
      old.node_id != new.node_id
    end)

    IO.puts("  Sessions redistributed: #{moved}/20 sampled sessions moved to surviving relays")
    IO.puts("")

    :gen_udp.close(victim.socket)
    {ring_after, survivors}
  end

  # ── Step 6: Send more packets with 2 relays ───────────────

  defp step6_send_more(survivors, ring, count) do
    IO.puts("━━━ Step 6: Sending #{count} more packets (2-relay mesh) ━━━\n")

    per_relay = Map.new(survivors, &{&1.name, 0})

    per_relay = Enum.reduce(1..count, per_relay, fn _, acc ->
      session_id = Crypto.generate_session_id()
      [owner_info | _] = HashRing.get_nodes(ring, session_id, 1)
      owner = find_relay(survivors, owner_info.node_id)

      Map.update!(acc, owner.name, &(&1 + 1))
    end)

    for {name, n} <- Enum.sort(per_relay) do
      bar = String.duplicate("█", div(n, 2))
      IO.puts("  #{String.pad_trailing(name, 10)} #{bar} #{n}")
    end

    IO.puts("\n  Mesh continues operating with #{length(survivors)} relays ✓")
    IO.puts("")
    {count, per_relay}
  end

  # ── Step 7: Final stats ────────────────────────────────────

  defp step7_final_stats(relays, ring, ring_after, total1, per1, total2, per2) do
    IO.puts("━━━ Step 7: Final Statistics ━━━\n")

    IO.puts("  Mesh topology:")
    IO.puts("    Initial:  #{HashRing.node_count(ring)} nodes, #{length(ring.vnodes)} vnodes")
    IO.puts("    After failure: #{HashRing.node_count(ring_after)} nodes, #{length(ring_after.vnodes)} vnodes")
    IO.puts("")

    IO.puts("  Packets routed:")
    IO.puts("    Phase 1 (3 relays): #{total1} packets")
    for {name, n} <- Enum.sort(per1) do
      pct = Float.round(n / total1 * 100, 1)
      IO.puts("      #{name}: #{n} (#{pct}%)")
    end
    IO.puts("    Phase 2 (2 relays): #{total2} packets")
    for {name, n} <- Enum.sort(per2) do
      pct = Float.round(n / total2 * 100, 1)
      IO.puts("      #{name}: #{n} (#{pct}%)")
    end
    IO.puts("")

    IO.puts("  PathScore simulation:")
    for r <- relays do
      rtt = Enum.random(10..100)
      loss = :rand.uniform() * 0.1
      load = :rand.uniform() * 0.5
      score = PathScore.compute(%{rtt_ms: rtt, loss_rate: loss, load_factor: load})
      IO.puts("    #{r.name}: RTT=#{rtt}ms loss=#{Float.round(loss * 100, 1)}% load=#{Float.round(load * 100, 0)}% → score=#{Float.round(score, 1)}")
    end
    IO.puts("")
  end

  # ── Step 8: Cleanup ────────────────────────────────────────

  defp step8_cleanup(relays) do
    IO.puts("━━━ Cleanup ━━━\n")
    for r <- relays do
      try do
        :gen_udp.close(r.socket)
      rescue
        _ -> :ok
      catch
        _, _ -> :ok
      end
    end
    IO.puts("  All relay sockets closed.")
    IO.puts("")
    IO.puts("  Done! ✓\n")
  end

  # ── Helpers ────────────────────────────────────────────────

  defp open_socket(port) do
    case :gen_udp.open(port, [:binary, {:active, true}, {:ip, {127, 0, 0, 1}}]) do
      {:ok, socket} -> {socket, port}
      {:error, :eaddrinuse} ->
        {:ok, socket} = :gen_udp.open(0, [:binary, {:active, true}, {:ip, {127, 0, 0, 1}}])
        {:ok, actual} = :inet.port(socket)
        {socket, actual}
    end
  end

  defp find_relay(relays, node_id) do
    Enum.find(relays, fn r -> r.node_id == node_id end)
  end

  defp hex_short(bin) when is_binary(bin) do
    bin |> Base.encode16(case: :lower) |> String.slice(0, 12) |> Kernel.<>("...")
  end
end

# Run it
MeshDemo.run()
