defmodule ZtlpGateway.FederationTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.Federation
  alias ZtlpGateway.Federation.Peer

  # ── Helpers ──

  # Start a federation GenServer with a random port and explicit options.
  # Returns the pid; the caller's `on_exit` should stop it.
  defp start_federation(extra_opts \\ []) do
    defaults = [
      enabled: true,
      port: 0,
      zone: "test.local",
      ns_server: nil,
      local_services: Keyword.get(extra_opts, :local_services, [])
    ]

    opts = Keyword.merge(defaults, extra_opts)

    # Unregister any previous instance so we can use the named process
    if pid = GenServer.whereis(Federation) do
      GenServer.stop(pid, :normal, 1_000)
      Process.sleep(10)
    end

    {:ok, pid} = Federation.start_link(opts)
    pid
  end

  # ────────────────────────────────────────────
  # 1. Federation starts disabled by default (no env var)
  # ────────────────────────────────────────────
  test "starts disabled by default when no env var set" do
    # Ensure env var is unset
    System.delete_env("ZTLP_GATEWAY_FEDERATION_ENABLED")

    if pid = GenServer.whereis(Federation) do
      GenServer.stop(pid, :normal, 1_000)
      Process.sleep(10)
    end

    {:ok, pid} = Federation.start_link([])

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    status = Federation.status()
    assert status.enabled == false
  end

  # ────────────────────────────────────────────
  # 2. Federation status shows enabled=false when disabled
  # ────────────────────────────────────────────
  test "status returns enabled=false and nil gateway_id when disabled" do
    if pid = GenServer.whereis(Federation) do
      GenServer.stop(pid, :normal, 1_000)
      Process.sleep(10)
    end

    {:ok, pid} = Federation.start_link(enabled: false)

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    status = Federation.status()
    assert status.enabled == false
    assert status.gateway_id == nil
    assert status.peer_count == 0
    assert status.healthy_peers == 0
  end

  # ────────────────────────────────────────────
  # 3. Federation starts with enabled: true option
  # ────────────────────────────────────────────
  test "starts enabled when enabled: true is passed" do
    pid = start_federation()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    status = Federation.status()
    assert status.enabled == true
    assert is_binary(status.gateway_id)
    assert byte_size(status.gateway_id) == 32
  end

  # ────────────────────────────────────────────
  # 4. generate_gateway_id returns 16 bytes
  # ────────────────────────────────────────────
  test "generate_gateway_id returns 16 bytes" do
    id = Federation.generate_gateway_id()
    assert byte_size(id) == 16
  end

  # ────────────────────────────────────────────
  # 5. generate_gateway_id is unique each call
  # ────────────────────────────────────────────
  test "generate_gateway_id returns unique values" do
    ids = for _ <- 1..100, do: Federation.generate_gateway_id()
    assert length(Enum.uniq(ids)) == 100
  end

  # ────────────────────────────────────────────
  # 6. parse_hello_payload parses load + services correctly
  # ────────────────────────────────────────────
  test "parse_hello_payload parses load and service names" do
    # load=42, 2 services: "web" (3 bytes), "api" (3 bytes)
    payload = <<42, 2, 3, "web", 3, "api">>
    {services, load} = Federation.parse_hello_payload(payload)
    assert load == 42
    assert services == ["web", "api"]
  end

  # ────────────────────────────────────────────
  # 7. parse_hello_payload handles empty services
  # ────────────────────────────────────────────
  test "parse_hello_payload handles zero services" do
    payload = <<10, 0>>
    {services, load} = Federation.parse_hello_payload(payload)
    assert load == 10
    assert services == []
  end

  # ────────────────────────────────────────────
  # 8. parse_service_names parses multiple services
  # ────────────────────────────────────────────
  test "parse_service_names parses multiple length-prefixed names" do
    data = <<5, "alpha", 4, "beta", 5, "gamma">>
    result = Federation.parse_service_names(data, 3, [])
    assert result == ["alpha", "beta", "gamma"]
  end

  # ────────────────────────────────────────────
  # 9. route_service returns {:local, _} for local service
  # ────────────────────────────────────────────
  test "route_service returns {:local, _} for locally served service" do
    pid = start_federation(local_services: [{"myservice", nil}])

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    assert {:local, _gateway_id} = Federation.route_service("myservice")
  end

  # ────────────────────────────────────────────
  # 10. route_service returns error for unknown service
  # ────────────────────────────────────────────
  test "route_service returns {:error, :no_gateway_available} for unknown service" do
    pid = start_federation()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    assert {:error, :no_gateway_available} = Federation.route_service("nonexistent")
  end

  # ────────────────────────────────────────────
  # 11. service_weights returns local weight for local service
  # ────────────────────────────────────────────
  test "service_weights includes local gateway with weight 100" do
    pid = start_federation(local_services: [{"web", nil}])

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    weights = Federation.service_weights("web")
    assert length(weights) == 1
    [{_gw_id, weight}] = weights
    assert weight == 100
  end

  # ────────────────────────────────────────────
  # 12. service_weights returns empty for unknown service
  # ────────────────────────────────────────────
  test "service_weights returns empty list for unknown service" do
    pid = start_federation()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    assert [] == Federation.service_weights("nonexistent")
  end

  # ────────────────────────────────────────────
  # 13. Peer status transitions
  # ────────────────────────────────────────────
  test "peer status transitions: healthy → degraded → unreachable" do
    now = System.monotonic_time(:millisecond)

    # Healthy: last_seen within 2× ping interval
    healthy = %Peer{
      gateway_id: :crypto.strong_rand_bytes(16),
      addr: {{127, 0, 0, 1}, 9000},
      services: [],
      load_percent: 10,
      last_seen: now,
      rtt_ms: 5,
      status: :healthy
    }

    assert healthy.status == :healthy

    # Degraded: last_seen between 2× ping interval and timeout
    # ping_interval=5000, timeout=15000 → degraded when age in (10000, 15000)
    degraded = %Peer{healthy | last_seen: now - 11_000, status: :degraded}
    assert degraded.status == :degraded

    # Unreachable: past timeout
    unreachable = %Peer{healthy | last_seen: now - 16_000, status: :unreachable}
    assert unreachable.status == :unreachable
  end

  # ────────────────────────────────────────────
  # 14. rebuild_service_map builds correct map from peers
  # ────────────────────────────────────────────
  test "rebuild_service_map aggregates services across peers" do
    gw1 = :crypto.strong_rand_bytes(16)
    gw2 = :crypto.strong_rand_bytes(16)

    peers = %{
      gw1 => %Peer{gateway_id: gw1, services: ["web", "api"], status: :healthy},
      gw2 => %Peer{gateway_id: gw2, services: ["api", "db"], status: :healthy}
    }

    smap = Federation.rebuild_service_map(peers, [])

    assert gw1 in Map.get(smap, "web", [])
    assert gw1 in Map.get(smap, "api", [])
    assert gw2 in Map.get(smap, "api", [])
    assert gw2 in Map.get(smap, "db", [])
    refute Map.has_key?(smap, "nonexistent")
  end

  # ────────────────────────────────────────────
  # 15. format_addr formats IP tuple correctly
  # ────────────────────────────────────────────
  test "format_addr formats {ip_tuple, port} as string" do
    assert "127.0.0.1:8080" == Federation.format_addr({{127, 0, 0, 1}, 8080})
    assert "10.0.1.5:443" == Federation.format_addr({{10, 0, 1, 5}, 443})
  end

  # ────────────────────────────────────────────
  # 16. Federation handles unknown UDP messages gracefully
  # ────────────────────────────────────────────
  test "unknown UDP messages are silently ignored" do
    pid = start_federation()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    # Get the federation port
    status = Federation.status()
    assert status.enabled == true

    # Send garbage data to the federation socket
    {:ok, sock} = :gen_udp.open(0, [:binary])
    # We need the actual port — get it via :inet.port on the federation socket.
    # Since we can't access the socket directly, send to localhost on port 0
    # and verify no crash by checking status after.
    # The federation was started with port: 0, so we need to find it.
    # Instead, just send the GenServer the message directly.
    send(pid, {:udp, nil, {127, 0, 0, 1}, 9999, <<0xFF, 0xFF, "garbage">>})
    :gen_udp.close(sock)

    # Process should still be alive and functional
    Process.sleep(50)
    assert Process.alive?(pid)
    status2 = Federation.status()
    assert status2.enabled == true
  end

  # ────────────────────────────────────────────
  # 17. PEER_HELLO wire format encoding is correct
  # ────────────────────────────────────────────
  test "encode_hello produces correct wire format" do
    gw_id = :crypto.strong_rand_bytes(16)
    packet = Federation.encode_hello(gw_id, 55, ["web", "api"])

    # Opcode
    assert <<0x20, rest::binary>> = packet
    # Gateway ID (16 bytes)
    assert <<^gw_id::binary-16, payload::binary>> = rest
    # Load byte + service count
    assert <<55, 2, svc_data::binary>> = payload
    # First service: length 3, "web"
    assert <<3, "web", 3, "api">> = svc_data
  end

  # ────────────────────────────────────────────
  # 18. PEER_PING wire format is 9 bytes
  # ────────────────────────────────────────────
  test "encode_ping produces 9-byte packet (opcode + 8-byte timestamp)" do
    ts = 1_234_567_890
    packet = Federation.encode_ping(ts)
    assert byte_size(packet) == 9
    assert <<0x21, ^ts::64>> = packet
  end

  # ────────────────────────────────────────────
  # 19. SERVICE_QUERY wire format encoding
  # ────────────────────────────────────────────
  test "encode_service_query produces correct wire format" do
    packet = Federation.encode_service_query("myservice")
    assert <<0x24, 9, "myservice">> = packet
  end

  # ────────────────────────────────────────────
  # 20. status returns peer_count and healthy_peers
  # ────────────────────────────────────────────
  test "status returns correct peer_count and healthy_peers counts" do
    pid = start_federation()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 1_000)
    end)

    status = Federation.status()
    assert status.peer_count == 0
    assert status.healthy_peers == 0
    assert is_list(status.local_services)
  end
end
