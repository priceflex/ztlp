defmodule ZtlpGateway.RelayRegistrarTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.RelayRegistrar

  describe "build_registration_packet/4" do
    test "builds correct packet structure (no secret)" do
      node_id = :crypto.strong_rand_bytes(16)
      packet = RelayRegistrar.build_registration_packet(node_id, "beta", 60, nil)

      # Total: 3 (magic+type) + 16 (node_id) + 16 (service) + 4 (ttl) + 8 (timestamp) + 32 (hmac) = 79
      assert byte_size(packet) == 79

      # Check magic bytes and type
      assert <<0x5A, 0x37, 0x0A, rest::binary>> = packet

      # Extract fields
      <<^node_id::binary-size(16), service_raw::binary-size(16), 60::32, _ts::64,
        hmac::binary-size(32)>> = rest

      # Service name should be "beta" zero-padded
      assert service_raw == <<"beta", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>

      # HMAC should be zeros (dev mode)
      assert hmac == <<0::256>>
    end

    test "builds correct packet with HMAC when secret is provided" do
      node_id = :crypto.strong_rand_bytes(16)
      secret = "my-shared-secret"
      packet = RelayRegistrar.build_registration_packet(node_id, "api", 120, secret)

      assert byte_size(packet) == 79
      assert <<0x5A, 0x37, 0x0A, _rest::binary>> = packet

      # Extract fields
      <<0x5A, 0x37, 0x0A, ^node_id::binary-size(16), service_raw::binary-size(16), 120::32,
        timestamp::64, hmac::binary-size(32)>> = packet

      # HMAC should NOT be zeros
      refute hmac == <<0::256>>

      # Verify HMAC is correct
      signed_data = <<0x0A, node_id::binary, service_raw::binary, 120::32, timestamp::64>>
      expected_hmac = :crypto.mac(:hmac, :sha256, secret, signed_data)
      assert hmac == expected_hmac
    end

    test "truncates long service names to 16 bytes" do
      node_id = :crypto.strong_rand_bytes(16)
      long_name = "this-is-a-very-long-service-name"
      packet = RelayRegistrar.build_registration_packet(node_id, long_name, 60, nil)

      <<0x5A, 0x37, 0x0A, _node::binary-size(16), service_raw::binary-size(16), _rest::binary>> =
        packet

      assert service_raw == binary_part(long_name, 0, 16)
    end

    test "timestamp is recent" do
      node_id = :crypto.strong_rand_bytes(16)
      before = System.system_time(:second)
      packet = RelayRegistrar.build_registration_packet(node_id, "ts", 60, nil)
      after_ts = System.system_time(:second)

      <<0x5A, 0x37, 0x0A, _node::binary-size(16), _svc::binary-size(16), _ttl::32, ts::64,
        _hmac::binary-size(32)>> = packet

      assert ts >= before
      assert ts <= after_ts
    end
  end

  describe "GenServer lifecycle" do
    test "starts with no relay configured" do
      # Clear relay config
      old = Application.get_env(:ztlp_gateway, :relay_server)
      Application.delete_env(:ztlp_gateway, :relay_server)
      old_env = System.get_env("ZTLP_RELAY_SERVER")
      System.delete_env("ZTLP_RELAY_SERVER")

      on_exit(fn ->
        if old, do: Application.put_env(:ztlp_gateway, :relay_server, old)
        if old_env, do: System.put_env("ZTLP_RELAY_SERVER", old_env)
      end)

      {:ok, pid} = GenServer.start_link(RelayRegistrar, [], name: :test_registrar_no_relay)
      state = GenServer.call(pid, :state)
      assert state.relay == nil
      GenServer.stop(pid)
    end

    test "starts and sends registration when relay is configured" do
      # Open a UDP socket to act as the relay
      {:ok, relay_sock} = :gen_udp.open(0, [:binary, {:active, true}])
      {:ok, relay_port} = :inet.port(relay_sock)

      # Configure the gateway to point at our fake relay
      Application.put_env(:ztlp_gateway, :relay_server, {{127, 0, 0, 1}, relay_port})
      Application.put_env(:ztlp_gateway, :node_id, :crypto.strong_rand_bytes(16))
      Application.put_env(:ztlp_gateway, :service_names, ["test-svc"])
      Application.delete_env(:ztlp_gateway, :registration_secret)
      System.delete_env("ZTLP_RELAY_SERVER")
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")
      System.delete_env("ZTLP_GATEWAY_SERVICE_NAMES")

      on_exit(fn ->
        Application.delete_env(:ztlp_gateway, :relay_server)
        Application.delete_env(:ztlp_gateway, :node_id)
        Application.delete_env(:ztlp_gateway, :service_names)
        :gen_udp.close(relay_sock)
      end)

      {:ok, pid} = GenServer.start_link(RelayRegistrar, [ttl: 10], name: :test_registrar_with_relay)

      # Wait for the registration packet
      assert_receive {:udp, ^relay_sock, _ip, _port, packet}, 2000

      # Verify packet structure
      assert <<0x5A, 0x37, 0x0A, _rest::binary-size(76)>> = packet
      assert byte_size(packet) == 79

      GenServer.stop(pid)
    end

    test "re-registers at TTL/2 interval" do
      {:ok, relay_sock} = :gen_udp.open(0, [:binary, {:active, true}])
      {:ok, relay_port} = :inet.port(relay_sock)

      Application.put_env(:ztlp_gateway, :relay_server, {{127, 0, 0, 1}, relay_port})
      Application.put_env(:ztlp_gateway, :node_id, :crypto.strong_rand_bytes(16))
      Application.put_env(:ztlp_gateway, :service_names, ["resvc"])
      Application.delete_env(:ztlp_gateway, :registration_secret)
      System.delete_env("ZTLP_RELAY_SERVER")
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")
      System.delete_env("ZTLP_GATEWAY_SERVICE_NAMES")

      on_exit(fn ->
        Application.delete_env(:ztlp_gateway, :relay_server)
        Application.delete_env(:ztlp_gateway, :node_id)
        Application.delete_env(:ztlp_gateway, :service_names)
        :gen_udp.close(relay_sock)
      end)

      # TTL of 2 seconds → re-register every 1 second
      {:ok, pid} = GenServer.start_link(RelayRegistrar, [ttl: 2], name: :test_registrar_reregister)

      # First registration
      assert_receive {:udp, ^relay_sock, _ip, _port, _packet1}, 2000

      # Second registration (after TTL/2 = 1 second)
      assert_receive {:udp, ^relay_sock, _ip, _port, _packet2}, 2000

      GenServer.stop(pid)
    end
  end
end
