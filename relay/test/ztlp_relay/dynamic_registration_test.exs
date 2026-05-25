defmodule ZtlpRelay.DynamicRegistrationTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.GatewayForwarder

  setup do
    # Ensure GatewayForwarder is running (it should be started by the app now)
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

      _pid ->
        :ok
    end

    :ok
  end

  describe "register_dynamic_gateway/4" do
    test "registers a dynamic gateway" do
      node_id = :crypto.strong_rand_bytes(16)
      address = {{10, 0, 0, 5}, 23097}

      GatewayForwarder.register_dynamic_gateway(address, node_id, "beta", 60)
      Process.sleep(10)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert length(dynamic) >= 1

      gw = Enum.find(dynamic, fn gw -> gw.node_id == node_id end)
      assert gw != nil
      assert gw.address == address
      assert gw.service_name == "beta"
    end

    test "refreshes an existing registration (same node_id + service)" do
      node_id = :crypto.strong_rand_bytes(16)
      addr1 = {{10, 0, 0, 5}, 23097}
      addr2 = {{10, 0, 0, 6}, 23097}

      GatewayForwarder.register_dynamic_gateway(addr1, node_id, "beta", 60)
      Process.sleep(10)
      GatewayForwarder.register_dynamic_gateway(addr2, node_id, "beta", 60)
      Process.sleep(10)

      dynamic = GatewayForwarder.dynamic_gateways()
      matching = Enum.filter(dynamic, fn gw -> gw.node_id == node_id and gw.service_name == "beta" end)
      assert length(matching) == 1
      assert hd(matching).address == addr2
    end

    test "different services from same node are tracked separately" do
      node_id = :crypto.strong_rand_bytes(16)
      address = {{10, 0, 0, 5}, 23097}

      GatewayForwarder.register_dynamic_gateway(address, node_id, "beta", 60)
      GatewayForwarder.register_dynamic_gateway(address, node_id, "api", 60)
      Process.sleep(10)

      dynamic = GatewayForwarder.dynamic_gateways()
      matching = Enum.filter(dynamic, fn gw -> gw.node_id == node_id end)
      assert length(matching) == 2
    end
  end

  describe "pick_gateway/0 with dynamic gateways" do
    test "picks from dynamic gateways when no static gateways configured" do
      node_id = :crypto.strong_rand_bytes(16)
      address = {{10, 0, 0, 99}, 23097}

      # Register with a gateway-prefixed service name so the registration
      # passes the `pick_gateway/0` no-preference filter (added 2026-05-25
      # to exclude non-gateway service registrations like z2ls-desktop-lrc
      # from the round-robin pool — see `gateway_forwarder.ex`).
      GatewayForwarder.register_dynamic_gateway(address, node_id, "gw-test-tenant", 60)
      Process.sleep(10)

      # Dynamic gateways are included in pick_gateway — verify we get a valid result
      assert {:ok, _addr} = GatewayForwarder.pick_gateway()
    end

    test "returns error or ok (doesn't crash)" do
      # Verify the function doesn't crash — result depends on what other tests registered
      result = GatewayForwarder.pick_gateway()
      assert result == :error or match?({:ok, _}, result)
    end
  end

  describe "enabled?/0" do
    test "returns true when dynamic gateways are registered" do
      node_id = :crypto.strong_rand_bytes(16)
      address = {{10, 0, 0, 99}, 23097}

      GatewayForwarder.register_dynamic_gateway(address, node_id, "test", 60)
      Process.sleep(10)

      assert GatewayForwarder.enabled?()
    end
  end

  describe "UDP registration packet handling" do
    test "relay accepts well-formed registration packet (no secret)" do
      # Get the relay's UDP port
      port = ZtlpRelay.UdpListener.get_port()

      # Build a registration packet (dev mode — no HMAC)
      node_id = :crypto.strong_rand_bytes(16)
      service = "integration"
      service_padded = service <> String.duplicate(<<0>>, 16 - byte_size(service))
      ttl = 60
      timestamp = System.system_time(:second)

      hmac = <<0::256>>

      packet =
        <<0x5A, 0x37, 0x0A, node_id::binary, service_padded::binary, ttl::32, timestamp::64,
          hmac::binary>>

      # Send via UDP
      {:ok, sock} = :gen_udp.open(0, [:binary])
      :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
      :gen_udp.close(sock)

      # Wait for processing
      Process.sleep(50)

      # Verify the gateway was registered
      dynamic = GatewayForwarder.dynamic_gateways()
      matching = Enum.find(dynamic, fn gw -> gw.node_id == node_id end)
      assert matching != nil
      assert matching.service_name == "integration"
    end

    test "relay accepts registration packet with valid HMAC" do
      secret = "test-secret-key"
      # Set the secret in app config for this test
      old_secret = Application.get_env(:ztlp_relay, :registration_secret)
      Application.put_env(:ztlp_relay, :registration_secret, secret)

      on_exit(fn ->
        if old_secret do
          Application.put_env(:ztlp_relay, :registration_secret, old_secret)
        else
          Application.delete_env(:ztlp_relay, :registration_secret)
        end
      end)

      port = ZtlpRelay.UdpListener.get_port()
      node_id = :crypto.strong_rand_bytes(16)
      service = "hmactest"
      service_padded = service <> String.duplicate(<<0>>, 16 - byte_size(service))
      ttl = 60
      timestamp = System.system_time(:second)

      signed_data = <<0x0A, node_id::binary, service_padded::binary, ttl::32, timestamp::64>>
      hmac = :crypto.mac(:hmac, :sha256, secret, signed_data)

      packet =
        <<0x5A, 0x37, 0x0A, node_id::binary, service_padded::binary, ttl::32, timestamp::64,
          hmac::binary>>

      {:ok, sock} = :gen_udp.open(0, [:binary])
      :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
      :gen_udp.close(sock)

      Process.sleep(50)

      dynamic = GatewayForwarder.dynamic_gateways()
      matching = Enum.find(dynamic, fn gw -> gw.node_id == node_id end)
      assert matching != nil
      assert matching.service_name == "hmactest"
    end

    test "relay rejects registration packet with invalid HMAC" do
      secret = "test-secret-key-reject"
      Application.put_env(:ztlp_relay, :registration_secret, secret)

      on_exit(fn ->
        Application.delete_env(:ztlp_relay, :registration_secret)
      end)

      port = ZtlpRelay.UdpListener.get_port()
      node_id = :crypto.strong_rand_bytes(16)
      service = "badhmac"
      service_padded = service <> String.duplicate(<<0>>, 16 - byte_size(service))
      ttl = 60
      timestamp = System.system_time(:second)

      # Use wrong secret for HMAC
      bad_hmac = :crypto.mac(:hmac, :sha256, "wrong-secret", <<0x0A>>)

      packet =
        <<0x5A, 0x37, 0x0A, node_id::binary, service_padded::binary, ttl::32, timestamp::64,
          bad_hmac::binary>>

      {:ok, sock} = :gen_udp.open(0, [:binary])
      :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
      :gen_udp.close(sock)

      Process.sleep(50)

      dynamic = GatewayForwarder.dynamic_gateways()
      matching = Enum.find(dynamic, fn gw -> gw.node_id == node_id end)
      assert matching == nil
    end
  end

  describe "UDP registration packet handling with per-zone HMAC (Task #2)" do
    # These tests exercise the integration between
    # `ZtlpRelay.UdpListener.handle_gateway_register/2` and
    # `ZtlpRelay.HmacSecrets`. They prove that:
    #
    #  - a frame signed with the zone-specific key for service `gw-acme`
    #    is accepted in `prod` mode without any legacy secret configured,
    #  - a frame signed with the WRONG zone's key is rejected (no
    #    cross-tenant hijack),
    #  - `prod` mode rejects unsigned/no-secret registrations.
    #
    # The unit tests in `hmac_secrets_test.exs` cover the policy
    # decisions in isolation; these tests cover the wire path.

    setup do
      # Save & restore the env vars these tests touch.
      saved = %{
        mode: System.get_env("ZTLP_RELAY_HMAC_MODE"),
        zone_acme: System.get_env("ZTLP_HMAC_SECRET_ACME"),
        zone_evil: System.get_env("ZTLP_HMAC_SECRET_EVIL"),
        legacy: System.get_env("ZTLP_RELAY_REGISTRATION_SECRET")
      }

      on_exit(fn ->
        for {name, val} <- [
              {"ZTLP_RELAY_HMAC_MODE", saved.mode},
              {"ZTLP_HMAC_SECRET_ACME", saved.zone_acme},
              {"ZTLP_HMAC_SECRET_EVIL", saved.zone_evil},
              {"ZTLP_RELAY_REGISTRATION_SECRET", saved.legacy}
            ] do
          case val do
            nil -> System.delete_env(name)
            v -> System.put_env(name, v)
          end
        end
      end)

      :ok
    end

    defp send_registration(service, secret) do
      port = ZtlpRelay.UdpListener.get_port()
      node_id = :crypto.strong_rand_bytes(16)
      service_padded = service <> String.duplicate(<<0>>, 16 - byte_size(service))
      ttl = 60
      timestamp = System.system_time(:second)

      signed = <<0x0A, node_id::binary, service_padded::binary, ttl::32, timestamp::64>>
      hmac = :crypto.mac(:hmac, :sha256, secret, signed)

      packet =
        <<0x5A, 0x37, 0x0A, node_id::binary, service_padded::binary, ttl::32, timestamp::64,
          hmac::binary>>

      {:ok, sock} = :gen_udp.open(0, [:binary])
      :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
      :gen_udp.close(sock)
      Process.sleep(50)
      node_id
    end

    test "prod mode + matching per-zone secret accepts" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      acme_secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME", Base.encode16(acme_secret))
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      node_id = send_registration("gw-acme", acme_secret)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) != nil
    end

    test "prod mode + secret for zone A signing for zone B REJECTS (cross-tenant hijack)" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      acme_secret = :crypto.strong_rand_bytes(32)
      evil_secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME", Base.encode16(acme_secret))
      System.put_env("ZTLP_HMAC_SECRET_EVIL", Base.encode16(evil_secret))
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      # Sign with EVIL's secret but claim to be `gw-acme` — must reject.
      node_id = send_registration("gw-acme", evil_secret)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) == nil
    end

    test "prod mode + no secret configured REJECTS" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      System.delete_env("ZTLP_HMAC_SECRET_ACME")
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      # Any HMAC (here zero) — prod with no secret rejects unconditionally.
      port = ZtlpRelay.UdpListener.get_port()
      node_id = :crypto.strong_rand_bytes(16)
      service = "gw-acme"
      service_padded = service <> String.duplicate(<<0>>, 16 - byte_size(service))
      ttl = 60
      timestamp = System.system_time(:second)
      zero_hmac = <<0::256>>

      packet =
        <<0x5A, 0x37, 0x0A, node_id::binary, service_padded::binary, ttl::32, timestamp::64,
          zero_hmac::binary>>

      {:ok, sock} = :gen_udp.open(0, [:binary])
      :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
      :gen_udp.close(sock)
      Process.sleep(50)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) == nil
    end

    test "rotation: signing with a grace key is accepted" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      primary = :crypto.strong_rand_bytes(32)
      grace = :crypto.strong_rand_bytes(32)

      # Primary first, grace second — both verify, primary is the
      # current signing key for the relay (we don't sign in this test).
      System.put_env(
        "ZTLP_HMAC_SECRET_ACME",
        Base.encode16(primary) <> "," <> Base.encode16(grace)
      )

      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      # Gateway is still signing with the grace key (mid-rotation).
      node_id = send_registration("gw-acme", grace)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) != nil
    end
  end
end
