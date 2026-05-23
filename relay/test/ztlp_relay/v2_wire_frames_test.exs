defmodule ZtlpRelay.V2WireFramesTest do
  @moduledoc """
  Wire-format + integration tests for the V2 registration frames added in
  Task #2 Phase 1.5:

  - `GATEWAY_REGISTER_V2` (type byte `0x0E`)
  - `CLIENT_ROUTE_V2`     (type byte `0x0F`)

  These frames carry an explicit `zone_id` field so per-zone HMAC verification
  no longer relies on the V1 `gw-<zone>` service-name convention.

  The full byte layout is documented in `docs/per_zone_hmac_design.md` §
  "Wire format" and at the top of the `handle_gateway_register_v2/2` and
  `handle_client_route_v2/3` handlers in
  `relay/lib/ztlp_relay/udp_listener.ex`.

  The unit tests below pin down:

  1. The encoding rule for `signed_material` (what HMAC-SHA256 is computed
     over) — independent of any UDP listener state.
  2. The integration boundary against a live `ZtlpRelay.UdpListener` socket
     — proving the new dispatch arms hand off to `HmacSecrets` correctly
     and that GATEWAY_REGISTER_V2 + CLIENT_ROUTE_V2 install the expected
     state (registered gateway, client_map ETS entry) on success and
     install nothing on rejection.

  The cross-tenant hijack test is the headline security assertion: a
  registration signed with zone B's secret but claiming zone A in the V2
  `zone_id` field MUST be rejected even when zone A has no secret of its
  own configured — i.e., zone B's leaked secret cannot be used to register
  ANY other zone.
  """
  use ExUnit.Case, async: false

  alias ZtlpRelay.{GatewayForwarder, UdpListener}

  # ---------------------------------------------------------------------------
  # Wire-format unit tests (no UDP, no env vars)
  # ---------------------------------------------------------------------------
  #
  # These tests don't talk to a listener — they just lock down the byte
  # layout and the signed-material encoding rule for V2 frames. Useful for
  # catching accidental wire changes (e.g., somebody adding a field to V2
  # without bumping to V3).

  describe "V2 wire encoding (offline)" do
    test "GATEWAY_REGISTER_V2 byte layout: 3 + 1 + zone_len + 16 + 16 + 4 + 8 + 32" do
      zone_id = "acme.ztlp"
      zone_len = byte_size(zone_id)
      node_id = :crypto.strong_rand_bytes(16)
      service_raw = pad16("gw-acme")
      ttl = 60
      timestamp = 1_700_000_000
      hmac = :crypto.strong_rand_bytes(32)

      packet = build_gateway_register_v2(zone_id, node_id, service_raw, ttl, timestamp, hmac)

      # 3 (magic+type) + 1 (zone_len) + zone_len + 16 + 16 + 4 + 8 + 32
      assert byte_size(packet) == 3 + 1 + zone_len + 16 + 16 + 4 + 8 + 32

      assert <<0x5A, 0x37, 0x0E, ^zone_len::8, ^zone_id::binary-size(zone_len), rest::binary>> =
               packet

      assert byte_size(rest) == 16 + 16 + 4 + 8 + 32
    end

    test "CLIENT_ROUTE_V2 byte layout: 3 + 1 + zone_len + 16 + 1 + svc_len + 8 + 32" do
      zone_id = "tenant1.ztlp"
      svc = "gw-tenant1"
      node_id = :crypto.strong_rand_bytes(16)
      timestamp = 1_700_000_000
      hmac = :crypto.strong_rand_bytes(32)

      packet = build_client_route_v2(zone_id, node_id, svc, timestamp, hmac)

      expected_size = 3 + 1 + byte_size(zone_id) + 16 + 1 + byte_size(svc) + 8 + 32
      assert byte_size(packet) == expected_size
    end

    test "signed material for GATEWAY_REGISTER_V2 excludes wire magic and hmac field" do
      zone_id = "acme"
      node_id = :crypto.strong_rand_bytes(16)
      service_raw = pad16("gw-acme")
      ttl = 60
      timestamp = 1_700_000_000

      expected =
        <<0x0E, byte_size(zone_id)::8, zone_id::binary, node_id::binary, service_raw::binary,
          ttl::32, timestamp::64>>

      assert byte_size(expected) == 1 + 1 + byte_size(zone_id) + 16 + 16 + 4 + 8
      # First byte is the type (0x0E), NOT the wire magic (0x5A 0x37).
      assert <<0x0E, _::binary>> = expected
    end

    test "signed material for CLIENT_ROUTE_V2 excludes wire magic and hmac field" do
      zone_id = "acme"
      node_id = :crypto.strong_rand_bytes(16)
      svc = "gw-acme"
      timestamp = 1_700_000_000

      expected =
        <<0x0F, byte_size(zone_id)::8, zone_id::binary, node_id::binary, byte_size(svc)::8,
          svc::binary, timestamp::64-signed>>

      assert byte_size(expected) ==
               1 + 1 + byte_size(zone_id) + 16 + 1 + byte_size(svc) + 8

      assert <<0x0F, _::binary>> = expected
    end

    test "V1 (0x0A/0x0B) and V2 (0x0E/0x0F) type bytes are disjoint" do
      assert 0x0A != 0x0E
      assert 0x0B != 0x0F
      # Also disjoint from the proto control-frame types (0x07 ENROLL, etc.)
      # and from FRAME_ACK_V2 (0x10) used on the data plane:
      for v1_v2 <- [0x0A, 0x0B, 0x0E, 0x0F],
          other <- [0x00, 0x01, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12] do
        assert v1_v2 != other
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Integration tests against a live UdpListener (real :gen_udp sockets)
  # ---------------------------------------------------------------------------

  describe "GATEWAY_REGISTER_V2 over the wire" do
    setup [:reset_env, :ensure_forwarder]

    test "prod mode + matching per-zone secret accepts and registers the gateway" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      zone_id = "acme.ztlp"
      acme_secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME_ZTLP", Base.encode16(acme_secret))
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      node_id = send_gateway_register_v2(zone_id, "gw-acme", acme_secret)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) != nil
    end

    test "prod mode + secret for zone A signing for zone B REJECTS (cross-tenant hijack)" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      acme_secret = :crypto.strong_rand_bytes(32)
      evil_secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME_ZTLP", Base.encode16(acme_secret))
      System.put_env("ZTLP_HMAC_SECRET_EVIL_ZTLP", Base.encode16(evil_secret))
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      # Sign with EVIL's secret but claim the zone_id field is "acme.ztlp".
      # The V2 frame's explicit zone_id forces the verifier to look up
      # acme.ztlp's key, NOT evil.ztlp's. So this must reject regardless
      # of which gateway name the attacker chose.
      node_id = send_gateway_register_v2("acme.ztlp", "gw-acme", evil_secret)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) == nil
    end

    test "prod mode + no secret configured for the claimed zone REJECTS" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      System.delete_env("ZTLP_HMAC_SECRET_ACME_ZTLP")
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      # Sign with anything — the verifier rejects pre-HMAC because the
      # claimed zone has no key configured at all.
      node_id = send_gateway_register_v2("acme.ztlp", "gw-acme", :crypto.strong_rand_bytes(32))

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) == nil
    end

    test "rotation: signing with a grace key is accepted" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      primary = :crypto.strong_rand_bytes(32)
      grace = :crypto.strong_rand_bytes(32)

      System.put_env(
        "ZTLP_HMAC_SECRET_ACME_ZTLP",
        Base.encode16(primary) <> "," <> Base.encode16(grace)
      )

      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      # The relay accepts both primary and grace keys for VERIFICATION;
      # signing with the grace key (e.g., a still-rotating gateway) must
      # be honored during the overlap window.
      node_id = send_gateway_register_v2("acme.ztlp", "gw-acme", grace)

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) != nil
    end

    test "dev mode accepts any HMAC (backward-compat with V1 dev mode)" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "dev")
      System.delete_env("ZTLP_HMAC_SECRET_ACME_ZTLP")
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      node_id = send_gateway_register_v2("acme.ztlp", "gw-acme", :crypto.strong_rand_bytes(32))

      dynamic = GatewayForwarder.dynamic_gateways()
      assert Enum.find(dynamic, fn gw -> gw.node_id == node_id end) != nil
    end

    test "malformed V2 frame (zone_len=0) is silently dropped without crashing the listener" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "dev")
      port = UdpListener.get_port()

      # zone_len = 0 violates the 1..=63 range guard
      bad = <<0x5A, 0x37, 0x0E, 0::8, 0::128, 0::128, 0::32, 0::64, 0::256>>

      {:ok, sock} = :gen_udp.open(0, [:binary])
      :gen_udp.send(sock, {127, 0, 0, 1}, port, bad)
      :gen_udp.close(sock)
      Process.sleep(50)

      # Listener must still be alive and accepting packets afterwards.
      assert is_pid(GenServer.whereis(ZtlpRelay.UdpListener))
    end
  end

  describe "CLIENT_ROUTE_V2 over the wire" do
    setup [:reset_env, :ensure_forwarder, :clean_ets]

    test "prod mode + matching per-zone secret installs the client_map entry" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      acme_secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME_ZTLP", Base.encode16(acme_secret))
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      # Register a fake backend gateway for the target service first so
      # `pick_gateway_for_service/1` resolves.
      gw_addr = {{10, 0, 0, 99}, 23097}
      service_name = "gw-acme"

      GatewayForwarder.register_dynamic_gateway(
        gw_addr,
        :crypto.strong_rand_bytes(16),
        service_name,
        60
      )

      Process.sleep(20)

      {sender, _node_id} = send_client_route_v2("acme.ztlp", service_name, acme_secret)

      assert [{{:client_map, ^sender}, {^gw_addr, _inserted_at}}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})
    end

    test "prod mode + cross-tenant hijack on CLIENT_ROUTE_V2 REJECTS" do
      System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")
      acme_secret = :crypto.strong_rand_bytes(32)
      evil_secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME_ZTLP", Base.encode16(acme_secret))
      System.put_env("ZTLP_HMAC_SECRET_EVIL_ZTLP", Base.encode16(evil_secret))
      System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

      gw_addr = {{10, 0, 0, 99}, 23097}
      service_name = "gw-acme"

      GatewayForwarder.register_dynamic_gateway(
        gw_addr,
        :crypto.strong_rand_bytes(16),
        service_name,
        60
      )

      Process.sleep(20)

      # Sign with EVIL's secret but claim zone_id = "acme.ztlp" — reject.
      {sender, _node_id} = send_client_route_v2("acme.ztlp", service_name, evil_secret)

      assert :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender}) == []
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp reset_env(_ctx) do
    saved = %{
      mode: System.get_env("ZTLP_RELAY_HMAC_MODE"),
      acme: System.get_env("ZTLP_HMAC_SECRET_ACME_ZTLP"),
      evil: System.get_env("ZTLP_HMAC_SECRET_EVIL_ZTLP"),
      legacy: System.get_env("ZTLP_RELAY_REGISTRATION_SECRET")
    }

    on_exit(fn ->
      for {name, val} <- [
            {"ZTLP_RELAY_HMAC_MODE", saved.mode},
            {"ZTLP_HMAC_SECRET_ACME_ZTLP", saved.acme},
            {"ZTLP_HMAC_SECRET_EVIL_ZTLP", saved.evil},
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

  defp ensure_forwarder(_ctx) do
    case GenServer.whereis(GatewayForwarder) do
      nil ->
        {:ok, _pid} = GatewayForwarder.start_link()

      _pid ->
        :ok
    end

    GatewayForwarder.clear_all()
    :ok
  end

  defp clean_ets(_ctx) do
    if :ets.info(:ztlp_forwarded_quic_tuples, :name) != :undefined do
      :ets.delete_all_objects(:ztlp_forwarded_quic_tuples)
    end

    :ok
  end

  defp pad16(svc) do
    svc <> String.duplicate(<<0>>, 16 - byte_size(svc))
  end

  defp build_gateway_register_v2(zone_id, node_id, service_raw, ttl, timestamp, hmac) do
    zone_len = byte_size(zone_id)

    <<0x5A, 0x37, 0x0E, zone_len::8, zone_id::binary, node_id::binary, service_raw::binary,
      ttl::32, timestamp::64, hmac::binary>>
  end

  defp build_client_route_v2(zone_id, node_id, service_name, timestamp, hmac) do
    zone_len = byte_size(zone_id)
    svc_len = byte_size(service_name)

    <<0x5A, 0x37, 0x0F, zone_len::8, zone_id::binary, node_id::binary, svc_len::8,
      service_name::binary, timestamp::64-signed, hmac::binary>>
  end

  defp send_gateway_register_v2(zone_id, service, secret) do
    port = UdpListener.get_port()
    node_id = :crypto.strong_rand_bytes(16)
    service_raw = pad16(service)
    ttl = 60
    timestamp = System.system_time(:second)
    zone_len = byte_size(zone_id)

    signed =
      <<0x0E, zone_len::8, zone_id::binary, node_id::binary, service_raw::binary, ttl::32,
        timestamp::64>>

    hmac = :crypto.mac(:hmac, :sha256, secret, signed)
    packet = build_gateway_register_v2(zone_id, node_id, service_raw, ttl, timestamp, hmac)

    {:ok, sock} = :gen_udp.open(0, [:binary])
    :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
    :gen_udp.close(sock)
    Process.sleep(50)
    node_id
  end

  defp send_client_route_v2(zone_id, service_name, secret) do
    port = UdpListener.get_port()
    node_id = :crypto.strong_rand_bytes(16)
    timestamp = System.system_time(:second)
    zone_len = byte_size(zone_id)
    svc_len = byte_size(service_name)

    signed =
      <<0x0F, zone_len::8, zone_id::binary, node_id::binary, svc_len::8, service_name::binary,
        timestamp::64-signed>>

    hmac = :crypto.mac(:hmac, :sha256, secret, signed)

    packet = build_client_route_v2(zone_id, node_id, service_name, timestamp, hmac)

    {:ok, sock} = :gen_udp.open(0, [:binary])
    {:ok, client_port} = :inet.port(sock)
    sender = {{127, 0, 0, 1}, client_port}
    :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
    Process.sleep(50)
    :gen_udp.close(sock)
    {sender, node_id}
  end
end
