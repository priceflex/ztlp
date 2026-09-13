defmodule ZtlpGateway.RelayRegistrarAddrTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Task Q5 (gateway side): when `ZTLP_GATEWAY_RELAY_ADVERTISE_ADDR` is set,
  `RelayRegistrar` emits GATEWAY_REGISTER_ADDR (0x0D) frames from its own
  ephemeral UDP socket — it must NOT depend on the legacy UDP `Listener`
  socket, which does not exist in a QUIC-only gateway
  (`ZTLP_GATEWAY_UDP_ENABLED=false`).
  """

  alias ZtlpGateway.RelayRegistrar

  setup do
    {:ok, relay_sock} = :gen_udp.open(0, [:binary, {:active, true}])
    {:ok, relay_port} = :inet.port(relay_sock)

    Application.put_env(:ztlp_gateway, :relay_server, {{127, 0, 0, 1}, relay_port})
    Application.put_env(:ztlp_gateway, :node_id, :crypto.strong_rand_bytes(16))
    Application.put_env(:ztlp_gateway, :service_names, ["gw-defcon"])
    Application.delete_env(:ztlp_gateway, :registration_secret)

    for v <- ~w(ZTLP_RELAY_SERVER ZTLP_RELAY_REGISTRATION_SECRET ZTLP_GATEWAY_SERVICE_NAMES ZTLP_GATEWAY_RELAY_ADVERTISE_ADDR) do
      System.delete_env(v)
    end

    on_exit(fn ->
      Application.delete_env(:ztlp_gateway, :relay_server)
      Application.delete_env(:ztlp_gateway, :node_id)
      Application.delete_env(:ztlp_gateway, :service_names)
      System.delete_env("ZTLP_GATEWAY_RELAY_ADVERTISE_ADDR")
      :gen_udp.close(relay_sock)
    end)

    %{relay_sock: relay_sock}
  end

  test "build_registration_packet_addr/5 layout and HMAC coverage" do
    node_id = :crypto.strong_rand_bytes(16)
    pkt = RelayRegistrar.build_registration_packet_addr(":23097", node_id, "gw-defcon", 60, "s3cret")

    assert <<0x5A, 0x37, 0x0D, 6, ":23097", ^node_id::binary-size(16), svc::binary-size(16), 60::32, ts::64,
             hmac::binary-size(32)>> = pkt

    assert svc == "gw-defcon" <> <<0::7*8>>
    assert abs(System.system_time(:second) - ts) < 5

    signed = <<0x0D, 6, ":23097", node_id::binary, svc::binary, 60::32, ts::64>>
    assert hmac == :crypto.mac(:hmac, :sha256, "s3cret", signed)
  end

  # The relay decodes ZTLP_RELAY_REGISTRATION_SECRET with
  # `ZtlpRelay.HmacSecrets.decode_secret/1` (64 hex chars -> 32 raw bytes,
  # `base64:` -> bytes, else raw). The gateway MUST sign with the SAME bytes
  # or a hex secret (the documented `openssl rand -hex 32` form) yields
  # `bad_hmac` on every 0x0D frame in prod mode.
  test "legacy_secret/0 decodes a 64-hex ZTLP_RELAY_REGISTRATION_SECRET like the relay" do
    hex = "03949c364265e5e2cf0eb0f90a27cf51b97e85c2564a9ece899d6daab2a70d7c"
    System.put_env("ZTLP_RELAY_REGISTRATION_SECRET", hex)
    on_exit(fn -> System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET") end)

    assert RelayRegistrar.legacy_secret() == Base.decode16!(hex, case: :lower)
    assert byte_size(RelayRegistrar.legacy_secret()) == 32

    System.put_env("ZTLP_RELAY_REGISTRATION_SECRET", "supersecretkey")
    assert RelayRegistrar.legacy_secret() == "supersecretkey"

    System.put_env("ZTLP_RELAY_REGISTRATION_SECRET", "base64:" <> Base.encode64("0123456789abcdef"))
    assert RelayRegistrar.legacy_secret() == "0123456789abcdef"

    System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")
    assert RelayRegistrar.legacy_secret() == nil
  end

  test "0x0D frame signed with a hex secret verifies against the relay-decoded bytes",
       %{relay_sock: relay_sock} do
    hex = "03949c364265e5e2cf0eb0f90a27cf51b97e85c2564a9ece899d6daab2a70d7c"
    System.put_env("ZTLP_RELAY_REGISTRATION_SECRET", hex)
    System.put_env("ZTLP_GATEWAY_RELAY_ADVERTISE_ADDR", ":23097")
    on_exit(fn -> System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET") end)

    {:ok, pid} = GenServer.start_link(RelayRegistrar, [ttl: 10], name: :test_registrar_hex_secret)
    assert_receive {:udp, ^relay_sock, {127, 0, 0, 1}, _src_port, packet}, 4_000
    GenServer.stop(pid)

    <<0x5A, 0x37, signed::binary-size(byte_size(packet) - 2 - 32), hmac::binary-size(32)>> = packet
    assert hmac == :crypto.mac(:hmac, :sha256, Base.decode16!(hex, case: :lower), signed)
    refute hmac == :crypto.mac(:hmac, :sha256, hex, signed)
  end

  test "with ZTLP_GATEWAY_RELAY_ADVERTISE_ADDR set, emits 0x0D from its own socket without a Listener",
       %{relay_sock: relay_sock} do
    System.put_env("ZTLP_GATEWAY_RELAY_ADVERTISE_ADDR", ":23097")

    {:ok, pid} = GenServer.start_link(RelayRegistrar, [ttl: 10], name: :test_registrar_addr)

    assert_receive {:udp, ^relay_sock, {127, 0, 0, 1}, src_port, packet}, 4_000
    assert <<0x5A, 0x37, 0x0D, 6, ":23097", _::binary>> = packet
    # sent from an ephemeral port, not the advertised one
    refute src_port == 23097

    GenServer.stop(pid)
  end

  test "without the env var, behaviour is unchanged (V1 0x0A via provided socket)", %{relay_sock: relay_sock} do
    {:ok, sender} = :gen_udp.open(0, [:binary, {:active, false}])
    on_exit(fn -> :gen_udp.close(sender) end)

    {:ok, pid} = GenServer.start_link(RelayRegistrar, [ttl: 10, test_socket: sender], name: :test_registrar_v1_unchanged)
    assert_receive {:udp, ^relay_sock, _, _, <<0x5A, 0x37, 0x0A, _::binary>>}, 4_000
    GenServer.stop(pid)
  end
end
