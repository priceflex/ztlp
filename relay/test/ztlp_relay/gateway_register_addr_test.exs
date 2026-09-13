defmodule ZtlpRelay.GatewayRegisterAddrTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Task Q5 (ztlp-cloud-demo-plan.md, R1 option b): GATEWAY_REGISTER_ADDR
  (type byte 0x0D). A QUIC gateway cannot send from its listening UDP port
  (msquic owns the socket; SO_REUSEPORT spike stole 300/300 inbound
  datagrams), so it registers from an ephemeral socket and DECLARES the
  address the relay should forward to.

  Wire (after `0x5A 0x37 0x0D`):

      [1 addr_len][addr_len addr][16 node_id][16 service_padded][4 ttl][8 ts][32 hmac]

  `addr` is ASCII `"ip:port"` or `":port"`. The port-only form means "my
  observed source IP, this port" — NAT-friendly and unspoofable, and is
  what the demo compose uses. Signed material = `0x0D || addr_len || addr
  || node_id || service_padded || ttl || ts`; HMAC policy identical to V1.
  """

  alias ZtlpRelay.GatewayForwarder

  setup do
    prev_mode = System.get_env("ZTLP_RELAY_HMAC_MODE")
    System.put_env("ZTLP_RELAY_HMAC_MODE", "dev")

    on_exit(fn ->
      if prev_mode, do: System.put_env("ZTLP_RELAY_HMAC_MODE", prev_mode), else: System.delete_env("ZTLP_RELAY_HMAC_MODE")
    end)

    case GenServer.whereis(GatewayForwarder) do
      nil -> {:ok, _} = GatewayForwarder.start_link()
      _ -> :ok
    end

    :ok
  end

  defp packet(addr, node_id, service, secret \\ nil) do
    service_padded = service <> String.duplicate(<<0>>, 16 - byte_size(service))
    ttl = 60
    ts = System.system_time(:second)

    signed =
      <<0x0D, byte_size(addr)::8, addr::binary, node_id::binary, service_padded::binary, ttl::32, ts::64>>

    hmac = if secret, do: :crypto.mac(:hmac, :sha256, secret, signed), else: <<0::256>>
    <<0x5A, 0x37, signed::binary, hmac::binary>>
  end

  defp send_to_relay(pkt) do
    port = ZtlpRelay.UdpListener.get_port()
    {:ok, sock} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}])
    :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, pkt)
    {:ok, src_port} = :inet.port(sock)
    :gen_udp.close(sock)
    Process.sleep(50)
    src_port
  end

  defp find(node_id) do
    GatewayForwarder.dynamic_gateways() |> Enum.find(&(&1.node_id == node_id))
  end

  test "port-only addr registers observed source IP + declared port (not the ephemeral source port)" do
    node_id = :crypto.strong_rand_bytes(16)
    src_port = send_to_relay(packet(":23097", node_id, "gw-defcon"))

    gw = find(node_id)
    assert gw != nil
    assert gw.service_name == "gw-defcon"
    assert gw.address == {{127, 0, 0, 1}, 23097}
    refute elem(gw.address, 1) == src_port
  end

  test "ip:port addr registers exactly the declared address" do
    node_id = :crypto.strong_rand_bytes(16)
    send_to_relay(packet("172.42.90.30:23097", node_id, "gw-defcon"))

    assert %{address: {{172, 42, 90, 30}, 23097}} = find(node_id)
  end

  test "declared address is inside the HMAC-signed material" do
    secret = "addr-test-secret"
    old = Application.get_env(:ztlp_relay, :registration_secret)
    Application.put_env(:ztlp_relay, :registration_secret, secret)
    System.put_env("ZTLP_RELAY_HMAC_MODE", "prod")

    on_exit(fn ->
      if old, do: Application.put_env(:ztlp_relay, :registration_secret, old), else: Application.delete_env(:ztlp_relay, :registration_secret)
    end)

    good = :crypto.strong_rand_bytes(16)
    send_to_relay(packet(":23097", good, "gw-signed", secret))
    assert %{address: {{127, 0, 0, 1}, 23097}} = find(good)

    # Tamper the address after signing: must be rejected.
    bad = :crypto.strong_rand_bytes(16)
    pkt = packet(":23097", bad, "gw-signed", secret)
    <<head::binary-size(3), 6, ":23097", rest::binary>> = pkt
    tampered = <<head::binary, 6, ":23098", rest::binary>>
    send_to_relay(tampered)
    assert find(bad) == nil
  end

  test "malformed addr (no port / bad ip / too long) is dropped without crashing the listener" do
    for addr <- ["23097", "nonsense", "300.1.1.1:23097", ":99999", ":0", String.duplicate("1", 70)] do
      node_id = :crypto.strong_rand_bytes(16)
      send_to_relay(packet(addr, node_id, "gw-bad"))
      assert find(node_id) == nil, "addr #{inspect(addr)} should not register"
    end

    assert Process.alive?(GenServer.whereis(ZtlpRelay.UdpListener))
  end

  test "0x0D is classified as a control frame, not forwarded as QUIC" do
    # Regression guard: the QUIC fast-bypass classifier must treat 0x0D as
    # relay control so it never gets echoed to a gateway as client data.
    assert ZtlpRelay.UdpListener.relay_control_frame?(<<0x5A, 0x37, 0x0D, 1, ?:, 0::8>>)
  end
end
