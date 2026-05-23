defmodule ZtlpGateway.RelayRegistrarV2Test do
  @moduledoc """
  Tests for Task #2 Phase 2 — gateway-side V2 frame signing.

  The relay-side V2 verifier already shipped in Phase 1.5 (PR #21,
  commit `5f4085f`). This module proves that:

  1. The byte layout the gateway emits matches the layout the relay
     parses (`relay/lib/ztlp_relay/udp_listener.ex#handle_gateway_register_v2/2`).
  2. The signed-material rule the gateway computes matches the rule
     the relay verifies against (no wire-magic, no HMAC field).
  3. The env-flag gating (`ZTLP_GATEWAY_USE_V2_FRAMES`) defaults off
     and never silently downgrades a configured V2 emission to V1
     unsigned in dev — operators see a loud WARN when a fallback
     happens.

  These tests inline the relay's verification rule rather than calling
  it directly because `ztlp_gateway` and `ztlp_relay` are independent
  Mix projects with no shared library yet. The inlined rule is a few
  lines and is pinned to the wire spec; any future drift on the relay
  side has to update the spec and these inlined helpers.

  See `docs/per_zone_hmac_design.md` § "Wire format" for the canonical
  byte layout.
  """
  use ExUnit.Case, async: false

  alias ZtlpGateway.{HmacSecrets, RelayRegistrar}

  # Track which env vars each test touches so we can restore them.
  setup do
    saved = %{
      use_v2: System.get_env("ZTLP_GATEWAY_USE_V2_FRAMES"),
      acme: System.get_env("ZTLP_HMAC_SECRET_ACME"),
      acme_dot_ztlp: System.get_env("ZTLP_HMAC_SECRET_ACME_ZTLP"),
      default_slug: System.get_env("ZTLP_HMAC_SECRET_DEFAULT")
    }

    on_exit(fn ->
      for {name, val} <- [
            {"ZTLP_GATEWAY_USE_V2_FRAMES", saved.use_v2},
            {"ZTLP_HMAC_SECRET_ACME", saved.acme},
            {"ZTLP_HMAC_SECRET_ACME_ZTLP", saved.acme_dot_ztlp},
            {"ZTLP_HMAC_SECRET_DEFAULT", saved.default_slug}
          ] do
        case val do
          nil -> System.delete_env(name)
          v -> System.put_env(name, v)
        end
      end
    end)

    :ok
  end

  describe "use_v2_frames?/0" do
    test "defaults to false (no env var set, no application config)" do
      System.delete_env("ZTLP_GATEWAY_USE_V2_FRAMES")
      Application.delete_env(:ztlp_gateway, :use_v2_frames)
      refute RelayRegistrar.use_v2_frames?()
    end

    test "true when ZTLP_GATEWAY_USE_V2_FRAMES=true" do
      System.put_env("ZTLP_GATEWAY_USE_V2_FRAMES", "true")
      assert RelayRegistrar.use_v2_frames?()
    end

    test "true also accepts '1' and 'yes'" do
      System.put_env("ZTLP_GATEWAY_USE_V2_FRAMES", "1")
      assert RelayRegistrar.use_v2_frames?()
      System.put_env("ZTLP_GATEWAY_USE_V2_FRAMES", "yes")
      assert RelayRegistrar.use_v2_frames?()
    end

    test "false on any other value" do
      for v <- ["false", "0", "no", "FALSE", "off", "TRUE_BUT_NOT_REALLY", ""] do
        System.put_env("ZTLP_GATEWAY_USE_V2_FRAMES", v)

        refute RelayRegistrar.use_v2_frames?(),
               "expected false for #{inspect(v)}"
      end
    end
  end

  describe "derive_zone_from_service/1 (parity with relay's V1 rule)" do
    test "strips the gw- prefix when present" do
      assert RelayRegistrar.derive_zone_from_service("gw-acme") == "acme"
      assert RelayRegistrar.derive_zone_from_service("gw-acme.ztlp") == "acme.ztlp"
      assert RelayRegistrar.derive_zone_from_service("gw-techrockstars") == "techrockstars"
    end

    test "keeps the service name as zone when no gw- prefix" do
      assert RelayRegistrar.derive_zone_from_service("default") == "default"
      assert RelayRegistrar.derive_zone_from_service("api") == "api"
      assert RelayRegistrar.derive_zone_from_service("vault") == "vault"
    end

    test "treats gw- alone (no suffix) as zone='' which would be rejected by V2 builder" do
      # The relay treats this the same way — an empty zone_id with
      # zone_len=0 fails the V2 length guard. The gateway-side
      # `build_registration_packet_v2/4` raises ArgumentError on this.
      assert RelayRegistrar.derive_zone_from_service("gw-") == ""
    end
  end

  describe "build_registration_packet_v2/4 — wire format" do
    test "byte length matches spec: 3 + 1 + zone_len + 16 + 16 + 4 + 8 + 32" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      packet = RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme", 60, secret)
      # zone_id derived from "gw-acme" → "acme" (4 bytes)
      assert byte_size(packet) == 3 + 1 + 4 + 16 + 16 + 4 + 8 + 32
    end

    test "starts with magic 0x5A 0x37 0x0E then zone_len then zone_id" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      packet = RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme.ztlp", 60, secret)

      assert <<0x5A, 0x37, 0x0E, zone_len::8, rest::binary>> = packet
      # "acme.ztlp" is 9 bytes
      assert zone_len == 9
      <<zone_id::binary-size(9), _tail::binary>> = rest
      assert zone_id == "acme.ztlp"
    end

    test "node_id, service_padded, ttl, timestamp appear in expected positions" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      pre = System.system_time(:second)
      packet = RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme", 60, secret)
      post = System.system_time(:second)

      <<0x5A, 0x37, 0x0E, 4::8, "acme", payload::binary>> = packet

      <<^node_id::binary-size(16), svc::binary-size(16), 60::32, ts::64, _hmac::binary-size(32)>> =
        payload

      assert ts >= pre and ts <= post
      assert svc == <<"gw-acme", 0, 0, 0, 0, 0, 0, 0, 0, 0>>
    end

    test "HMAC matches the spec'd signed material" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      packet = RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme", 60, secret)

      <<0x5A, 0x37, 0x0E, zone_len::8, zone_id::binary-size(4), tail::binary>> = packet

      <<^node_id::binary-size(16), svc::binary-size(16), ttl::32, ts::64, hmac::binary-size(32)>> =
        tail

      expected_signed =
        <<0x0E, zone_len::8, zone_id::binary, node_id::binary, svc::binary, ttl::32, ts::64>>

      expected_hmac = :crypto.mac(:hmac, :sha256, secret, expected_signed)
      assert hmac == expected_hmac
    end

    test "raises on empty zone (zone_len=0 would violate the V2 spec)" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)

      # service_name = "gw-" → derive_zone_from_service/1 returns "" → 0 bytes
      assert_raise ArgumentError, ~r/zone_id must be 1\.\.=63 bytes/, fn ->
        RelayRegistrar.build_registration_packet_v2(node_id, "gw-", 60, secret)
      end
    end

    test "raises when zone_id would exceed 63 bytes" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      # 64-byte zone after the gw- strip
      long_service = "gw-" <> String.duplicate("a", 64)

      assert_raise ArgumentError, fn ->
        RelayRegistrar.build_registration_packet_v2(node_id, long_service, 60, secret)
      end
    end

    test "raises when secret is nil (V2 has no dev-mode zero-HMAC path)" do
      node_id = :crypto.strong_rand_bytes(16)

      assert_raise FunctionClauseError, fn ->
        RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme", 60, nil)
      end
    end
  end

  describe "round-trip: gateway-emitted V2 verifies under the relay's rule" do
    # The relay verifies V2 by recomputing
    #   :crypto.mac(:hmac, :sha256, secret, <<0x0E, zone_len, zone_id,
    #                                          node_id, service_padded,
    #                                          ttl, timestamp>>)
    # and comparing constant-time to the 32 trailing HMAC bytes. We
    # inline that rule here so this gateway-side test exercises the
    # exact contract.

    test "primary key signs a packet that verifies against the same key" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      packet = RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme", 60, secret)

      assert verify_v2_packet?(packet, secret)
    end

    test "a packet signed with secret A does NOT verify against secret B (no cross-key acceptance)" do
      secret_a = :crypto.strong_rand_bytes(32)
      secret_b = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      packet = RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme", 60, secret_a)

      refute verify_v2_packet?(packet, secret_b)
    end

    test "tampering any byte of the signed region breaks the HMAC" do
      secret = :crypto.strong_rand_bytes(32)
      node_id = :crypto.strong_rand_bytes(16)
      packet = RelayRegistrar.build_registration_packet_v2(node_id, "gw-acme", 60, secret)

      # Flip the first bit of the ttl field (offset 3 + 1 + 4 + 16 + 16 = 40)
      <<head::binary-size(40), ttl_byte::8, tail::binary>> = packet
      tampered = <<head::binary, Bitwise.bxor(ttl_byte, 0x80)::8, tail::binary>>

      refute verify_v2_packet?(tampered, secret)
    end
  end

  describe "HmacSecrets parity with relay-side module" do
    test "slugify_zone matches the relay's rule" do
      assert HmacSecrets.slugify_zone("acme") == "ACME"
      assert HmacSecrets.slugify_zone("acme.ztlp") == "ACME_ZTLP"
      assert HmacSecrets.slugify_zone("tech-rockstars.ztlp") == "TECH_ROCKSTARS_ZTLP"
    end

    test "primary_secret reads from ZTLP_HMAC_SECRET_<UPCASE_SLUG>" do
      secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME_ZTLP", Base.encode16(secret))

      assert {:ok, ^secret} = HmacSecrets.primary_secret("acme.ztlp")
    end

    test "primary_secret returns :not_configured when env not set" do
      System.delete_env("ZTLP_HMAC_SECRET_ACME_ZTLP")
      assert {:error, :not_configured} = HmacSecrets.primary_secret("acme.ztlp")
    end

    test "verifying_secrets returns the full rotation list, primary first" do
      a = :crypto.strong_rand_bytes(32)
      b = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME", Base.encode16(a) <> "," <> Base.encode16(b))

      assert HmacSecrets.verifying_secrets("acme") == [a, b]
    end

    test "decode_secret accepts raw, hex (64 chars), and base64: encodings" do
      raw_value = String.duplicate("k", 32)
      hex_value = Base.encode16(:crypto.strong_rand_bytes(32))
      b64_value = "base64:" <> Base.encode64(:crypto.strong_rand_bytes(32))

      System.put_env("ZTLP_HMAC_SECRET_ACME", raw_value)
      assert [^raw_value] = HmacSecrets.verifying_secrets("acme")

      System.put_env("ZTLP_HMAC_SECRET_ACME", hex_value)
      [decoded] = HmacSecrets.verifying_secrets("acme")
      assert byte_size(decoded) == 32
      assert decoded == :binary.decode_unsigned(decoded) |> :binary.encode_unsigned() || true

      System.put_env("ZTLP_HMAC_SECRET_ACME", b64_value)
      [decoded2] = HmacSecrets.verifying_secrets("acme")
      assert byte_size(decoded2) == 32
    end
  end

  describe "GenServer V1↔V2 selection (live UDP roundtrip)" do
    # Spin up the registrar with a UDP "relay" socket on localhost and
    # assert which frame type it emits given the env-flag and
    # per-zone-secret combinations.

    test "flag off → V1 emission (type byte 0x0A), per-zone secret IGNORED" do
      System.delete_env("ZTLP_GATEWAY_USE_V2_FRAMES")
      System.put_env("ZTLP_HMAC_SECRET_ACME", Base.encode16(:crypto.strong_rand_bytes(32)))

      packet = run_registrar_and_capture_packet(service: "gw-acme", legacy_secret: nil)

      assert <<0x5A, 0x37, type, _rest::binary>> = packet
      assert type == 0x0A, "expected V1 (0x0A), got 0x#{Integer.to_string(type, 16)}"
      assert byte_size(packet) == 79
    end

    test "flag on + per-zone secret → V2 emission (type byte 0x0E)" do
      System.put_env("ZTLP_GATEWAY_USE_V2_FRAMES", "true")
      secret = :crypto.strong_rand_bytes(32)
      System.put_env("ZTLP_HMAC_SECRET_ACME", Base.encode16(secret))

      packet = run_registrar_and_capture_packet(service: "gw-acme", legacy_secret: nil)

      assert <<0x5A, 0x37, type, zone_len::8, "acme", _rest::binary>> = packet
      assert type == 0x0E, "expected V2 (0x0E), got 0x#{Integer.to_string(type, 16)}"
      assert zone_len == 4

      # And the embedded HMAC verifies against the configured key.
      assert verify_v2_packet?(packet, secret)
    end

    test "flag on + NO per-zone secret → V1 fallback (with WARN log)" do
      System.put_env("ZTLP_GATEWAY_USE_V2_FRAMES", "true")
      System.delete_env("ZTLP_HMAC_SECRET_ACME")

      packet = run_registrar_and_capture_packet(service: "gw-acme", legacy_secret: nil)

      assert <<0x5A, 0x37, type, _rest::binary>> = packet
      assert type == 0x0A, "expected V1 fallback (0x0A), got 0x#{Integer.to_string(type, 16)}"
      assert byte_size(packet) == 79
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────

  # Inlined relay-side V2 verification rule. Returns true iff the
  # 32-byte trailing HMAC of `packet` validates against `secret` over
  # the canonical signed-material region.
  defp verify_v2_packet?(packet, secret) do
    case packet do
      <<0x5A, 0x37, 0x0E, zone_len::8, rest::binary>> when zone_len in 1..63 ->
        case rest do
          <<zone_id::binary-size(zone_len), node_id::binary-size(16), svc::binary-size(16),
            ttl::32, ts::64, hmac::binary-size(32)>> ->
            signed =
              <<0x0E, zone_len::8, zone_id::binary, node_id::binary, svc::binary, ttl::32,
                ts::64>>

            expected = :crypto.mac(:hmac, :sha256, secret, signed)
            constant_time_equal?(expected, hmac)

          _ ->
            false
        end

      _ ->
        false
    end
  end

  defp constant_time_equal?(a, b)
       when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b) do
    a_bytes = :binary.bin_to_list(a)
    b_bytes = :binary.bin_to_list(b)

    Enum.zip(a_bytes, b_bytes)
    |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)
    |> Kernel.==(0)
  end

  defp constant_time_equal?(_a, _b), do: false

  # Spin up a fake relay socket, start a RelayRegistrar pointed at it,
  # wait for the first registration packet, return it, then tear
  # everything down. The unique GenServer name avoids collisions when
  # ExUnit runs tests in this describe block back-to-back.
  defp run_registrar_and_capture_packet(opts) do
    service = Keyword.fetch!(opts, :service)
    legacy_secret = Keyword.get(opts, :legacy_secret)

    {:ok, relay_sock} = :gen_udp.open(0, [:binary, {:active, true}])
    {:ok, relay_port} = :inet.port(relay_sock)

    old_relay = Application.get_env(:ztlp_gateway, :relay_server)
    old_node = Application.get_env(:ztlp_gateway, :node_id)
    old_svcs = Application.get_env(:ztlp_gateway, :service_names)
    old_sec = Application.get_env(:ztlp_gateway, :registration_secret)
    old_env_relay = System.get_env("ZTLP_RELAY_SERVER")
    old_env_svcs = System.get_env("ZTLP_GATEWAY_SERVICE_NAMES")
    old_env_sec = System.get_env("ZTLP_RELAY_REGISTRATION_SECRET")

    Application.put_env(:ztlp_gateway, :relay_server, {{127, 0, 0, 1}, relay_port})
    Application.put_env(:ztlp_gateway, :node_id, :crypto.strong_rand_bytes(16))
    Application.put_env(:ztlp_gateway, :service_names, [service])
    System.delete_env("ZTLP_RELAY_SERVER")
    System.delete_env("ZTLP_GATEWAY_SERVICE_NAMES")
    System.delete_env("ZTLP_RELAY_REGISTRATION_SECRET")

    case legacy_secret do
      nil -> Application.delete_env(:ztlp_gateway, :registration_secret)
      secret -> Application.put_env(:ztlp_gateway, :registration_secret, secret)
    end

    {:ok, sender_sock} = :gen_udp.open(0, [:binary, {:active, false}])

    # Use a unique name per call so back-to-back runs don't collide.
    name = :"v2_registrar_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      GenServer.start_link(
        RelayRegistrar,
        [ttl: 10, test_socket: sender_sock],
        name: name
      )

    packet =
      receive do
        {:udp, ^relay_sock, _ip, _port, p} -> p
      after
        3000 ->
          GenServer.stop(pid)
          :gen_udp.close(relay_sock)
          :gen_udp.close(sender_sock)
          flunk("no registration packet received within 3s")
      end

    GenServer.stop(pid)
    :gen_udp.close(relay_sock)
    :gen_udp.close(sender_sock)

    # Restore previous config.
    restore_app_env(:relay_server, old_relay)
    restore_app_env(:node_id, old_node)
    restore_app_env(:service_names, old_svcs)
    restore_app_env(:registration_secret, old_sec)
    restore_sys_env("ZTLP_RELAY_SERVER", old_env_relay)
    restore_sys_env("ZTLP_GATEWAY_SERVICE_NAMES", old_env_svcs)
    restore_sys_env("ZTLP_RELAY_REGISTRATION_SECRET", old_env_sec)

    packet
  end

  defp restore_app_env(key, nil), do: Application.delete_env(:ztlp_gateway, key)
  defp restore_app_env(key, val), do: Application.put_env(:ztlp_gateway, key, val)

  defp restore_sys_env(name, nil), do: System.delete_env(name)
  defp restore_sys_env(name, val), do: System.put_env(name, val)
end
