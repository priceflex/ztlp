defmodule ZtlpRelay.GatewayForwarderTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.GatewayForwarder

  setup do
    # GatewayForwarder may or may not be started by the application
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

        :ok

      _pid ->
        :ok
    end
  end

  test "register and lookup forwarded session" do
    initial_count = GatewayForwarder.count()
    session_id = :crypto.strong_rand_bytes(12)
    client = {{10, 0, 0, 1}, 5000}
    gateway = {{10, 0, 0, 2}, 23098}

    GatewayForwarder.register_forwarded_session(session_id, client, gateway)
    # Cast is async, give it a moment
    Process.sleep(10)

    assert {:ok, session} = GatewayForwarder.lookup(session_id)
    assert session.client == client
    assert session.gateway == gateway
    assert GatewayForwarder.count() == initial_count + 1
  end

  test "lookup returns error for unknown session" do
    assert :error == GatewayForwarder.lookup(:crypto.strong_rand_bytes(12))
  end

  test "multiple sessions tracked independently" do
    initial_count = GatewayForwarder.count()
    s1 = :crypto.strong_rand_bytes(12)
    s2 = :crypto.strong_rand_bytes(12)
    c1 = {{10, 0, 0, 1}, 5000}
    c2 = {{10, 0, 0, 3}, 6000}
    gw = {{10, 0, 0, 2}, 23098}

    GatewayForwarder.register_forwarded_session(s1, c1, gw)
    GatewayForwarder.register_forwarded_session(s2, c2, gw)
    Process.sleep(10)

    assert {:ok, session1} = GatewayForwarder.lookup(s1)
    assert {:ok, session2} = GatewayForwarder.lookup(s2)
    assert session1.client == c1
    assert session2.client == c2
    assert GatewayForwarder.count() == initial_count + 2
  end

  describe "lookup_by_peer/1 — post-handshake Noise transport forwarding" do
    # These tests verify the fast-path used by the UDP listener to forward
    # raw Noise transport packets between peers after the handshake has
    # completed. The relay can't parse the ciphertext (zero-trust), so it
    # must route purely by sender→other-peer mapping.

    test "returns the gateway address when the sender is the client" do
      session_id = :crypto.strong_rand_bytes(12)
      client = {{10, 0, 0, 1}, 5000}
      gateway = {{10, 0, 0, 2}, 23098}

      GatewayForwarder.register_forwarded_session(session_id, client, gateway)
      Process.sleep(10)

      assert {:ok, ^session_id, ^gateway} = GatewayForwarder.lookup_by_peer(client)
    end

    test "returns the client address when the sender is the gateway" do
      session_id = :crypto.strong_rand_bytes(12)
      client = {{10, 0, 0, 1}, 5001}
      gateway = {{10, 0, 0, 2}, 23099}

      GatewayForwarder.register_forwarded_session(session_id, client, gateway)
      Process.sleep(10)

      assert {:ok, ^session_id, ^client} = GatewayForwarder.lookup_by_peer(gateway)
    end

    test "returns :error for an unknown peer address" do
      assert :error == GatewayForwarder.lookup_by_peer({{192, 168, 99, 99}, 1234})
    end

    test "pick_gateway_for_service/1 accepts a 16-byte truncated SHA-256 hash and matches the registered service name" do
      # Wire-decoupling Option C: the CLI puts the truncated SHA-256 of the
      # service name in `dst_svc_hash`. Gateways register at the relay with
      # the canonical NAME (string). The relay must hash the registered
      # names and compare against the wire bytes — NOT decode the wire
      # bytes as zero-padded ASCII (the previous, broken assumption).
      #
      # See `proto/src/tunnel.rs::encode_service_name` and
      # `gateway/lib/ztlp_gateway/packet.ex::service_hash/1` — both compute
      # `:crypto.hash(:sha256, downcase(strip_trailing_dots(name))) |> :binary.part(0, 16)`.

      node_id = :crypto.strong_rand_bytes(16)
      service_name = "gw-hermescorp-test-#{System.unique_integer([:positive])}"
      gateway_addr = {{10, 0, 99, 1}, 23097}

      GatewayForwarder.register_dynamic_gateway(gateway_addr, node_id, service_name, 60)
      Process.sleep(20)

      # Compute the same wire hash the CLI sends.
      hash =
        :crypto.hash(:sha256, String.downcase(service_name) |> String.trim_trailing("."))
        |> :binary.part(0, 16)

      assert byte_size(hash) == 16

      # Hash-based lookup MUST hit the registered gateway, not round-robin.
      assert {:ok, ^gateway_addr} = GatewayForwarder.pick_gateway_for_service(hash)

      # And looking up by the legacy string name must still work — backwards
      # compatibility for any internal caller still passing strings.
      assert {:ok, ^gateway_addr} = GatewayForwarder.pick_gateway_for_service(service_name)
    end

    test "pick_gateway_for_service/1 with a 16-byte hash that does not match any registered service returns :error and does NOT silently round-robin to a different tenant" do
      # SECURITY-CRITICAL: when the caller passes an explicit service hash
      # (i.e. they want gw-tenant-X, not just any gateway), the relay MUST
      # NOT silently fall back to whichever other tenant happens to be next
      # in the round-robin index. That was the v0.29.0..v0.29.2 footgun:
      # a client asking for gw-test-org-2 could be silently routed to
      # gw-hermese2e-1779353410 and see the WRONG TENANT's Bootstrap UI.
      #
      # Strict-routing contract:
      #   * explicit non-zero service hash with NO match  → :error
      #   * empty / all-zero service hash                 → fall back to
      #     `pick_gateway/0` round-robin (unchanged behavior)
      #
      # This test pins the strict path for non-matching hashes.

      node_id_a = :crypto.strong_rand_bytes(16)
      node_id_b = :crypto.strong_rand_bytes(16)
      gw_a = {{10, 0, 88, 1}, 23097}
      gw_b = {{10, 0, 88, 2}, 23097}

      GatewayForwarder.register_dynamic_gateway(gw_a, node_id_a, "gw-some-other-tenant-a", 60)
      GatewayForwarder.register_dynamic_gateway(gw_b, node_id_b, "gw-some-other-tenant-b", 60)
      Process.sleep(20)

      # Hash of a service NOT registered.
      hash =
        :crypto.hash(:sha256, "gw-totally-unknown-#{System.unique_integer([:positive])}")
        |> :binary.part(0, 16)

      result = GatewayForwarder.pick_gateway_for_service(hash)

      # MUST be :error. Returning {:ok, gw_a} or {:ok, gw_b} would mean a
      # silent cross-tenant route — exactly the bug Task #2 of the v0.29.3
      # handoff was filed to prevent.
      assert result == :error,
             "pick_gateway_for_service/1 with an unknown service hash must return :error, " <>
               "not silently round-robin to a different tenant. Got: #{inspect(result)}"
    end

    test "pick_gateway_for_service/1 with an unknown service NAME (string form) also returns :error" do
      # Same strict contract for the legacy string-name caller path.
      # Internal Elixir callers that still pass a name string instead of a
      # hash get the same hard-error semantics — no surprise round-robin.

      node_id = :crypto.strong_rand_bytes(16)
      gw = {{10, 0, 77, 1}, 23097}

      GatewayForwarder.register_dynamic_gateway(gw, node_id, "gw-real-tenant", 60)
      Process.sleep(20)

      result = GatewayForwarder.pick_gateway_for_service("gw-does-not-exist")

      assert result == :error,
             "pick_gateway_for_service/1 with an unknown service name must return :error. " <>
               "Got: #{inspect(result)}"
    end

    test "pick_gateway_for_service/1 with an all-zero (no-preference) hash falls back to round-robin" do
      # Backwards-compat sanity: the all-zero 16-byte hash is the
      # \"no service preference\" sentinel (see `forward_hello_to_gateway`
      # in `udp_listener.ex` — it routes nil and <<0::128>> through
      # `pick_gateway/0`, never through `pick_gateway_for_service/1`).
      #
      # If a caller does pass us the all-zero hash directly, treat it as
      # the same \"any gateway\" intent rather than the strict-error path,
      # so the legacy semantics still hold for pre-Option-C clients.

      node_id = :crypto.strong_rand_bytes(16)
      gw = {{10, 0, 66, 1}, 23097}

      GatewayForwarder.register_dynamic_gateway(gw, node_id, "gw-some-tenant", 60)
      Process.sleep(20)

      result = GatewayForwarder.pick_gateway_for_service(<<0::128>>)

      assert match?({:ok, _}, result),
             "all-zero hash should fall back to round-robin, not strict-error. " <>
               "Got: #{inspect(result)}"
    end

    test "update_client/2 rewrites the peer index so old client address is no longer routable" do
      # When a NAT rebinds the client's source port, the relay's
      # GatewayForwarder is updated via {:update_client, ...}. The peer
      # index must be kept in sync so the old (stale) address can no
      # longer be used to forward packets.
      session_id = :crypto.strong_rand_bytes(12)
      old_client = {{10, 0, 0, 1}, 5002}
      new_client = {{10, 0, 0, 1}, 5999}
      gateway = {{10, 0, 0, 2}, 23100}

      GatewayForwarder.register_forwarded_session(session_id, old_client, gateway)
      Process.sleep(10)
      assert {:ok, ^session_id, ^gateway} = GatewayForwarder.lookup_by_peer(old_client)

      GenServer.cast(GatewayForwarder, {:update_client, session_id, new_client})
      Process.sleep(10)

      assert :error == GatewayForwarder.lookup_by_peer(old_client)
      assert {:ok, ^session_id, ^gateway} = GatewayForwarder.lookup_by_peer(new_client)
      # Gateway can still reach the client (now at its new addr)
      assert {:ok, ^session_id, ^new_client} = GatewayForwarder.lookup_by_peer(gateway)
    end

    test "pick_gateway/0 excludes non-gateway-prefixed registrations (z2ls-style services)" do
      # SECURITY-CRITICAL: pick_gateway/0 is the all-zeros / no-preference
      # fallback round-robin used by `forward_hello_to_gateway/5` in
      # `udp_listener.ex` when the client's HELLO carries no
      # `dst_svc_hash`. It must NOT round-robin over registrations that
      # aren't gateways at all — e.g. ad-hoc service registrations like
      # `z2ls-desktop-lrc` registered from a developer's desktop.
      #
      # Observed in production 2026-05-25: a `ztlp connect bootstrap.<zone>`
      # with no --service flag landed on `z2ls-desktop-lrc` at Steve's
      # home IP (47.180.216.203:20251) instead of the tenant gateway.
      # The cross-tenant misroute is the bug this test pins.
      #
      # Contract: only registrations whose `service_name` starts with
      # `"gw:"` (V2 zone-keyed form) or `"gw-"` (V1 slug form) are
      # eligible for the no-preference round-robin. Other services can
      # still be reached by EXPLICIT name/hash via
      # `pick_gateway_for_service/1`, but the no-preference fallback
      # ignores them.

      node_id_gw = :crypto.strong_rand_bytes(16)
      node_id_z2ls = :crypto.strong_rand_bytes(16)
      gw_addr = {{10, 0, 55, 1}, 23097}
      z2ls_addr = {{47, 180, 216, 203}, 20251}

      GatewayForwarder.register_dynamic_gateway(gw_addr, node_id_gw, "gw:my-tenant.ztlp", 60)
      GatewayForwarder.register_dynamic_gateway(z2ls_addr, node_id_z2ls, "z2ls-desktop-lrc", 60)
      Process.sleep(20)

      # Repeat the call 10 times — the legacy round-robin would land on
      # z2ls_addr ~half the time. With the fix, it must NEVER pick z2ls.
      results =
        for _ <- 1..10 do
          {:ok, picked} = GatewayForwarder.pick_gateway()
          picked
        end

      refute Enum.any?(results, fn r -> r == z2ls_addr end),
             "pick_gateway/0 routed to z2ls_addr — cross-tenant route bug regressed. " <>
               "Picks: #{inspect(results)}"
    end

    test "pick_gateway/0 accepts both V1 (gw-<slug>) and V2 (gw:<zone>) prefixes" do
      # Both registration forms emitted by the Rust gateway (in v0.30.5+)
      # must be eligible for the round-robin fallback. The same gateway
      # registers under BOTH forms in parallel, so excluding either
      # would halve the fallback pool.
      #
      # NB: this test asserts the FILTER predicate accepts both prefixes,
      # not a specific round-robin order — the GenServer is shared across
      # tests in this suite, so other registrations may be present in the
      # pool. We use unique addresses + repeated picks just to confirm
      # both shapes get picked at least once over a sufficient sample.

      node_id_v1 = :crypto.strong_rand_bytes(16)
      node_id_v2 = :crypto.strong_rand_bytes(16)
      gw_v1 = {{10, 0, 44, 1}, 23097}
      gw_v2 = {{10, 0, 44, 2}, 23097}

      GatewayForwarder.register_dynamic_gateway(gw_v1, node_id_v1, "gw-legacy-slug", 60)
      GatewayForwarder.register_dynamic_gateway(gw_v2, node_id_v2, "gw:zone.ztlp", 60)
      Process.sleep(20)

      # Sample 50 picks — enough to almost certainly hit both new entries
      # even when other tests have polluted the dynamic gateway pool.
      picks =
        for _ <- 1..50 do
          {:ok, p} = GatewayForwarder.pick_gateway()
          p
        end

      assert gw_v1 in picks,
             "gw- (V1) prefix excluded from pick_gateway/0; picks: #{inspect(picks)}"

      assert gw_v2 in picks,
             "gw: (V2) prefix excluded from pick_gateway/0; picks: #{inspect(picks)}"
    end
  end
end
