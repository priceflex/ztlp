defmodule ZtlpGateway.ServiceRegistrarTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.ServiceRegistrar

  # Use unique names per test to avoid collision with the app-started instance
  defp unique_name, do: :"test_registrar_#{:erlang.unique_integer([:positive])}"

  setup do
    # Clean env before each test
    for key <- ~w[
      ZTLP_GATEWAY_OPERATOR_KEY ZTLP_GATEWAY_OPERATOR_KEY_FILE
      ZTLP_NS_SERVER ZTLP_GATEWAY_PUBLIC_ADDR ZTLP_GATEWAY_BACKENDS
      ZTLP_GATEWAY_SERVICE_ZONE ZTLP_GATEWAY_SERVICE_ALIASES
      ZTLP_NS_REGISTRATION_TTL
    ] do
      System.delete_env(key)
    end

    on_exit(fn ->
      for key <- ~w[
        ZTLP_GATEWAY_OPERATOR_KEY ZTLP_GATEWAY_OPERATOR_KEY_FILE
        ZTLP_NS_SERVER ZTLP_GATEWAY_PUBLIC_ADDR ZTLP_GATEWAY_BACKENDS
        ZTLP_GATEWAY_SERVICE_ZONE ZTLP_GATEWAY_SERVICE_ALIASES
        ZTLP_NS_REGISTRATION_TTL
      ] do
        System.delete_env(key)
      end
    end)

    :ok
  end

  describe "key loading" do
    test "loads hex seed from env" do
      name = unique_name()
      seed = :crypto.strong_rand_bytes(32)
      seed_hex = Base.encode16(seed, case: :lower)
      {expected_pub, _expected_priv} = :crypto.generate_key(:eddsa, :ed25519, seed)

      System.put_env("ZTLP_GATEWAY_OPERATOR_KEY", seed_hex)
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      {:ok, pid} = ServiceRegistrar.start_link(name: name, test_opts: %{skip_register: true})
      state = ServiceRegistrar.state(name)

      assert state.enabled == true
      assert state.key_source == :env
      assert state.pubkey_hex == Base.encode16(expected_pub, case: :lower)

      GenServer.stop(pid)
    end

    test "loads key from JSON file" do
      name = unique_name()
      seed = :crypto.strong_rand_bytes(32)
      seed_hex = Base.encode16(seed, case: :lower)
      {expected_pub, _} = :crypto.generate_key(:eddsa, :ed25519, seed)

      path = Path.join(System.tmp_dir!(), "test_operator_key_#{:rand.uniform(999999)}.json")
      File.write!(path, ~s({"ed25519_seed": "#{seed_hex}", "ed25519_public_key": "ignored"}))

      System.put_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE", path)
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      on_exit(fn -> File.rm(path) end)

      {:ok, pid} = ServiceRegistrar.start_link(name: name, test_opts: %{skip_register: true})
      state = ServiceRegistrar.state(name)

      assert state.enabled == true
      assert state.key_source == :file
      assert state.pubkey_hex == Base.encode16(expected_pub, case: :lower)

      GenServer.stop(pid)
    end

    test "falls back to ephemeral key with warning" do
      name = unique_name()
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      {:ok, pid} = ServiceRegistrar.start_link(name: name, test_opts: %{skip_register: true})
      state = ServiceRegistrar.state(name)

      assert state.enabled == true
      assert state.key_source == :ephemeral
      assert is_binary(state.pubkey_hex)
      assert byte_size(state.pubkey_hex) == 64

      GenServer.stop(pid)
    end
  end

  describe "service name derivation" do
    test "derives vault alias from vaultwarden backend" do
      name = unique_name()
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:vaultwarden:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      {:ok, pid} = ServiceRegistrar.start_link(name: name, test_opts: %{skip_register: true})
      state = ServiceRegistrar.state(name)

      assert "default.test.ztlp" in state.service_names
      assert "vault.test.ztlp" in state.service_names

      GenServer.stop(pid)
    end

    test "includes manual aliases from env" do
      name = unique_name()
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:myapp:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")
      System.put_env("ZTLP_GATEWAY_SERVICE_ALIASES", "myapp,dashboard")

      {:ok, pid} = ServiceRegistrar.start_link(name: name, test_opts: %{skip_register: true})
      state = ServiceRegistrar.state(name)

      assert "default.test.ztlp" in state.service_names
      assert "myapp.test.ztlp" in state.service_names
      assert "dashboard.test.ztlp" in state.service_names

      GenServer.stop(pid)
    end
  end

  describe "disabled states" do
    test "disabled when no NS server" do
      name = unique_name()
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")

      {:ok, pid} = ServiceRegistrar.start_link(name: name)
      state = ServiceRegistrar.state(name)
      assert state.enabled == false

      GenServer.stop(pid)
    end

    test "disabled when no public addr" do
      name = unique_name()
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")

      {:ok, pid} = ServiceRegistrar.start_link(name: name)
      state = ServiceRegistrar.state(name)
      assert state.enabled == false

      GenServer.stop(pid)
    end
  end

  describe "registration protocol" do
    test "sends valid REGISTER packet to NS" do
      name = unique_name()
      {:ok, ns_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, ns_port} = :inet.port(ns_socket)

      seed = :crypto.strong_rand_bytes(32)
      seed_hex = Base.encode16(seed, case: :lower)

      System.put_env("ZTLP_GATEWAY_OPERATOR_KEY", seed_hex)
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:#{ns_port}")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      on_exit(fn -> :gen_udp.close(ns_socket) end)

      {:ok, pid} = ServiceRegistrar.start_link(name: name)

      # Accept all incoming packets (zone KEY lookup + bootstrap + SVC registrations)
      # and respond with success
      accept_all = fn accept_all ->
        case :gen_udp.recv(ns_socket, 0, 500) do
          {:ok, {_, port, <<0x01, _::binary>>}} ->
            # Zone KEY lookup — respond with "not found" to trigger bootstrap
            :gen_udp.send(ns_socket, {127, 0, 0, 1}, port, <<0xFF>>)
            accept_all.(accept_all)
          {:ok, {_, port, <<0x09, _::binary>> = packet}} ->
            # REGISTER packet (zone bootstrap or SVC registration)
            assert <<0x09, _::binary>> = packet
            :gen_udp.send(ns_socket, {127, 0, 0, 1}, port, <<0x06>>)
            accept_all.(accept_all)
          {:error, :timeout} -> :ok
        end
      end

      # Wait for first registration cycle
      Process.sleep(1_200)
      accept_all.(accept_all)

      Process.sleep(200)
      state = ServiceRegistrar.state(name)
      assert state.total_registrations >= 1

      GenServer.stop(pid)
    end

    test "handles NS rejection with backoff" do
      name = unique_name()
      {:ok, ns_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, ns_port} = :inet.port(ns_socket)

      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:#{ns_port}")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      on_exit(fn -> :gen_udp.close(ns_socket) end)

      {:ok, pid} = ServiceRegistrar.start_link(name: name)

      # Wait for registration cycle, then reject everything
      Process.sleep(1_200)

      reject_all = fn reject_all ->
        case :gen_udp.recv(ns_socket, 0, 500) do
          {:ok, {_, port, _packet}} ->
            :gen_udp.send(ns_socket, {127, 0, 0, 1}, port, <<0xFF>>)
            reject_all.(reject_all)
          {:error, :timeout} -> :ok
        end
      end

      reject_all.(reject_all)

      Process.sleep(300)
      state = ServiceRegistrar.state(name)
      assert state.consecutive_failures >= 1

      GenServer.stop(pid)
    end
  end

  # ── v0.34.2 fix: refresh interval cap + fast-retry on zone-key issues ──
  #
  # Bug discovered 2026-05-29: SVC records have TTL=24h, so the previous
  # next_interval/1 of TTL/2 = 12h meant one missed refresh = 24h outage.
  # In practice the gateway's bootstrap.trs.ztlp SVC went 13+ hours without
  # a single refresh after creation, leaving every Z2LS enrollment dead
  # the moment the record expired.
  #
  # Fix: cap normal refresh at 30 min regardless of TTL, and treat any
  # zone-key-missing / NS-unreachable signal as a "retry soon" event
  # instead of waiting another TTL/2.
  describe "next_interval/1 refresh-cap" do
    test "caps normal refresh interval at 30 minutes even when TTL is 24 hours" do
      # 24h TTL is the production reality for SVC records.
      # Without the cap, this is 12 hours — too long to survive a single
      # missed cycle. With the cap, it must be at most 30 minutes.
      state = %{consecutive_failures: 0, ttl: 86_400}
      interval = ServiceRegistrar.next_interval(state)

      assert interval <= 30 * 60 * 1000,
             "expected ≤ 30min cap, got #{interval}ms (#{div(interval, 60_000)}min)"
    end

    test "respects TTL/2 when TTL is below the cap (1-hour TTL → 30min refresh)" do
      # When the TTL is small enough that TTL/2 < cap, fall back to TTL/2.
      # 1h TTL → 30min refresh, which equals the cap; result should be 30min.
      state = %{consecutive_failures: 0, ttl: 3_600}
      interval = ServiceRegistrar.next_interval(state)

      # TTL/2 = 30min = 1_800_000ms; min(1_800_000, 1_800_000) = 1_800_000
      assert interval == 1_800_000,
             "expected 30min for 1h TTL, got #{interval}ms"
    end

    test "respects TTL/2 when TTL is well below the cap (10-min TTL → 5min refresh)" do
      # Small-TTL configs (test envs, dev) should NOT get bumped up to the
      # cap — the cap is a ceiling, not a floor.
      state = %{consecutive_failures: 0, ttl: 600}
      interval = ServiceRegistrar.next_interval(state)

      assert interval == 300_000,
             "expected 5min for 10min TTL, got #{interval}ms"
    end

    test "keeps existing exponential-backoff behaviour on consecutive failures" do
      # Failure path is unchanged — TTL doesn't matter when the registrar
      # is in backoff mode. Verify the existing curve still holds.
      state_1 = %{consecutive_failures: 1, ttl: 86_400}
      state_2 = %{consecutive_failures: 2, ttl: 86_400}
      state_5 = %{consecutive_failures: 5, ttl: 86_400}

      # Backoff = 5_000 * 2^min(n-1, 4), capped at 60_000.
      assert ServiceRegistrar.next_interval(state_1) == 5_000
      assert ServiceRegistrar.next_interval(state_2) == 10_000
      assert ServiceRegistrar.next_interval(state_5) == 60_000  # capped
    end
  end

  describe "next_interval/1 zone-key-recovery fast-retry" do
    test "schedules a fast retry when zone_bootstrapped just flipped from false to true" do
      # When the registrar discovers the zone KEY was missing and just
      # re-bootstrapped it, the SVC records under that zone are about to
      # fail too (the chain was broken). Don't wait TTL/2 — re-register
      # soon so the SVC records line up with the freshly-bootstrapped
      # zone key.
      state = %{
        consecutive_failures: 0,
        ttl: 86_400,
        zone_just_recovered: true
      }

      interval = ServiceRegistrar.next_interval(state)

      assert interval <= 60_000,
             "expected ≤ 60s after zone recovery, got #{interval}ms"
    end

    test "absence of zone_just_recovered flag falls through to normal cap behaviour" do
      # The flag is opt-in; missing flag must not break existing callers.
      state = %{consecutive_failures: 0, ttl: 86_400}
      interval = ServiceRegistrar.next_interval(state)

      # Normal capped interval — NOT the fast-recovery 60s.
      assert interval == 30 * 60 * 1000
    end
  end
end
