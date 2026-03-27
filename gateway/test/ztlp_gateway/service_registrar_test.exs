defmodule ZtlpGateway.ServiceRegistrarTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.ServiceRegistrar

  # Stop the app-started instance before each test, restart after
  setup do
    # Terminate the supervisor's child so it won't auto-restart
    Supervisor.terminate_child(ZtlpGateway.Supervisor, ServiceRegistrar)
    Process.sleep(50)

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
      # Clean env
      for key <- ~w[
        ZTLP_GATEWAY_OPERATOR_KEY ZTLP_GATEWAY_OPERATOR_KEY_FILE
        ZTLP_NS_SERVER ZTLP_GATEWAY_PUBLIC_ADDR ZTLP_GATEWAY_BACKENDS
        ZTLP_GATEWAY_SERVICE_ZONE ZTLP_GATEWAY_SERVICE_ALIASES
        ZTLP_NS_REGISTRATION_TTL
      ] do
        System.delete_env(key)
      end

      # Restart the supervisor's child for other tests
      Supervisor.restart_child(ZtlpGateway.Supervisor, ServiceRegistrar)
    end)

    :ok
  end

  describe "key loading" do
    test "loads hex seed from env" do
      seed = :crypto.strong_rand_bytes(32)
      seed_hex = Base.encode16(seed, case: :lower)
      {expected_pub, _expected_priv} = :crypto.generate_key(:eddsa, :ed25519, seed)

      System.put_env("ZTLP_GATEWAY_OPERATOR_KEY", seed_hex)
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert state.enabled == true
      assert state.key_source == :env
      assert state.pubkey_hex == Base.encode16(expected_pub, case: :lower)

      GenServer.stop(pid)
    end

    test "loads key from JSON file" do
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

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert state.enabled == true
      assert state.key_source == :file
      assert state.pubkey_hex == Base.encode16(expected_pub, case: :lower)

      GenServer.stop(pid)
    end

    test "falls back to ephemeral key with warning" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert state.enabled == true
      assert state.key_source == :ephemeral
      assert is_binary(state.pubkey_hex)
      assert byte_size(state.pubkey_hex) == 64

      GenServer.stop(pid)
    end
  end

  describe "service name derivation" do
    test "derives vault alias from vaultwarden backend" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:vaultwarden:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert "default.test.ztlp" in state.service_names
      assert "vault.test.ztlp" in state.service_names

      GenServer.stop(pid)
    end

    test "includes manual aliases from env" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:myapp:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")
      System.put_env("ZTLP_GATEWAY_SERVICE_ALIASES", "myapp,dashboard")

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert "default.test.ztlp" in state.service_names
      assert "myapp.test.ztlp" in state.service_names
      assert "dashboard.test.ztlp" in state.service_names

      GenServer.stop(pid)
    end
  end

  describe "disabled states" do
    test "disabled when no NS server" do
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")

      {:ok, pid} = ServiceRegistrar.start_link()
      state = ServiceRegistrar.state()
      assert state.enabled == false

      GenServer.stop(pid)
    end

    test "disabled when no public addr" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")

      {:ok, pid} = ServiceRegistrar.start_link()
      state = ServiceRegistrar.state()
      assert state.enabled == false

      GenServer.stop(pid)
    end
  end

  describe "registration protocol" do
    test "sends valid REGISTER packet to NS" do
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

      {:ok, pid} = ServiceRegistrar.start_link()

      # First packet will be zone delegation bootstrap (unsigned KEY record)
      assert {:ok, {_ip, bootstrap_port, bootstrap_packet}} = :gen_udp.recv(ns_socket, 0, 5_000)
      assert <<0x09, _::binary>> = bootstrap_packet
      # Accept the zone bootstrap
      :gen_udp.send(ns_socket, {127, 0, 0, 1}, bootstrap_port, <<0x06>>)

      # Next packet: actual SVC registration
      assert {:ok, {_ip, reg_port, packet}} = :gen_udp.recv(ns_socket, 0, 5_000)

      # Verify packet structure: starts with 0x09 (REGISTER)
      assert <<0x09, name_len::16, _rest::binary>> = packet
      assert name_len > 0

      # Extract name
      <<0x09, ^name_len::16, name::binary-size(name_len), rest::binary>> = packet

      # Record type byte should be 0x02 (SVC)
      assert <<0x02, _::binary>> = rest

      # Send success response
      :gen_udp.send(ns_socket, {127, 0, 0, 1}, reg_port, <<0x06>>)

      # Wait and receive remaining registrations, accept them all
      Enum.each(1..10, fn _ ->
        case :gen_udp.recv(ns_socket, 0, 500) do
          {:ok, {_, p, _}} ->
            :gen_udp.send(ns_socket, {127, 0, 0, 1}, p, <<0x06>>)
          {:error, :timeout} -> :ok
        end
      end)

      Process.sleep(200)
      state = ServiceRegistrar.state()
      assert state.total_registrations >= 1

      GenServer.stop(pid)
    end

    test "handles NS rejection with backoff" do
      {:ok, ns_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, ns_port} = :inet.port(ns_socket)

      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:#{ns_port}")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      on_exit(fn -> :gen_udp.close(ns_socket) end)

      {:ok, pid} = ServiceRegistrar.start_link()

      # Receive packets and reject them all
      Enum.each(1..10, fn _ ->
        case :gen_udp.recv(ns_socket, 0, 500) do
          {:ok, {_, client_port, _packet}} ->
            :gen_udp.send(ns_socket, {127, 0, 0, 1}, client_port, <<0xFF>>)
          {:error, :timeout} -> :ok
        end
      end)

      Process.sleep(300)
      state = ServiceRegistrar.state()
      assert state.consecutive_failures >= 1

      GenServer.stop(pid)
    end
  end
end
