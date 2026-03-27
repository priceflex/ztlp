defmodule ZtlpGateway.ServiceRegistrarTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.ServiceRegistrar

  describe "key loading" do
    test "loads hex seed from env" do
      # Generate a known keypair
      seed = :crypto.strong_rand_bytes(32)
      seed_hex = Base.encode16(seed, case: :lower)
      {expected_pub, _expected_priv} = :crypto.generate_key(:eddsa, :ed25519, seed)

      System.put_env("ZTLP_GATEWAY_OPERATOR_KEY", seed_hex)
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      on_exit(fn ->
        System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY")
        System.delete_env("ZTLP_NS_SERVER")
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
        System.delete_env("ZTLP_GATEWAY_BACKENDS")
      end)

      # Start the registrar (it will fail to connect to NS but that's fine)
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

      # Write a temp key file in ztlp keygen format
      path = Path.join(System.tmp_dir!(), "test_operator_key_#{:rand.uniform(999999)}.json")
      File.write!(path, ~s({"ed25519_seed": "#{seed_hex}", "ed25519_public_key": "ignored"}))

      System.put_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE", path)
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY")
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      on_exit(fn ->
        System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE")
        System.delete_env("ZTLP_NS_SERVER")
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
        System.delete_env("ZTLP_GATEWAY_BACKENDS")
        File.rm(path)
      end)

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert state.enabled == true
      assert state.key_source == :file
      assert state.pubkey_hex == Base.encode16(expected_pub, case: :lower)

      GenServer.stop(pid)
    end

    test "falls back to ephemeral key with warning" do
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE")
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY")
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")

      on_exit(fn ->
        System.delete_env("ZTLP_NS_SERVER")
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
        System.delete_env("ZTLP_GATEWAY_BACKENDS")
      end)

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert state.enabled == true
      assert state.key_source == :ephemeral
      assert is_binary(state.pubkey_hex)
      assert byte_size(state.pubkey_hex) == 64  # 32 bytes hex-encoded

      GenServer.stop(pid)
    end
  end

  describe "service name derivation" do
    test "derives vault alias from vaultwarden backend" do
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE")
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY")
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:vaultwarden:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      on_exit(fn ->
        System.delete_env("ZTLP_NS_SERVER")
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
        System.delete_env("ZTLP_GATEWAY_BACKENDS")
        System.delete_env("ZTLP_GATEWAY_SERVICE_ZONE")
      end)

      {:ok, pid} = ServiceRegistrar.start_link(test_opts: %{skip_register: true})
      state = ServiceRegistrar.state()

      assert "default.test.ztlp" in state.service_names
      assert "vault.test.ztlp" in state.service_names

      GenServer.stop(pid)
    end

    test "includes manual aliases from env" do
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE")
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY")
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:myapp:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")
      System.put_env("ZTLP_GATEWAY_SERVICE_ALIASES", "myapp,dashboard")

      on_exit(fn ->
        System.delete_env("ZTLP_NS_SERVER")
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
        System.delete_env("ZTLP_GATEWAY_BACKENDS")
        System.delete_env("ZTLP_GATEWAY_SERVICE_ZONE")
        System.delete_env("ZTLP_GATEWAY_SERVICE_ALIASES")
      end)

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
      System.delete_env("ZTLP_NS_SERVER")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")

      on_exit(fn ->
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
      end)

      {:ok, pid} = ServiceRegistrar.start_link()
      state = ServiceRegistrar.state()
      assert state.enabled == false

      GenServer.stop(pid)
    end

    test "disabled when no public addr" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")

      on_exit(fn ->
        System.delete_env("ZTLP_NS_SERVER")
      end)

      {:ok, pid} = ServiceRegistrar.start_link()
      state = ServiceRegistrar.state()
      assert state.enabled == false

      GenServer.stop(pid)
    end
  end

  describe "registration protocol" do
    test "sends valid REGISTER packet to NS" do
      # Start a mock NS server
      {:ok, ns_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, ns_port} = :inet.port(ns_socket)

      seed = :crypto.strong_rand_bytes(32)
      seed_hex = Base.encode16(seed, case: :lower)

      System.put_env("ZTLP_GATEWAY_OPERATOR_KEY", seed_hex)
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:#{ns_port}")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      on_exit(fn ->
        :gen_udp.close(ns_socket)
        System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY")
        System.delete_env("ZTLP_NS_SERVER")
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
        System.delete_env("ZTLP_GATEWAY_BACKENDS")
        System.delete_env("ZTLP_GATEWAY_SERVICE_ZONE")
      end)

      {:ok, pid} = ServiceRegistrar.start_link()

      # Wait for the registration packet
      assert {:ok, {_ip, _port, packet}} = :gen_udp.recv(ns_socket, 0, 5_000)

      # Verify packet structure: starts with 0x09 (REGISTER)
      assert <<0x09, name_len::16, _rest::binary>> = packet
      assert name_len > 0

      # Extract name
      <<0x09, ^name_len::16, name::binary-size(name_len), rest::binary>> = packet
      assert name == "test.test.ztlp"

      # Record type byte should be 0x02 (SVC)
      assert <<0x02, _::binary>> = rest

      # Send success response
      :gen_udp.send(ns_socket, {127, 0, 0, 1}, _port, <<0x06, 0x00>>)

      # Give it time to process
      Process.sleep(100)

      state = ServiceRegistrar.state()
      assert state.total_registrations >= 1

      GenServer.stop(pid)
    end

    test "handles NS rejection with backoff" do
      {:ok, ns_socket} = :gen_udp.open(0, [:binary, {:active, false}])
      {:ok, ns_port} = :inet.port(ns_socket)

      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY")
      System.delete_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE")
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:#{ns_port}")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "test:localhost:80")
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "test.ztlp")

      on_exit(fn ->
        :gen_udp.close(ns_socket)
        System.delete_env("ZTLP_NS_SERVER")
        System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
        System.delete_env("ZTLP_GATEWAY_BACKENDS")
        System.delete_env("ZTLP_GATEWAY_SERVICE_ZONE")
      end)

      {:ok, pid} = ServiceRegistrar.start_link()

      # Receive and reject the registration
      assert {:ok, {_ip, client_port, _packet}} = :gen_udp.recv(ns_socket, 0, 5_000)
      :gen_udp.send(ns_socket, {127, 0, 0, 1}, client_port, <<0xFF>>)

      Process.sleep(200)
      state = ServiceRegistrar.state()
      assert state.consecutive_failures >= 1

      GenServer.stop(pid)
    end
  end
end
