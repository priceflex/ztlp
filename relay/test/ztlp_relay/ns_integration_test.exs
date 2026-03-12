defmodule ZtlpRelay.NsIntegrationTest do
  @moduledoc """
  Integration tests for NS-based relay discovery using real ZTLP-NS server.
  """

  use ExUnit.Case, async: false

  alias ZtlpRelay.{NsClient, Config, RelayRegistry, MeshManager}

  @moduletag :ns_integration

  defp start_ns_server do
    Application.put_env(:ztlp_ns, :port, 0)
    Application.put_env(:ztlp_ns, :storage_mode, :ram_copies)

    # Ensure Mnesia is started (required by NS Store)
    :mnesia.stop()
    :mnesia.start()

    {:ok, store_pid} = ZtlpNs.Store.start_link([])
    {:ok, ns_pid} = ZtlpNs.Server.start_link([])
    ns_port = ZtlpNs.Server.port()
    {ns_pid, store_pid, ns_port}
  end

  defp register_relay_record_with_ns(_ns_port, node_id, endpoints, opts \\ []) do
    capacity = Keyword.get(opts, :capacity, 100)
    region = Keyword.get(opts, :region, "test")
    zone = Keyword.get(opts, :zone, "relay.ztlp")
    node_id_hex = Base.encode16(node_id, case: :lower)
    name = "#{node_id_hex}.#{zone}"
    {_pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    record = ZtlpNs.Record.new_relay(name, node_id, endpoints, capacity, region)
    signed = ZtlpNs.Record.sign(record, priv)
    ZtlpNs.Store.insert(signed)
    name
  end

  setup do
    try do
      GenServer.stop(NsClient)
    catch
      :exit, _ -> :ok
    end

    case RelayRegistry.start_link() do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    on_exit(fn ->
      try do
        GenServer.stop(NsClient)
      catch
        :exit, _ -> :ok
      end
    end)

    :ok
  end

  describe "NsClient with real NS server" do
    test "discovers relay records from NS" do
      {ns_pid, _store_pid, ns_port} = start_ns_server()
      relay_node_id = :crypto.strong_rand_bytes(16)
      relay_endpoints = ["127.0.0.1:9876"]
      name = register_relay_record_with_ns(ns_port, relay_node_id, relay_endpoints)
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, ns_port})
      assert {:ok, record} = NsClient.lookup_relay(name)
      assert record.type == :relay
      assert record.data["node_id"] == Base.encode16(relay_node_id, case: :lower)
      assert record.data["endpoints"] == relay_endpoints
      GenServer.stop(ns_pid)
    end

    test "zone discovery returns relay records" do
      {ns_pid, _store_pid, ns_port} = start_ns_server()
      relay_node_id = :crypto.strong_rand_bytes(16)
      node_id_hex = Base.encode16(relay_node_id, case: :lower)
      zone = "relay.ztlp"
      name = "#{node_id_hex}.#{zone}"
      {_pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      record = ZtlpNs.Record.new_relay(name, relay_node_id, ["127.0.0.1:8765"], 50, "us-east")
      signed = ZtlpNs.Record.sign(record, priv)
      ZtlpNs.Store.insert(signed)
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, ns_port})
      assert {:ok, found} = NsClient.lookup_relay(name)
      assert found.type == :relay
      assert found.data["capacity"] == 50
      assert found.data["region"] == "us-east"
      GenServer.stop(ns_pid)
    end

    test "registration via NsClient creates record in NS" do
      {ns_pid, _store_pid, ns_port} = start_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, ns_port})
      our_node_id = :crypto.strong_rand_bytes(16)

      our_info = %{
        node_id: our_node_id,
        endpoints: ["127.0.0.1:4444"],
        capacity: 200,
        region: "eu-west"
      }

      assert :ok = NsClient.register_self("relay.ztlp", our_info)
      node_id_hex = Base.encode16(our_node_id, case: :lower)
      expected_name = "#{node_id_hex}.relay.ztlp"
      Process.sleep(50)

      case ZtlpNs.Store.lookup(expected_name, :relay) do
        {:ok, record} ->
          assert record.data["node_id"] == node_id_hex
          assert record.data["endpoints"] == ["127.0.0.1:4444"]
          assert record.data["capacity"] == 200
          assert record.data["region"] == "eu-west"

        :not_found ->
          flunk("Expected relay record '#{expected_name}' to exist in NS store")
      end

      GenServer.stop(ns_pid)
    end
  end

  describe "config" do
    test "ns_server returns nil by default" do
      assert Config.ns_server() == nil
    end

    test "ns_discovery_zone defaults to relay.ztlp" do
      assert Config.ns_discovery_zone() == "relay.ztlp"
    end

    test "ns_refresh_interval_ms defaults to 60_000" do
      assert Config.ns_refresh_interval_ms() == 60_000
    end

    test "relay_region defaults to default" do
      assert Config.relay_region() == "default"
    end
  end

  describe "static bootstrap fallback" do
    test "mesh manager works without NS server configured" do
      our_node_id = :crypto.strong_rand_bytes(16)

      {:ok, pid} =
        MeshManager.start_link(
          node_id: our_node_id,
          mesh_listen_port: 0,
          bootstrap_relays: [],
          ns_server: nil
        )

      status = MeshManager.get_mesh_status()
      assert status.node_id == our_node_id
      assert status.socket_open == true
      GenServer.stop(pid)
    end
  end
end
