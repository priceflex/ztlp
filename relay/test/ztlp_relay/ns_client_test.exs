defmodule ZtlpRelay.NsClientTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.NsClient

  @moduletag :ns_client

  defp start_mock_ns_server(opts \\ []) do
    parent = self()
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, true}])
    {:ok, port} = :inet.port(socket)
    pid = spawn_link(fn -> mock_ns_loop(socket, parent, opts) end)
    :gen_udp.controlling_process(socket, pid)
    {pid, port, socket}
  end

  defp mock_ns_loop(socket, parent, opts) do
    receive do
      {:udp, ^socket, ip, port, data} ->
        send(parent, {:mock_ns_received, data})

        response =
          case data do
            <<0x01, name_len::16, _name::binary-size(name_len), _type::8>> ->
              handle_mock_query(opts)

            <<0x02, _rest::binary>> ->
              handle_mock_registration(opts)

            _ ->
              <<0xFF>>
          end

        :gen_udp.send(socket, ip, port, response)
        mock_ns_loop(socket, parent, opts)

      :stop ->
        :gen_udp.close(socket)
    end
  end

  defp handle_mock_query(opts) do
    case Keyword.get(opts, :query_response) do
      :not_found -> <<0x03>>
      :error -> <<0xFF>>
      nil -> build_mock_relay_record()
      record_bin when is_binary(record_bin) -> <<0x02>> <> record_bin
    end
  end

  defp handle_mock_registration(opts) do
    case Keyword.get(opts, :register_response) do
      :reject -> <<0xFF>>
      _ -> <<0x06>>
    end
  end

  defp build_mock_relay_record do
    node_id = :crypto.strong_rand_bytes(16)
    name = "test.relay.ztlp"

    data = %{
      node_id: Base.encode16(node_id, case: :lower),
      endpoints: ["127.0.0.1:9999"],
      capacity: 100,
      region: "test"
    }

    type_byte = 3
    data_bin = :erlang.term_to_binary(data, [:deterministic])
    created_at = System.system_time(:second)
    ttl = 3600
    serial = 1
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)

    signable =
      <<type_byte::8, byte_size(name)::16, name::binary, byte_size(data_bin)::32,
        data_bin::binary, created_at::unsigned-big-64, ttl::unsigned-big-32,
        serial::unsigned-big-64>>

    sig = :crypto.sign(:eddsa, :none, signable, [priv, :ed25519])

    record_wire =
      <<type_byte::8, byte_size(name)::16, name::binary, byte_size(data_bin)::32,
        data_bin::binary, created_at::unsigned-big-64, ttl::unsigned-big-32,
        serial::unsigned-big-64, byte_size(sig)::16, sig::binary, byte_size(pub)::16,
        pub::binary>>

    <<0x02>> <> record_wire
  end

  setup do
    if :ets.whereis(:ztlp_relay_ns_cache) != :undefined do
      :ets.delete_all_objects(:ztlp_relay_ns_cache)
    end

    :ok
  end

  describe "discover_relays/1" do
    test "discovers relays from mock NS server" do
      {_pid, port, _socket} = start_mock_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      assert {:ok, records} = NsClient.discover_relays("relay.ztlp")
      assert is_list(records)
      assert length(records) >= 1
      record = hd(records)
      assert record.type == :relay
      assert is_map(record.data)
      GenServer.stop(NsClient)
    end

    test "returns empty list when no relays found" do
      {_pid, port, _socket} = start_mock_ns_server(query_response: :not_found)
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      assert {:ok, []} = NsClient.discover_relays("empty.ztlp")
      GenServer.stop(NsClient)
    end

    test "returns error on invalid query" do
      {_pid, port, _socket} = start_mock_ns_server(query_response: :error)
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      assert {:error, :invalid_query} = NsClient.discover_relays("bad.ztlp")
      GenServer.stop(NsClient)
    end
  end

  describe "register_self/2" do
    test "registers successfully" do
      {_pid, port, _socket} = start_mock_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})

      our_info = %{
        node_id: :crypto.strong_rand_bytes(16),
        endpoints: ["127.0.0.1:5555"],
        capacity: 50,
        region: "test"
      }

      assert :ok = NsClient.register_self("relay.ztlp", our_info)
      assert_receive {:mock_ns_received, <<0x02, _rest::binary>>}
      GenServer.stop(NsClient)
    end

    test "returns error on rejection" do
      {_pid, port, _socket} = start_mock_ns_server(register_response: :reject)
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})

      our_info = %{
        node_id: :crypto.strong_rand_bytes(16),
        endpoints: ["127.0.0.1:5555"],
        capacity: 50,
        region: "test"
      }

      assert {:error, _reason} = NsClient.register_self("relay.ztlp", our_info)
      GenServer.stop(NsClient)
    end
  end

  describe "lookup_relay/1" do
    test "looks up a relay by name" do
      {_pid, port, _socket} = start_mock_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      assert {:ok, record} = NsClient.lookup_relay("test.relay.ztlp")
      assert record.type == :relay
      GenServer.stop(NsClient)
    end

    test "returns error for non-existent relay" do
      {_pid, port, _socket} = start_mock_ns_server(query_response: :not_found)
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      assert {:error, :not_found} = NsClient.lookup_relay("missing.relay.ztlp")
      GenServer.stop(NsClient)
    end

    test "caches results and returns from cache" do
      {_pid, port, _socket} = start_mock_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      assert {:ok, _} = NsClient.lookup_relay("cached.relay.ztlp")
      assert_receive {:mock_ns_received, _}
      assert {:ok, _} = NsClient.lookup_relay("cached.relay.ztlp")
      refute_receive {:mock_ns_received, _}, 100
      GenServer.stop(NsClient)
    end
  end

  describe "clear_cache/0" do
    test "clears the lookup cache" do
      {_pid, port, _socket} = start_mock_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      NsClient.lookup_relay("clear.relay.ztlp")
      assert_receive {:mock_ns_received, _}
      assert :ok = NsClient.clear_cache()
      NsClient.lookup_relay("clear.relay.ztlp")
      assert_receive {:mock_ns_received, _}
      GenServer.stop(NsClient)
    end
  end

  describe "error handling" do
    test "returns error when no NS server configured" do
      {:ok, _} = NsClient.start_link(ns_server: nil)
      assert {:error, :no_ns_server} = NsClient.discover_relays("relay.ztlp")
      GenServer.stop(NsClient)
    end
  end

  describe "wire protocol" do
    test "sends correct query format" do
      {_pid, port, _socket} = start_mock_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      NsClient.discover_relays("relay.ztlp")
      assert_receive {:mock_ns_received, query}
      name = "relay.ztlp"
      name_len = byte_size(name)
      assert <<0x01, ^name_len::16, ^name::binary-size(name_len), 3::8>> = query
      GenServer.stop(NsClient)
    end

    test "sends correct registration format" do
      {_pid, port, _socket} = start_mock_ns_server()
      {:ok, _} = NsClient.start_link(ns_server: {{127, 0, 0, 1}, port})
      node_id = :crypto.strong_rand_bytes(16)
      our_info = %{node_id: node_id, endpoints: ["127.0.0.1:5555"], capacity: 50, region: "test"}
      NsClient.register_self("relay.ztlp", our_info)
      assert_receive {:mock_ns_received, reg_msg}
      assert <<0x02, name_len::16, _rest::binary>> = reg_msg
      <<0x02, ^name_len::16, name::binary-size(name_len), rest2::binary>> = reg_msg
      assert String.ends_with?(name, ".relay.ztlp")
      <<3::8, _rest3::binary>> = rest2
      GenServer.stop(NsClient)
    end
  end
end
