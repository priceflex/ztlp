defmodule ZtlpRelay.NsClient do
  @moduledoc "UDP client for querying and registering with ZTLP-NS."
  use GenServer
  require Logger

  @ns_cache :ztlp_relay_ns_cache
  @relay_type_byte 3
  @max_retries 3

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @spec discover_relays(String.t()) :: {:ok, [map()]} | {:error, atom()}
  def discover_relays(zone), do: GenServer.call(__MODULE__, {:discover_relays, zone}, 15_000)

  @spec register_self(String.t(), map()) :: :ok | {:error, atom()}
  def register_self(zone, our_info), do: GenServer.call(__MODULE__, {:register_self, zone, our_info}, 10_000)

  @spec lookup_relay(String.t()) :: {:ok, map()} | {:error, atom()}
  def lookup_relay(name) do
    case cache_lookup(name) do
      {:ok, _} = hit -> hit
      :miss -> GenServer.call(__MODULE__, {:lookup_relay, name}, 10_000)
    end
  end

  @spec clear_cache() :: :ok
  def clear_cache, do: GenServer.call(__MODULE__, :clear_cache)

  @impl true
  def init(opts) do
    case :gen_udp.open(0, [:binary, {:active, false}]) do
      {:ok, socket} ->
        if :ets.whereis(@ns_cache) == :undefined do
          :ets.new(@ns_cache, [:named_table, :set, :public, read_concurrency: true])
        end
        {:ok, %{socket: socket, ns_server: Keyword.get(opts, :ns_server)}}
      {:error, reason} ->
        Logger.warning("NsClient: failed to open UDP socket: #{inspect(reason)}")
        {:ok, %{socket: nil, ns_server: nil}}
    end
  end

  @impl true
  def handle_call({:discover_relays, _}, _from, %{socket: nil} = s), do: {:reply, {:error, :no_socket}, s}
  def handle_call({:discover_relays, zone}, _from, s) do
    {:reply, wrap_discover_result(do_query_with_retry(s.socket, zone, @relay_type_byte, get_ns(s))), s}
  end
  def handle_call({:register_self, _, _}, _from, %{socket: nil} = s), do: {:reply, {:error, :no_socket}, s}
  def handle_call({:register_self, zone, info}, _from, s) do
    {:reply, do_register(s.socket, zone, info, get_ns(s)), s}
  end
  def handle_call({:lookup_relay, _}, _from, %{socket: nil} = s), do: {:reply, {:error, :no_socket}, s}
  def handle_call({:lookup_relay, name}, _from, s) do
    case cache_lookup(name) do
      {:ok, _} = hit -> {:reply, hit, s}
      :miss ->
        result = do_query_with_retry(s.socket, name, @relay_type_byte, get_ns(s))
        case result do
          {:ok, rm} ->
            :ets.insert(@ns_cache, {name, {rm, System.system_time(:second) + Map.get(rm, :ttl, 3600)}})
          _ -> :ok
        end
        {:reply, result, s}
    end
  end
  def handle_call(:clear_cache, _from, s) do
    if :ets.whereis(@ns_cache) != :undefined, do: :ets.delete_all_objects(@ns_cache)
    {:reply, :ok, s}
  end

  @impl true
  def terminate(_reason, %{socket: socket}) when not is_nil(socket), do: :gen_udp.close(socket)
  def terminate(_reason, _state), do: :ok

  defp do_query_with_retry(socket, name, tb, ns, attempt \\ 1)
  defp do_query_with_retry(_, _, _, nil, _), do: {:error, :no_ns_server}
  defp do_query_with_retry(socket, name, tb, {host, port}, attempt) do
    case do_query(socket, name, tb, host, port) do
      {:ok, _} = r -> r
      {:error, _} when attempt < @max_retries ->
        Process.sleep(100 * :math.pow(2, attempt - 1) |> round())
        do_query_with_retry(socket, name, tb, {host, port}, attempt + 1)
      error -> error
    end
  end

  defp do_query(socket, name, type_byte, host, port) do
    query = <<0x01, byte_size(name)::16, name::binary, type_byte::8>>
    case resolve_host(host) do
      {:ok, ip} ->
        :gen_udp.send(socket, ip, port, query)
        case :gen_udp.recv(socket, 0, 3000) do
          {:ok, {_, _, response}} -> parse_response(response)
          {:error, :timeout} -> {:error, :timeout}
          {:error, reason} -> {:error, reason}
        end
      {:error, reason} -> {:error, reason}
    end
  end

  defp do_register(_, _, _, nil), do: {:error, :no_ns_server}
  defp do_register(socket, zone, info, {host, port}) do
    hex = Base.encode16(info.node_id, case: :lower)
    name = "#{hex}.#{zone}"
    data = %{node_id: hex, endpoints: info.endpoints, capacity: info.capacity, region: info.region}
    data_bin = :erlang.term_to_binary(data, [:deterministic])
    reg = <<0x02, byte_size(name)::16, name::binary, @relay_type_byte::8,
            byte_size(data_bin)::16, data_bin::binary, 0::16>>
    case resolve_host(host) do
      {:ok, ip} ->
        :gen_udp.send(socket, ip, port, reg)
        case :gen_udp.recv(socket, 0, 3000) do
          {:ok, {_, _, <<0x06, _::binary>>}} -> :ok
          {:ok, {_, _, <<0xFF>>}} -> {:error, :rejected}
          {:ok, {_, _, _}} -> {:error, :unexpected_response}
          {:error, :timeout} -> {:error, :timeout}
          {:error, reason} -> {:error, reason}
        end
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_response(<<0x02, record_bin::binary>>), do: decode_record(record_bin)
  defp parse_response(<<0x03, _::binary>>), do: {:error, :not_found}
  defp parse_response(<<0x04, _::binary>>), do: {:error, :revoked}
  defp parse_response(<<0xFF>>), do: {:error, :invalid_query}
  defp parse_response(_), do: {:error, :invalid_response}

  @type_map %{1 => :key, 2 => :svc, 3 => :relay, 4 => :policy, 5 => :revoke, 6 => :bootstrap}

  defp decode_record(data) do
    <<tb::8, nl::16, rest::binary>> = data
    <<name::binary-size(nl), rest2::binary>> = rest
    <<dl::32, rest3::binary>> = rest2
    <<db::binary-size(dl), rest4::binary>> = rest3
    <<ca::unsigned-big-64, ttl::unsigned-big-32, ser::unsigned-big-64, rest5::binary>> = rest4
    <<sl::16, sig::binary-size(sl), pl::16, pub::binary-size(pl)>> = rest5
    {:ok, %{name: name, type: Map.get(@type_map, tb, :unknown), data: :erlang.binary_to_term(db, [:safe]),
      signature: sig, signer_public_key: pub, created_at: ca, ttl: ttl, serial: ser}}
  rescue
    _ -> {:error, :invalid_wire_format}
  end

  defp cache_lookup(name) do
    case :ets.lookup(@ns_cache, name) do
      [{^name, {rm, exp}}] ->
        if System.system_time(:second) < exp, do: {:ok, rm}, else: (fn -> :ets.delete(@ns_cache, name); :miss end).()
      [] -> :miss
    end
  rescue
    ArgumentError -> :miss
  end

  defp resolve_host(h) when is_tuple(h), do: {:ok, h}
  defp resolve_host(h) when is_binary(h) do
    case :inet.parse_address(String.to_charlist(h)) do
      {:ok, ip} -> {:ok, ip}
      _ -> case :inet.getaddr(String.to_charlist(h), :inet) do
        {:ok, ip} -> {:ok, ip}
        {:error, r} -> {:error, r}
      end
    end
  end
  defp resolve_host(h) when is_list(h) do
    case :inet.parse_address(h) do
      {:ok, ip} -> {:ok, ip}
      _ -> case :inet.getaddr(h, :inet) do
        {:ok, ip} -> {:ok, ip}
        {:error, r} -> {:error, r}
      end
    end
  end

  defp get_ns(%{ns_server: ns}) when not is_nil(ns), do: ns
  defp get_ns(_), do: ZtlpRelay.Config.ns_server()

  defp wrap_discover_result({:ok, rm}), do: {:ok, [rm]}
  defp wrap_discover_result({:error, :not_found}), do: {:ok, []}
  defp wrap_discover_result({:error, _} = err), do: err
end
