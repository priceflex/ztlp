defmodule ZtlpNs.Server do
  @moduledoc """
  UDP query server for ZTLP-NS.

  Listens on a UDP port and responds to namespace queries. This is the
  network-facing interface to the record store.

  ## Wire Protocol

  All messages are binary. The first byte is the message type:

  ### Query (client → server)
  ```
  <<0x01, name_len::16, name::binary-size(name_len), type_byte::8>>
  ```

  ### Response: Record Found (server → client)
  ```
  <<0x02, record_wire_format::binary>>
  ```
  The record wire format includes the canonical serialization plus
  signature and public key (see `Record.encode/1`).

  ### Response: Not Found (server → client)
  ```
  <<0x03, name_len::16, name::binary-size(name_len), type_byte::8>>
  ```

  ### Response: Revoked (server → client)
  ```
  <<0x04, name_len::16, name::binary-size(name_len)>>
  ```

  ### Response: Invalid Query (server → client)
  ```
  <<0xFF>>
  ```

  ## Type Bytes
  - 1 = KEY, 2 = SVC, 3 = RELAY, 4 = POLICY, 5 = REVOKE, 6 = BOOTSTRAP, 7 = OPERATOR

  ### Query by Public Key (client → server)
  ```
  <<0x05, pubkey_hex_len::16, pubkey_hex::binary-size(pubkey_hex_len)>>
  ```
  Scans the store for any `:key` record whose `data.public_key` matches
  the given hex string. Returns `0x02` (found), `0x03` (not found), or
  `0x04` (revoked). This is an O(n) scan, acceptable for the prototype.
  """

  use GenServer

  alias ZtlpNs.{Enrollment, Query, Record, Store}

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(_args) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @doc "Get the port this server is listening on (useful when port is 0)."
  @spec port() :: non_neg_integer()
  def port do
    GenServer.call(__MODULE__, :get_port)
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(:ok) do
    # Read port at runtime (not compile time) so config changes take effect
    listen_port = ZtlpNs.Config.port()

    # Open UDP socket in binary mode with active message delivery.
    # Active mode means incoming packets arrive as messages to this
    # GenServer's mailbox — no manual recv() loop needed.
    {:ok, socket} = :gen_udp.open(listen_port, [:binary, {:active, true}])

    # Get the actual port (important when configured port is 0)
    {:ok, actual_port} = :inet.port(socket)

    {:ok, %{socket: socket, port: actual_port}}
  end

  @impl true
  def handle_call(:get_port, _from, state) do
    {:reply, state.port, state}
  end

  @impl true
  def handle_info({:udp, _socket, ip, port, data}, state) do
    # Process the query and send the response back to the sender.
    # We don't spawn a separate process for each query — the GenServer
    # handles them sequentially. For a production server, you'd want
    # a worker pool, but for the prototype this is fine.
    reply = process_query(data)
    :gen_udp.send(state.socket, ip, port, reply)
    {:noreply, state}
  end

  # ── Query Processing ───────────────────────────────────────────────

  # Parse a query packet, look up the record, and build the response.
  defp process_query(<<0x01, name_len::16, name::binary-size(name_len), type_byte::8>>) do
    # Convert wire type byte to atom
    type =
      try do
        Record.byte_to_type(type_byte)
      rescue
        _ -> :unknown
      end

    if type == :unknown do
      <<0xFF>>
    else
      case Query.lookup(name, type) do
        {:ok, record} ->
          # Encode the full record (including signature) for the wire
          record_bin = Record.encode(record)
          <<0x02, record_bin::binary>>

        :not_found ->
          <<0x03, name_len::16, name::binary, type_byte::8>>

        {:error, :revoked} ->
          <<0x04, name_len::16, name::binary>>

        {:error, _reason} ->
          <<0x03, name_len::16, name::binary, type_byte::8>>
      end
    end
  end

  # Query by public key (0x05) — scans the store for a :key record
  # whose data.public_key matches the given hex string.
  defp process_query(<<0x05, pk_hex_len::16, pk_hex::binary-size(pk_hex_len)>>) do
    pk_hex_lower = String.downcase(pk_hex)

    # O(n) scan of all records — fine for the prototype
    result =
      ZtlpNs.Store.list()
      |> Enum.find(fn {_name, type, record} ->
        type == :key and
          (Map.get(record.data, :public_key) == pk_hex_lower or
             Map.get(record.data, "public_key") == pk_hex_lower)
      end)

    case result do
      {name, _type, record} ->
        # Check revocation status
        if ZtlpNs.Store.revoked?(name) do
          name_bin = name
          name_len = byte_size(name_bin)
          <<0x04, name_len::16, name_bin::binary>>
        else
          # Verify signature before returning
          if Record.verify(record) do
            record_bin = Record.encode(record)
            <<0x02, record_bin::binary>>
          else
            # Record exists but has invalid signature — treat as not found
            <<0x03, pk_hex_len::16, pk_hex::binary, 0x00::8>>
          end
        end

      nil ->
        # Not found — return 0x03 with the pubkey hex as the "name"
        <<0x03, pk_hex_len::16, pk_hex::binary, 0x00::8>>
    end
  end

  # Registration (0x09) — insert/update a record in the store
  defp process_query(
         <<0x09, name_len::16, name::binary-size(name_len), type_byte::8, data_len::16,
           data_bin::binary-size(data_len), sig_len::16, _sig::binary-size(sig_len)>>
       ) do
    type =
      try do
        Record.byte_to_type(type_byte)
      rescue
        _ -> :unknown
      end

    if type == :unknown do
      <<0xFF>>
    else
      data =
        case ZtlpNs.Cbor.decode(data_bin) do
          {:ok, data} -> data
          {:error, _} -> nil
        end

      if is_nil(data) do
        <<0xFF>>
      else
        record = %Record{
          name: name,
          type: type,
          data: data,
          created_at: System.system_time(:second),
          ttl: 3600,
          serial: System.system_time(:second),
          signature: nil,
          signer_public_key: nil
        }

        priv = get_registration_key()
        signed = Record.sign(record, priv)

        case Store.insert(signed) do
          :ok ->
            <<0x06>>

          {:error, _} ->
            bumped = %{signed | serial: signed.serial + 1}
            bumped2 = Record.sign(bumped, priv)

            case Store.insert(bumped2) do
              :ok -> <<0x06>>
              {:error, _} -> <<0xFF>>
            end
        end
      end
    end
  end

  # Enrollment (0x07) — device enrollment with token
  defp process_query(<<0x07, rest::binary>>) do
    Enrollment.process_enroll(rest)
  end

  # Malformed query → invalid response
  defp process_query(_), do: <<0xFF>>

  defp get_registration_key do
    case Application.get_env(:ztlp_ns, :registration_private_key) do
      nil ->
        {_pub, priv} = ZtlpNs.Crypto.generate_keypair()
        Application.put_env(:ztlp_ns, :registration_private_key, priv)
        priv

      priv ->
        priv
    end
  end
end
