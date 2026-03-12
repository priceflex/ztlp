defmodule ZtlpNs.Enrollment do
  @moduledoc """
  Enrollment token validation and device registration for ZTLP-NS.

  Handles the 0x07 ENROLL wire protocol message. When a device presents
  a valid enrollment token along with its public key and desired name,
  this module:

  1. Validates the token MAC (HMAC-BLAKE2s) against the zone secret
  2. Checks expiration
  3. Checks and decrements usage count
  4. Creates KEY and optional SVC records for the device
  5. Returns network configuration (relay/gateway addresses)

  ## Token Store

  Enrollment tokens are tracked in an ETS table keyed by nonce (16 bytes).
  Each entry tracks remaining uses. Tokens with max_uses=0 are unlimited.

  ## Wire Protocol

  ### ENROLL request (0x07): client → NS

      <<0x07,
        token_len::16, token_binary::binary-size(token_len),
        pubkey::binary-size(32),
        node_id::binary-size(16),
        name_len::16, name::binary-size(name_len),
        addr_len::16, addr::binary-size(addr_len)>>

  ### ENROLL response (0x08): NS → client

      <<0x08, status::8, config_data::binary>>

  Status codes:
  - 0x00 = success (config_data follows)
  - 0x01 = token expired
  - 0x02 = token uses exhausted
  - 0x03 = invalid MAC
  - 0x04 = zone mismatch
  - 0x05 = name already taken
  - 0x06 = invalid request format

  Config data (on success):
      <<relay_count::8, relay_addrs..., gateway_count::8, gateway_addrs...>>
  Where each addr is: <<addr_len::16, addr::binary-size(addr_len)>>
  """

  alias ZtlpNs.{Record, Store}

  @blake2s_block_size 64

  @table :ztlp_enrollment_tokens

  # ── Public API ─────────────────────────────────────────────────────

  @doc "Initialize the enrollment token tracking table."
  @spec init() :: :ok
  def init do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ok
  end

  @doc """
  Process an ENROLL request (0x07 message body, after the 0x07 type byte).

  Returns the response binary (0x08 + status + optional config).
  """
  @spec process_enroll(binary()) :: binary()
  def process_enroll(
        <<token_len::16, token_bin::binary-size(token_len), pubkey::binary-size(32),
          node_id::binary-size(16), name_len::16, name::binary-size(name_len), addr_len::16,
          addr::binary-size(addr_len)>>
      ) do
    # Get zone enrollment secret
    case get_zone_secret() do
      nil ->
        # No enrollment secret configured — enrollment disabled
        <<0x08, 0x06>>

      secret ->
        case validate_token(token_bin, secret) do
          {:ok, token} ->
            addr_str = if addr_len > 0, do: addr, else: nil
            register_device(token, pubkey, node_id, name, addr_str)

          {:error, :expired} ->
            <<0x08, 0x01>>

          {:error, :exhausted} ->
            <<0x08, 0x02>>

          {:error, :invalid_mac} ->
            <<0x08, 0x03>>

          {:error, :invalid_format} ->
            <<0x08, 0x06>>
        end
    end
  end

  # Catch-all for malformed requests
  def process_enroll(_), do: <<0x08, 0x06>>

  @doc "Set the zone enrollment secret (32 bytes)."
  @spec set_zone_secret(binary()) :: :ok
  def set_zone_secret(secret) when byte_size(secret) == 32 do
    Application.put_env(:ztlp_ns, :enrollment_secret, secret)
    :ok
  end

  @doc "Get the zone enrollment secret."
  @spec get_zone_secret() :: binary() | nil
  def get_zone_secret do
    Application.get_env(:ztlp_ns, :enrollment_secret)
  end

  @doc "Reset the token tracking table (for testing)."
  @spec reset() :: :ok
  def reset do
    if :ets.whereis(@table) != :undefined do
      :ets.delete_all_objects(@table)
    end

    :ok
  end

  # ── Token Validation ───────────────────────────────────────────────

  @doc false
  defp validate_token(token_bin, secret) do
    case parse_token(token_bin) do
      {:ok, token} ->
        # 1. Verify MAC
        {data, mac} = split_mac(token_bin)

        expected_mac = hmac_blake2s(secret, data)

        if not constant_time_equal(mac, expected_mac) do
          {:error, :invalid_mac}
        else
          # 2. Check expiration
          now = System.system_time(:second)

          if token.expires_at > 0 and now > token.expires_at do
            {:error, :expired}
          else
            # 3. Check and decrement usage count
            case check_usage(token) do
              :ok -> {:ok, token}
              {:error, reason} -> {:error, reason}
            end
          end
        end

      {:error, _} ->
        {:error, :invalid_format}
    end
  end

  defp check_usage(%{max_uses: 0}), do: :ok

  defp check_usage(%{nonce: nonce, max_uses: max_uses}) do
    init()

    case :ets.lookup(@table, nonce) do
      [] ->
        # First use — record with remaining = max_uses - 1
        :ets.insert(@table, {nonce, max_uses - 1})
        :ok

      [{^nonce, remaining}] when remaining > 0 ->
        :ets.insert(@table, {nonce, remaining - 1})
        :ok

      [{^nonce, 0}] ->
        {:error, :exhausted}
    end
  end

  # ── Token Parsing ──────────────────────────────────────────────────

  @doc false
  defp parse_token(data) when byte_size(data) < 52 do
    # Minimum: version(1) + flags(1) + zone_len(2) + ns_len(2) + relay_count(1)
    #        + max_uses(2) + expires(8) + nonce(16) + mac(32) = 65 minimum
    {:error, :too_short}
  end

  defp parse_token(data) do
    try do
      <<version::8, flags::8, rest::binary>> = data

      if version != 0x01 do
        throw({:error, :bad_version})
      end

      # Zone
      <<zone_len::16, zone::binary-size(zone_len), rest2::binary>> = rest

      # NS addr
      <<ns_len::16, ns_addr::binary-size(ns_len), rest3::binary>> = rest2

      # Relay addrs
      <<relay_count::8, rest4::binary>> = rest3
      {relay_addrs, rest5} = parse_relay_addrs(rest4, relay_count, [])

      # Gateway addr (if flag set)
      {gateway_addr, rest6} =
        if Bitwise.band(flags, 0x01) != 0 do
          <<gw_len::16, gw::binary-size(gw_len), r::binary>> = rest5
          {gw, r}
        else
          {nil, rest5}
        end

      # max_uses, expires_at, nonce, mac
      <<max_uses::16, expires_at::64, nonce::binary-size(16), _mac::binary-size(32)>> = rest6

      {:ok,
       %{
         version: version,
         zone: zone,
         ns_addr: ns_addr,
         relay_addrs: relay_addrs,
         gateway_addr: gateway_addr,
         max_uses: max_uses,
         expires_at: expires_at,
         nonce: nonce
       }}
    rescue
      MatchError -> {:error, :malformed}
    catch
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_relay_addrs(rest, 0, acc), do: {Enum.reverse(acc), rest}

  defp parse_relay_addrs(<<len::16, addr::binary-size(len), rest::binary>>, count, acc) do
    parse_relay_addrs(rest, count - 1, [addr | acc])
  end

  defp split_mac(token_bin) do
    mac_start = byte_size(token_bin) - 32
    <<data::binary-size(mac_start), mac::binary-size(32)>> = token_bin
    {data, mac}
  end

  # ── Device Registration ────────────────────────────────────────────

  defp register_device(token, pubkey, node_id, name, addr_str) do
    # Verify name is within the token's zone
    zone = token.zone

    unless String.ends_with?(name, ".#{zone}") or name == zone do
      # Return zone mismatch
      return_error(0x04)
    else
      # Check if name is already taken
      case Store.lookup(name, :key) do
        {:ok, existing_record} ->
          # Name exists — check if it's the same device (same pubkey)
          existing_pubkey = existing_record.data["public_key"]
          pubkey_hex = Base.encode16(pubkey, case: :lower)

          if existing_pubkey == pubkey_hex do
            # Same device re-enrolling — update
            do_register(token, pubkey, node_id, name, addr_str)
          else
            # Different device — name taken
            <<0x08, 0x05>>
          end

        :not_found ->
          do_register(token, pubkey, node_id, name, addr_str)

        {:error, :revoked} ->
          # Name was revoked — allow re-registration
          do_register(token, pubkey, node_id, name, addr_str)
      end
    end
  end

  defp do_register(token, pubkey, node_id, name, addr_str) do
    pubkey_hex = Base.encode16(pubkey, case: :lower)
    node_id_hex = Base.encode16(node_id, case: :lower)

    # Get or generate the NS signing key
    priv = get_registration_key()

    # Create KEY record
    key_record = %Record{
      name: name,
      type: :key,
      data: %{
        "algorithm" => "Ed25519",
        "node_id" => node_id_hex,
        "public_key" => pubkey_hex
      },
      created_at: System.system_time(:second),
      ttl: 3600,
      serial: System.system_time(:second),
      signature: nil,
      signer_public_key: nil
    }

    signed_key = Record.sign(key_record, priv)

    case Store.insert(signed_key) do
      :ok ->
        :ok

      {:error, _} ->
        # Bump serial and retry
        bumped = %{signed_key | serial: signed_key.serial + 1}
        bumped2 = Record.sign(bumped, priv)
        Store.insert(bumped2)
    end

    # Create SVC record if address provided
    if addr_str do
      svc_record = %Record{
        name: name,
        type: :svc,
        data: %{
          "address" => addr_str,
          "node_id" => node_id_hex,
          "zone" => token.zone
        },
        created_at: System.system_time(:second),
        ttl: 3600,
        serial: System.system_time(:second),
        signature: nil,
        signer_public_key: nil
      }

      signed_svc = Record.sign(svc_record, priv)

      case Store.insert(signed_svc) do
        :ok ->
          :ok

        {:error, _} ->
          bumped = %{signed_svc | serial: signed_svc.serial + 1}
          bumped2 = Record.sign(bumped, priv)
          Store.insert(bumped2)
      end
    end

    # Build success response with network config
    config = build_config_response(token)
    <<0x08, 0x00, config::binary>>
  end

  defp build_config_response(token) do
    # Relay addresses
    relay_count = length(token.relay_addrs)
    relay_bin = Enum.reduce(token.relay_addrs, <<relay_count::8>>, fn addr, acc ->
      addr_bin = addr
      <<acc::binary, byte_size(addr_bin)::16, addr_bin::binary>>
    end)

    # Gateway addresses
    gw_addrs =
      if token.gateway_addr do
        [token.gateway_addr]
      else
        []
      end

    gw_count = length(gw_addrs)
    gw_bin = Enum.reduce(gw_addrs, <<gw_count::8>>, fn addr, acc ->
      addr_bin = addr
      <<acc::binary, byte_size(addr_bin)::16, addr_bin::binary>>
    end)

    <<relay_bin::binary, gw_bin::binary>>
  end

  defp return_error(code), do: <<0x08, code>>

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

  # ── HMAC-BLAKE2s ───────────────────────────────────────────────────

  @doc "HMAC-BLAKE2s-256 matching the Rust enrollment token implementation."
  @spec hmac_blake2s(binary(), binary()) :: binary()
  def hmac_blake2s(key, data) when byte_size(key) <= @blake2s_block_size do
    key_padded = pad_key(key)
    ipad = :crypto.exor(key_padded, :binary.copy(<<0x36>>, @blake2s_block_size))
    opad = :crypto.exor(key_padded, :binary.copy(<<0x5C>>, @blake2s_block_size))

    inner_hash = :crypto.hash(:blake2s, <<ipad::binary, data::binary>>)
    :crypto.hash(:blake2s, <<opad::binary, inner_hash::binary>>)
  end

  def hmac_blake2s(key, data) when byte_size(key) > @blake2s_block_size do
    hashed_key = :crypto.hash(:blake2s, key)
    hmac_blake2s(hashed_key, data)
  end

  defp pad_key(key) when byte_size(key) == @blake2s_block_size, do: key

  defp pad_key(key) do
    padding_size = @blake2s_block_size - byte_size(key)
    padding_bits = padding_size * 8
    <<key::binary, 0::size(padding_bits)>>
  end

  defp constant_time_equal(a, b) when byte_size(a) == byte_size(b) do
    # XOR all bytes and check if result is zero — constant time
    a_bytes = :binary.bin_to_list(a)
    b_bytes = :binary.bin_to_list(b)

    xor_sum =
      Enum.zip(a_bytes, b_bytes)
      |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)

    xor_sum == 0
  end

  defp constant_time_equal(_, _), do: false
end
