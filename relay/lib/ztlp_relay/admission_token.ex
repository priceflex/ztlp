defmodule ZtlpRelay.AdmissionToken do
  @moduledoc """
  Relay Admission Token (RAT) implementation.

  RATs are short-lived, cryptographically signed tokens that prove a node
  has been authenticated by an ingress relay. They are used by transit relays
  to accept pre-authenticated traffic without requiring re-authentication.

  ## Token Structure (93 bytes)

      Version:      1 byte  (0x01)
      NodeID:      16 bytes (authenticated node)
      IssuerID:    16 bytes (issuing relay's NodeID)
      IssuedAt:     8 bytes (Unix timestamp, big-endian)
      ExpiresAt:    8 bytes (Unix timestamp, big-endian)
      SessionScope: 12 bytes (SessionID this token is valid for, or all-zeros for any)
      MAC:         32 bytes (HMAC-BLAKE2s over all preceding fields)

  Total: 93 bytes

  ## HMAC-BLAKE2s

  Uses RFC 2104 HMAC construction with BLAKE2s as the hash function.
  Block size for BLAKE2s is 64 bytes, output size is 32 bytes.
  """

  @version 1
  @token_size 93
  @mac_size 32
  @data_size 61  # 93 - 32
  @blake2s_block_size 64
  @default_ttl_seconds 300

  @type token_fields :: %{
    version: non_neg_integer(),
    node_id: binary(),
    issuer_id: binary(),
    issued_at: non_neg_integer(),
    expires_at: non_neg_integer(),
    session_scope: binary()
  }

  @doc """
  Generate a new 32-byte random secret key for RAT signing.
  """
  @spec generate_secret() :: binary()
  def generate_secret do
    :crypto.strong_rand_bytes(32)
  end

  @doc """
  Issue a new Relay Admission Token.

  ## Parameters

    - `node_id` — 16-byte NodeID of the authenticated node
    - `session_scope` — 12-byte SessionID this token is scoped to,
      or `nil` / all-zeros for any session

  ## Options

    - `:ttl_seconds` — token lifetime (default: 300 = 5 minutes)
    - `:issuer_id` — 16-byte NodeID of the issuing relay (default: from config)
    - `:secret_key` — 32-byte signing key (default: from config)

  ## Returns

  A 93-byte binary token.
  """
  @spec issue(binary(), binary() | nil, keyword()) :: binary()
  def issue(node_id, session_scope \\ nil, opts \\ [])
      when byte_size(node_id) == 16 do
    ttl = Keyword.get(opts, :ttl_seconds, @default_ttl_seconds)
    issuer_id = Keyword.get(opts, :issuer_id, ZtlpRelay.Config.relay_node_id())
    secret_key = Keyword.get(opts, :secret_key, ZtlpRelay.Config.rat_secret())

    scope = normalize_session_scope(session_scope)
    now = System.system_time(:second)
    expires_at = now + ttl

    data = <<
      @version::8,
      node_id::binary-size(16),
      issuer_id::binary-size(16),
      now::big-unsigned-64,
      expires_at::big-unsigned-64,
      scope::binary-size(12)
    >>

    mac = hmac_blake2s(secret_key, data)

    <<data::binary, mac::binary-size(32)>>
  end

  @doc """
  Verify a Relay Admission Token.

  Checks MAC validity, version, and expiration.

  ## Parameters

    - `token` — 93-byte binary token
    - `secret_key` — 32-byte signing key

  ## Options

    - `:session_scope` — if provided, also validates that the token's
      session scope matches (or is all-zeros for any)

  ## Returns

    - `{:ok, fields}` where fields is a map with `:node_id`, `:issuer_id`,
      `:session_scope`, `:expires_at`, `:issued_at`
    - `{:error, reason}` on failure
  """
  @spec verify(binary(), binary(), keyword()) :: {:ok, token_fields()} | {:error, atom()}
  def verify(token, secret_key, opts \\ [])

  def verify(<<data::binary-size(@data_size), mac::binary-size(@mac_size)>>, secret_key, opts)
      when byte_size(secret_key) == 32 do
    expected_mac = hmac_blake2s(secret_key, data)

    if constant_time_compare(mac, expected_mac) do
      case parse_data(data) do
        {:ok, fields} ->
          with :ok <- check_version(fields),
               :ok <- check_expiry(fields),
               :ok <- check_session_scope(fields, Keyword.get(opts, :session_scope)) do
            {:ok, fields}
          end

        error ->
          error
      end
    else
      {:error, :invalid_mac}
    end
  end

  def verify(<<_::binary-size(@token_size)>>, _secret_key, _opts) do
    {:error, :invalid_key}
  end

  def verify(_token, _secret_key, _opts) do
    {:error, :invalid_token_size}
  end

  @doc """
  Verify a token, trying both the current and previous secret keys.

  Used during key rotation to accept tokens signed with either key.
  """
  @spec verify_with_rotation(binary(), binary(), binary() | nil, keyword()) ::
    {:ok, token_fields()} | {:error, atom()}
  def verify_with_rotation(token, current_key, previous_key, opts \\ []) do
    case verify(token, current_key, opts) do
      {:ok, _} = result ->
        result

      {:error, :invalid_mac} when is_binary(previous_key) and byte_size(previous_key) == 32 ->
        verify(token, previous_key, opts)

      error ->
        error
    end
  end

  @doc """
  Parse a token without MAC verification (for inspection).

  ## Returns

    - `{:ok, fields}` — parsed token fields
    - `{:error, reason}` — if token is malformed
  """
  @spec parse(binary()) :: {:ok, token_fields()} | {:error, atom()}
  def parse(<<data::binary-size(@data_size), _mac::binary-size(@mac_size)>>) do
    parse_data(data)
  end

  def parse(_), do: {:error, :invalid_token_size}

  @doc """
  Quick expiry check without full MAC verification.
  """
  @spec expired?(binary()) :: boolean()
  def expired?(<<_version::8, _node_id::binary-size(16), _issuer_id::binary-size(16),
                 _issued_at::big-unsigned-64, expires_at::big-unsigned-64,
                 _session_scope::binary-size(12), _mac::binary-size(32)>>) do
    System.system_time(:second) >= expires_at
  end

  def expired?(_), do: true

  # Internal functions

  @doc false
  defp parse_data(<<version::8, node_id::binary-size(16), issuer_id::binary-size(16),
                    issued_at::big-unsigned-64, expires_at::big-unsigned-64,
                    session_scope::binary-size(12)>>) do
    {:ok, %{
      version: version,
      node_id: node_id,
      issuer_id: issuer_id,
      issued_at: issued_at,
      expires_at: expires_at,
      session_scope: session_scope
    }}
  end

  defp parse_data(_), do: {:error, :malformed_token}

  defp check_version(%{version: @version}), do: :ok
  defp check_version(_), do: {:error, :unsupported_version}

  defp check_expiry(%{expires_at: expires_at}) do
    if System.system_time(:second) < expires_at do
      :ok
    else
      {:error, :expired}
    end
  end

  defp check_session_scope(_fields, nil), do: :ok

  defp check_session_scope(%{session_scope: <<0::96>>}, _expected_scope), do: :ok

  defp check_session_scope(%{session_scope: scope}, expected_scope)
       when byte_size(expected_scope) == 12 do
    if scope == expected_scope do
      :ok
    else
      {:error, :session_scope_mismatch}
    end
  end

  defp check_session_scope(_fields, _scope), do: :ok

  defp normalize_session_scope(nil), do: <<0::96>>
  defp normalize_session_scope(scope) when byte_size(scope) == 12, do: scope

  @doc """
  HMAC-BLAKE2s per RFC 2104.

  HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

  Where:
  - H is BLAKE2s (block_size = 64 bytes, output = 32 bytes)
  - K' is key padded/hashed to block_size
  - ipad = 0x36 repeated block_size times
  - opad = 0x5C repeated block_size times
  """
  @spec hmac_blake2s(binary(), binary()) :: binary()
  def hmac_blake2s(key, data) when byte_size(key) <= @blake2s_block_size do
    # Pad key to block size
    key_padded = pad_key(key)

    ipad = :crypto.exor(key_padded, :binary.copy(<<0x36>>, @blake2s_block_size))
    opad = :crypto.exor(key_padded, :binary.copy(<<0x5C>>, @blake2s_block_size))

    inner_hash = :crypto.hash(:blake2s, <<ipad::binary, data::binary>>)
    :crypto.hash(:blake2s, <<opad::binary, inner_hash::binary>>)
  end

  def hmac_blake2s(key, data) when byte_size(key) > @blake2s_block_size do
    # If key is longer than block size, hash it first
    hashed_key = :crypto.hash(:blake2s, key)
    hmac_blake2s(hashed_key, data)
  end

  defp pad_key(key) when byte_size(key) == @blake2s_block_size, do: key

  defp pad_key(key) do
    padding_size = @blake2s_block_size - byte_size(key)
    padding_bits = padding_size * 8
    <<key::binary, 0::size(padding_bits)>>
  end

  # Constant-time comparison to prevent timing attacks
  defp constant_time_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.exor(a, b)
    |> :binary.bin_to_list()
    |> Enum.reduce(0, fn byte, acc -> Bitwise.bor(acc, byte) end)
    |> Kernel.==(0)
  end

  defp constant_time_compare(_, _), do: false
end
