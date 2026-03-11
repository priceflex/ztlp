defmodule ZtlpRelay.ComponentAuth do
  @moduledoc """
  Mutual authentication for inter-component communication using Ed25519.

  Provides a lightweight challenge-response protocol for authenticating
  ZTLP components (relays, NS servers, gateways) over UDP. Since standard
  TLS requires TCP, this module implements mutual authentication using
  Ed25519 signatures over the existing `:crypto` OTP module.

  ## Protocol

  1. Challenger sends: `<<0xCA, nonce::binary-16>>`  (17 bytes)
  2. Responder sends: `<<0xCB, signature::binary-64, pubkey::binary-32>>`  (97 bytes)
  3. Challenger verifies signature over nonce against allowed public keys

  ## Configuration

  - `component_auth.enabled` — boolean, default `false`
  - `component_auth.identity_key_file` — path to hex-encoded Ed25519 private key
  - `component_auth.allowed_keys` — list of hex-encoded Ed25519 public keys

  When disabled, all connections are allowed (backward compatible).
  """

  require Logger

  @challenge_tag 0xCA
  @response_tag 0xCB
  @nonce_size 16
  @signature_size 64
  @pubkey_size 32

  # Nonce expiry in milliseconds (30 seconds)
  @nonce_ttl_ms 30_000

  @type keypair :: {public_key :: binary(), private_key :: binary()}
  @type nonce :: binary()

  # ── Challenge Generation ──────────────────────────────────────────────

  @doc """
  Generate a challenge message containing a random nonce.

  Returns `{challenge_binary, nonce}` where:
  - `challenge_binary` is a 17-byte binary `<<0xCA, nonce::binary-16>>`
  - `nonce` is the 16-byte random value (retained for verification)
  """
  @spec generate_challenge() :: {binary(), nonce()}
  def generate_challenge do
    nonce = :crypto.strong_rand_bytes(@nonce_size)
    {<<@challenge_tag, nonce::binary>>, nonce}
  end

  @doc """
  Parse a challenge message, extracting the nonce.

  Returns `{:ok, nonce}` or `:error`.
  """
  @spec parse_challenge(binary()) :: {:ok, nonce()} | :error
  def parse_challenge(<<@challenge_tag, nonce::binary-size(@nonce_size)>>) do
    {:ok, nonce}
  end

  def parse_challenge(_), do: :error

  # ── Response Generation ───────────────────────────────────────────────

  @doc """
  Sign a challenge nonce with our identity key, producing a response message.

  Returns a 97-byte binary: `<<0xCB, signature::binary-64, pubkey::binary-32>>`

  ## Parameters
  - `nonce` — the 16-byte challenge nonce to sign
  - `private_key` — our 32-byte Ed25519 private key (seed)
  """
  @spec sign_challenge(nonce(), binary()) :: binary()
  def sign_challenge(nonce, private_key)
      when byte_size(nonce) == @nonce_size and byte_size(private_key) == 32 do
    signature = :crypto.sign(:eddsa, :none, nonce, [private_key, :ed25519])
    {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, private_key)
    <<@response_tag, signature::binary-size(@signature_size), public_key::binary-size(@pubkey_size)>>
  end

  @doc """
  Parse a response message, extracting the signature and public key.

  Returns `{:ok, signature, public_key}` or `:error`.
  """
  @spec parse_response(binary()) :: {:ok, binary(), binary()} | :error
  def parse_response(
        <<@response_tag, signature::binary-size(@signature_size),
          public_key::binary-size(@pubkey_size)>>
      ) do
    {:ok, signature, public_key}
  end

  def parse_response(_), do: :error

  # ── Verification ──────────────────────────────────────────────────────

  @doc """
  Verify a response against the original nonce and allowed public keys.

  When component auth is disabled, always returns `{:ok, peer_pubkey}`.
  When enabled, verifies:
  1. The signature is valid for the nonce
  2. The peer's public key is in the allowed keys list

  ## Parameters
  - `nonce` — the original challenge nonce
  - `signature` — the 64-byte Ed25519 signature from the response
  - `peer_pubkey` — the 32-byte Ed25519 public key from the response
  - `opts` — keyword list with `:enabled` and `:allowed_keys`

  ## Returns
  - `{:ok, peer_pubkey}` on success
  - `{:error, reason}` on failure
  """
  @spec verify_response(nonce(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, atom()}
  def verify_response(nonce, signature, peer_pubkey, opts \\ []) do
    enabled = Keyword.get(opts, :enabled, auth_enabled?())
    allowed_keys = Keyword.get(opts, :allowed_keys, allowed_keys())

    cond do
      not enabled ->
        {:ok, peer_pubkey}

      not :crypto.verify(:eddsa, :none, nonce, signature, [peer_pubkey, :ed25519]) ->
        {:error, :invalid_signature}

      allowed_keys == [] ->
        {:error, :no_allowed_keys}

      peer_pubkey not in allowed_keys ->
        {:error, :unauthorized_key}

      true ->
        {:ok, peer_pubkey}
    end
  end

  # ── Identity Key Management ──────────────────────────────────────────

  @doc """
  Load or generate an Ed25519 identity keypair.

  If `identity_key_file` is configured and exists, loads the hex-encoded
  private key from file. Otherwise generates a new keypair.

  When a new keypair is generated and a file path is configured, the
  private key is saved to that path (hex-encoded).

  Returns `{public_key, private_key}`.
  """
  @spec load_or_generate_identity() :: keypair()
  def load_or_generate_identity do
    case identity_key_file() do
      nil ->
        generate_identity()

      path ->
        case load_identity_from_file(path) do
          {:ok, keypair} ->
            keypair

          {:error, :not_found} ->
            keypair = generate_identity()
            save_identity_to_file(path, keypair)
            keypair

          {:error, reason} ->
            Logger.warning(
              "[component-auth] Failed to load identity key from #{path}: #{inspect(reason)}, generating new one"
            )

            generate_identity()
        end
    end
  end

  @doc """
  Generate a new Ed25519 identity keypair.

  Returns `{public_key, private_key}` where both are 32 bytes.
  """
  @spec generate_identity() :: keypair()
  def generate_identity do
    :crypto.generate_key(:eddsa, :ed25519)
  end

  @doc """
  Load an identity keypair from a hex-encoded key file.

  The file should contain a single line with the 32-byte private key
  encoded as 64 hex characters.

  Returns `{:ok, {public_key, private_key}}` or `{:error, reason}`.
  """
  @spec load_identity_from_file(String.t()) :: {:ok, keypair()} | {:error, atom()}
  def load_identity_from_file(path) do
    case File.read(path) do
      {:ok, content} ->
        hex = String.trim(content)

        case Base.decode16(hex, case: :mixed) do
          {:ok, private_key} when byte_size(private_key) == 32 ->
            {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, private_key)
            {:ok, {public_key, private_key}}

          {:ok, _} ->
            {:error, :invalid_key_length}

          :error ->
            {:error, :invalid_hex}
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Save an identity keypair's private key to a hex-encoded file.
  """
  @spec save_identity_to_file(String.t(), keypair()) :: :ok | {:error, term()}
  def save_identity_to_file(path, {_public_key, private_key}) do
    hex = Base.encode16(private_key, case: :lower)

    # Ensure parent directory exists
    dir = Path.dirname(path)
    File.mkdir_p(dir)

    case File.write(path, hex <> "\n") do
      :ok ->
        # Set restrictive permissions (owner read/write only)
        File.chmod(path, 0o600)
        Logger.info("[component-auth] Identity key saved to #{path}")
        :ok

      {:error, reason} ->
        Logger.error("[component-auth] Failed to save identity key to #{path}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ── Nonce Tracking (Replay Protection) ────────────────────────────────

  @doc """
  Record a nonce as used for replay protection.

  Uses an ETS table to track recently used nonces. Nonces expire after
  `@nonce_ttl_ms` milliseconds.

  Returns `:ok` if the nonce was fresh, `{:error, :replay}` if already used.
  """
  @spec record_nonce(nonce()) :: :ok | {:error, :replay}
  def record_nonce(nonce) when byte_size(nonce) == @nonce_size do
    table = ensure_nonce_table()
    now = System.monotonic_time(:millisecond)

    # Clean expired entries occasionally (1 in 10 calls)
    if :rand.uniform(10) == 1 do
      cleanup_expired_nonces(table, now)
    end

    case :ets.insert_new(table, {nonce, now}) do
      true -> :ok
      false -> {:error, :replay}
    end
  end

  @doc """
  Check if a nonce has already been used.
  """
  @spec nonce_used?(nonce()) :: boolean()
  def nonce_used?(nonce) when byte_size(nonce) == @nonce_size do
    table = ensure_nonce_table()

    case :ets.lookup(table, nonce) do
      [{^nonce, timestamp}] ->
        now = System.monotonic_time(:millisecond)
        now - timestamp < @nonce_ttl_ms

      [] ->
        false
    end
  end

  # ── Configuration Helpers ─────────────────────────────────────────────

  @doc """
  Returns whether component authentication is enabled.
  """
  @spec auth_enabled?() :: boolean()
  def auth_enabled? do
    Application.get_env(:ztlp_relay, :component_auth_enabled, false)
  end

  @doc """
  Returns the list of allowed public keys (as raw binaries).
  """
  @spec allowed_keys() :: [binary()]
  def allowed_keys do
    Application.get_env(:ztlp_relay, :component_auth_allowed_keys, [])
  end

  @doc """
  Returns the configured identity key file path, or nil.
  """
  @spec identity_key_file() :: String.t() | nil
  def identity_key_file do
    Application.get_env(:ztlp_relay, :component_auth_identity_key_file)
  end

  @doc """
  Parse a list of hex-encoded public key strings into raw binaries.

  Returns `{:ok, [binary()]}` or `{:error, reason}`.
  """
  @spec parse_allowed_keys([String.t()]) :: {:ok, [binary()]} | {:error, String.t()}
  def parse_allowed_keys(hex_keys) when is_list(hex_keys) do
    results =
      Enum.reduce_while(hex_keys, {:ok, []}, fn hex, {:ok, acc} ->
        case Base.decode16(hex, case: :mixed) do
          {:ok, key} when byte_size(key) == 32 ->
            {:cont, {:ok, [key | acc]}}

          {:ok, key} ->
            {:halt,
             {:error,
              "allowed key must be 32 bytes (64 hex chars), got #{byte_size(key)} bytes: #{hex}"}}

          :error ->
            {:halt, {:error, "invalid hex in allowed key: #{hex}"}}
        end
      end)

    case results do
      {:ok, keys} -> {:ok, Enum.reverse(keys)}
      error -> error
    end
  end

  # ── Metrics Tracking ───────────────────────────────────────────────────

  @metrics_table :ztlp_relay_component_auth_metrics

  @doc """
  Record a challenge issued.
  """
  @spec record_challenge() :: :ok
  def record_challenge do
    ensure_metrics_table()
    :ets.update_counter(@metrics_table, :challenges, {2, 1}, {:challenges, 0})
    :ok
  end

  @doc """
  Record a successful authentication.
  """
  @spec record_success() :: :ok
  def record_success do
    ensure_metrics_table()
    :ets.update_counter(@metrics_table, :successes, {2, 1}, {:successes, 0})
    :ok
  end

  @doc """
  Record a failed authentication.
  """
  @spec record_failure() :: :ok
  def record_failure do
    ensure_metrics_table()
    :ets.update_counter(@metrics_table, :failures, {2, 1}, {:failures, 0})
    :ok
  end

  @doc """
  Get metrics for Prometheus export.

  Returns `%{challenges: int, successes: int, failures: int}`.
  """
  @spec metrics() :: %{challenges: non_neg_integer(), successes: non_neg_integer(), failures: non_neg_integer()}
  def metrics do
    ensure_metrics_table()

    get_counter = fn key ->
      case :ets.lookup(@metrics_table, key) do
        [{^key, n}] -> n
        [] -> 0
      end
    end

    %{
      challenges: get_counter.(:challenges),
      successes: get_counter.(:successes),
      failures: get_counter.(:failures)
    }
  end

  defp ensure_metrics_table do
    case :ets.whereis(@metrics_table) do
      :undefined ->
        try do
          :ets.new(@metrics_table, [:set, :public, :named_table, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end
  end

  # ── Internal ──────────────────────────────────────────────────────────

  defp ensure_nonce_table do
    case :ets.whereis(:ztlp_relay_component_nonces) do
      :undefined ->
        :ets.new(:ztlp_relay_component_nonces, [:set, :public, :named_table])

      tid ->
        tid
    end
  end

  defp cleanup_expired_nonces(table, now) do
    cutoff = now - @nonce_ttl_ms

    # Use select_delete for efficient cleanup
    :ets.select_delete(table, [{{:_, :"$1"}, [{:<, :"$1", cutoff}], [true]}])
  end
end
