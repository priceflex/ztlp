defmodule ZtlpGateway.ComponentAuth do
  @moduledoc """
  Client-side mutual authentication for ZTLP Gateway inter-component communication.

  The gateway only acts as a client — it responds to challenges from NS
  but never initiates them. Uses Ed25519 signatures from OTP's `:crypto`.

  See `ZtlpRelay.ComponentAuth` for the full protocol description.
  """

  require Logger

  @challenge_tag 0xCA
  @response_tag 0xCB
  @nonce_size 16
  @signature_size 64
  @pubkey_size 32

  @type keypair :: {public_key :: binary(), private_key :: binary()}

  # ── Challenge Parsing ─────────────────────────────────────────────────

  @doc """
  Parse a challenge message, extracting the nonce.
  """
  @spec parse_challenge(binary()) :: {:ok, binary()} | :error
  def parse_challenge(<<@challenge_tag, nonce::binary-size(@nonce_size)>>) do
    {:ok, nonce}
  end

  def parse_challenge(_), do: :error

  # ── Response Generation ───────────────────────────────────────────────

  @doc """
  Sign a challenge nonce with our identity key, producing a response message.

  Returns a 97-byte binary: `<<0xCB, signature::binary-64, pubkey::binary-32>>`
  """
  @spec sign_challenge(binary(), binary()) :: binary()
  def sign_challenge(nonce, private_key)
      when byte_size(nonce) == @nonce_size and byte_size(private_key) == 32 do
    signature = :crypto.sign(:eddsa, :none, nonce, [private_key, :ed25519])
    {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, private_key)
    <<@response_tag, signature::binary-size(@signature_size), public_key::binary-size(@pubkey_size)>>
  end

  @doc """
  Parse a response message, extracting the signature and public key.
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
  """
  @spec verify_response(binary(), binary(), binary(), keyword()) ::
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
  """
  @spec generate_identity() :: keypair()
  def generate_identity do
    :crypto.generate_key(:eddsa, :ed25519)
  end

  @doc """
  Load an identity keypair from a hex-encoded key file.
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
    dir = Path.dirname(path)
    File.mkdir_p(dir)

    case File.write(path, hex <> "\n") do
      :ok ->
        File.chmod(path, 0o600)
        Logger.info("[component-auth] Identity key saved to #{path}")
        :ok

      {:error, reason} ->
        Logger.error("[component-auth] Failed to save identity key to #{path}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Parse a list of hex-encoded public key strings into raw binaries.
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

  # ── Configuration Helpers ─────────────────────────────────────────────

  @spec auth_enabled?() :: boolean()
  def auth_enabled? do
    Application.get_env(:ztlp_gateway, :component_auth_enabled, false)
  end

  @spec allowed_keys() :: [binary()]
  def allowed_keys do
    Application.get_env(:ztlp_gateway, :component_auth_allowed_keys, [])
  end

  @spec identity_key_file() :: String.t() | nil
  def identity_key_file do
    Application.get_env(:ztlp_gateway, :component_auth_identity_key_file)
  end
end
