defmodule ZtlpRelay.Crypto do
  @moduledoc """
  HeaderAuthTag computation and verification using ChaCha20-Poly1305 AEAD.

  Uses Erlang's `:crypto` module (OTP 24) for ChaCha20-Poly1305 operations.
  The HeaderAuthTag is an AEAD tag over the packet header, computed with
  empty plaintext and the header bytes (minus the tag) as AAD.

  This is a "MAC-only" use of AEAD: we encrypt zero bytes, so the output
  is purely the 16-byte Poly1305 authentication tag over the AAD.
  """

  @chacha_cipher :chacha20_poly1305

  @doc """
  Compute a HeaderAuthTag (128-bit AEAD tag) over the given AAD.

  Uses ChaCha20-Poly1305 with a zero nonce and empty plaintext.
  The AAD should be the header bytes excluding the HeaderAuthTag field.

  ## Parameters

    - `key` — 32-byte symmetric key
    - `aad` — Additional Authenticated Data (header bytes without auth tag)

  ## Returns

  A 16-byte binary (128-bit Poly1305 tag).
  """
  @spec compute_header_auth_tag(binary(), binary()) :: binary()
  def compute_header_auth_tag(key, aad) when byte_size(key) == 32 do
    # 96-bit zero nonce — unique AAD per packet via seq/timestamp
    nonce = <<0::96>>

    # Encrypt empty plaintext with header as AAD
    # Returns {ciphertext, tag} where ciphertext is empty
    {_ciphertext, tag} = :crypto.crypto_one_time_aead(
      @chacha_cipher,
      key,
      nonce,
      _plaintext = <<>>,
      aad,
      _tag_length = 16,
      true  # encrypt
    )

    tag
  end

  @doc """
  Verify a HeaderAuthTag against the given key and AAD.

  ## Parameters

    - `key` — 32-byte symmetric key
    - `aad` — Additional Authenticated Data (header bytes without auth tag)
    - `tag` — 16-byte auth tag to verify

  ## Returns

  `true` if the tag is valid, `false` otherwise.
  """
  @spec verify_header_auth_tag(binary(), binary(), binary()) :: boolean()
  def verify_header_auth_tag(key, aad, tag)
      when byte_size(key) == 32 and byte_size(tag) == 16 do
    nonce = <<0::96>>

    # Decrypt empty ciphertext with the tag to verify
    # If tag is invalid, :crypto.crypto_one_time_aead/7 returns :error
    case :crypto.crypto_one_time_aead(
      @chacha_cipher,
      key,
      nonce,
      _ciphertext = <<>>,
      aad,
      tag,
      false  # decrypt/verify
    ) do
      :error -> false
      _plaintext -> true
    end
  end

  def verify_header_auth_tag(_key, _aad, _tag), do: false

  @doc """
  Generate a random 32-byte key for testing.
  """
  @spec generate_key() :: binary()
  def generate_key do
    :crypto.strong_rand_bytes(32)
  end

  @doc """
  Generate a random 12-byte SessionID.
  """
  @spec generate_session_id() :: binary()
  def generate_session_id do
    :crypto.strong_rand_bytes(12)
  end
end
