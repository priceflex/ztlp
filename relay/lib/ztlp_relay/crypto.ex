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

  Uses ChaCha20-Poly1305 with a per-packet nonce and empty plaintext.
  The AAD should be the header bytes excluding the HeaderAuthTag field.

  ## Nonce derivation (MUST match the Rust side, proto/src/pipeline.rs
  `compute_header_auth_tag`)

  nonce = [0; 4] || packet_seq.to_le_bytes()  (12 bytes)

  The per-packet nonce (derived from the packet sequence number,
  little-endian) provides replay protection: a replayed packet carries a
  different seq and therefore produces a different nonce, so its auth tag
  won't verify. (The old implementation used a fixed all-zero nonce and
  relied on AAD uniqueness for replay protection — the Rust security fix
  in commit 53b607f moved to per-packet nonces, and this side had to
  follow.)

  ## Parameters

    - `key` — 32-byte symmetric key
    - `aad` — Additional Authenticated Data (header bytes without auth tag)
    - `packet_seq` — the packet's sequence number (u64)

  ## Returns

  A 16-byte binary (128-bit Poly1305 tag).
  """
  @spec compute_header_auth_tag(binary(), binary(), non_neg_integer()) :: binary()
  def compute_header_auth_tag(key, aad, packet_seq \\ 0) when byte_size(key) == 32 do
    nonce = build_nonce(packet_seq)

    # Encrypt empty plaintext with header as AAD
    # Returns {ciphertext, tag} where ciphertext is empty
    {_ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        @chacha_cipher,
        key,
        nonce,
        _plaintext = <<>>,
        aad,
        _tag_length = 16,
        # encrypt
        true
      )

    tag
  end

  @doc """
  Verify a HeaderAuthTag against the given key and AAD.

  ## Parameters

    - `key` — 32-byte symmetric key
    - `aad` — Additional Authenticated Data (header bytes without auth tag)
    - `tag` — 16-byte auth tag to verify
    - `packet_seq` — the packet's sequence number (u64), used for the nonce

  ## Returns

  `true` if the tag is valid, `false` otherwise.
  """
  @spec verify_header_auth_tag(binary(), binary(), binary(), non_neg_integer()) :: boolean()
  def verify_header_auth_tag(key, aad, tag, packet_seq \\ 0)

  def verify_header_auth_tag(key, aad, tag, packet_seq)
      when byte_size(key) == 32 and byte_size(tag) == 16 do
    nonce = build_nonce(packet_seq)

    # Decrypt empty ciphertext with the tag to verify
    # If tag is invalid, :crypto.crypto_one_time_aead/7 returns :error
    case :crypto.crypto_one_time_aead(
           @chacha_cipher,
           key,
           nonce,
           _ciphertext = <<>>,
           aad,
           tag,
           # decrypt/verify
           false
         ) do
      :error -> false
      _plaintext -> true
    end
  end

  def verify_header_auth_tag(_key, _aad, _tag, _packet_seq), do: false

  # Build the 12-byte nonce: [0; 4] || packet_seq (little-endian, 8 bytes).
  # MUST match proto/src/pipeline.rs compute_header_auth_tag exactly.
  defp build_nonce(packet_seq) when is_integer(packet_seq) and packet_seq >= 0 do
    <<0::32, packet_seq::little-64>>
  end

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
