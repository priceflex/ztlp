defmodule ZtlpGateway.Crypto do
  @moduledoc """
  Cryptographic primitives for the ZTLP Gateway.

  Wraps OTP 24's `:crypto` module to provide:

  - **X25519** Diffie-Hellman key exchange
  - **ChaCha20-Poly1305** AEAD encryption/decryption
  - **BLAKE2s** hashing (used by the Noise framework)
  - **Ed25519** signatures (for identity verification)
  - **HKDF** (HMAC-based Key Derivation using BLAKE2s as the MAC)

  All functions use only Erlang/OTP built-in crypto — no external dependencies.

  ## OTP 24 API Notes

  - X25519 private keys are 32 bytes (just the scalar/seed)
  - Ed25519 private keys are 32 bytes (seed only; public key must be re-derived)
  - ChaCha20-Poly1305 uses 32-byte keys and 12-byte (96-bit) nonces
  - BLAKE2s produces 32-byte digests
  """

  # ---------------------------------------------------------------------------
  # Types
  # ---------------------------------------------------------------------------

  @type key :: <<_::256>>
  @type public_key :: <<_::256>>
  @type private_key :: <<_::256>>
  @type nonce :: <<_::96>>
  @type tag :: <<_::128>>
  @type keypair :: {public_key(), private_key()}

  # ---------------------------------------------------------------------------
  # X25519 Diffie-Hellman
  # ---------------------------------------------------------------------------

  @doc """
  Generate an X25519 ephemeral keypair for Diffie-Hellman.

  Returns `{public_key, private_key}` where both are 32 bytes.
  The private key is an opaque scalar — do not interpret its bytes.
  """
  @spec generate_keypair() :: keypair()
  def generate_keypair do
    :crypto.generate_key(:ecdh, :x25519)
  end

  @doc """
  Compute the X25519 Diffie-Hellman shared secret.

  Takes the other party's public key and our private key.
  Returns a 32-byte shared secret. Both parties computing
  `dh(other_pub, my_priv)` arrive at the same value.

  ## Parameters
  - `their_public` — the remote party's X25519 public key (32 bytes)
  - `my_private` — our X25519 private key (32 bytes)
  """
  @spec dh(public_key(), private_key()) :: key()
  def dh(their_public, my_private)
      when byte_size(their_public) == 32 and byte_size(my_private) == 32 do
    :crypto.compute_key(:ecdh, their_public, my_private, :x25519)
  end

  # ---------------------------------------------------------------------------
  # ChaCha20-Poly1305 AEAD
  # ---------------------------------------------------------------------------

  @doc """
  Encrypt with ChaCha20-Poly1305 AEAD.

  Returns `{ciphertext, tag}` where tag is 16 bytes (128-bit Poly1305 MAC).

  ## Parameters
  - `key` — 32-byte symmetric key
  - `nonce` — 12-byte nonce (MUST be unique per key)
  - `plaintext` — data to encrypt (arbitrary length)
  - `aad` — additional authenticated data (authenticated but not encrypted)
  """
  @spec encrypt(key(), nonce(), binary(), binary()) :: {binary(), tag()}
  def encrypt(key, nonce, plaintext, aad)
      when byte_size(key) == 32 and byte_size(nonce) == 12 do
    :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, plaintext, aad, true)
  end

  @doc """
  Decrypt with ChaCha20-Poly1305 AEAD.

  Returns the plaintext on success, or `:error` if the tag doesn't verify
  (indicating tampering or wrong key/nonce).

  ## Parameters
  - `key` — 32-byte symmetric key
  - `nonce` — 12-byte nonce (must match what was used for encryption)
  - `ciphertext` — the encrypted data
  - `aad` — additional authenticated data (must match what was used for encryption)
  - `tag` — 16-byte Poly1305 authentication tag
  """
  @spec decrypt(key(), nonce(), binary(), binary(), tag()) :: binary() | :error
  def decrypt(key, nonce, ciphertext, aad, tag)
      when byte_size(key) == 32 and byte_size(nonce) == 12 and byte_size(tag) == 16 do
    :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ciphertext, aad, tag, false)
  end

  # ---------------------------------------------------------------------------
  # BLAKE2s Hashing
  # ---------------------------------------------------------------------------

  @doc """
  Compute a BLAKE2s-256 hash.

  Returns a 32-byte digest. Used by the Noise framework for the
  handshake hash (`h`) and chaining key (`ck`) computations.
  """
  @spec hash(binary()) :: <<_::256>>
  def hash(data) when is_binary(data) do
    :crypto.hash(:blake2s, data)
  end

  # ---------------------------------------------------------------------------
  # HMAC-BLAKE2s (for HKDF)
  # ---------------------------------------------------------------------------

  @doc """
  Compute HMAC using BLAKE2s as the underlying hash.

  OTP 24's `:crypto.mac/4` doesn't support BLAKE2s as an HMAC hash,
  so we implement HMAC manually per RFC 2104:

      HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

  Where H = BLAKE2s, block size = 64 bytes.
  """
  @spec hmac_blake2s(binary(), binary()) :: <<_::256>>
  def hmac_blake2s(key, data) do
    block_size = 64

    # If key is longer than block size, hash it first
    key_prime =
      if byte_size(key) > block_size do
        hash(key)
      else
        key
      end

    # Pad key to block_size with zeros
    padded = key_prime <> :binary.copy(<<0>>, block_size - byte_size(key_prime))

    # Inner and outer pads
    ipad = :crypto.exor(padded, :binary.copy(<<0x36>>, block_size))
    opad = :crypto.exor(padded, :binary.copy(<<0x5C>>, block_size))

    # HMAC = H(opad || H(ipad || data))
    inner = hash(ipad <> data)
    hash(opad <> inner)
  end

  # ---------------------------------------------------------------------------
  # HKDF (HMAC-based Key Derivation Function) using BLAKE2s
  # ---------------------------------------------------------------------------

  @doc """
  HKDF-Extract: derive a pseudorandom key from input keying material.

  Uses HMAC-BLAKE2s. The `salt` acts as the HMAC key, `ikm` is the message.
  If salt is empty, uses a zero-filled key of hash length (32 bytes).

  This is the Noise framework's equivalent of the Extract step.
  """
  @spec hkdf_extract(binary(), binary()) :: <<_::256>>
  def hkdf_extract(salt, ikm) do
    actual_salt =
      if salt == <<>> do
        :binary.copy(<<0>>, 32)
      else
        salt
      end

    hmac_blake2s(actual_salt, ikm)
  end

  @doc """
  HKDF-Expand: expand a pseudorandom key into output keying material.

  Produces `length` bytes of derived key material using HMAC-BLAKE2s.
  The `info` parameter provides context separation (e.g., "ztlp_initiator_to_responder").

  Maximum output is 32 * 255 = 8160 bytes (more than we ever need).
  """
  @spec hkdf_expand(binary(), binary(), pos_integer()) :: binary()
  def hkdf_expand(prk, info, length) when length > 0 and length <= 8160 do
    # Number of HMAC blocks needed (each produces 32 bytes)
    n = div(length + 31, 32)

    {result, _} =
      Enum.reduce(1..n, {<<>>, <<>>}, fn i, {acc, prev} ->
        block = hmac_blake2s(prk, prev <> info <> <<i::8>>)
        {acc <> block, block}
      end)

    binary_part(result, 0, length)
  end

  @doc """
  Noise-style HKDF that splits the chaining key into two or three derived keys.

  Used after each DH operation in the Noise handshake to update the
  chaining key and optionally derive an encryption key.

  Returns `{new_ck, key}` — both 32 bytes.
  """
  @spec hkdf_noise(binary(), binary()) :: {<<_::256>>, <<_::256>>}
  def hkdf_noise(chaining_key, input_key_material) do
    # Noise's HKDF: temp_key = HMAC(ck, ikm), then derive two keys
    temp_key = hmac_blake2s(chaining_key, input_key_material)
    output1 = hmac_blake2s(temp_key, <<1::8>>)
    output2 = hmac_blake2s(temp_key, output1 <> <<2::8>>)
    {output1, output2}
  end

  @doc """
  Three-output Noise HKDF split — used at the end of the handshake
  to derive the two transport keys (initiator→responder, responder→initiator).

  Returns `{key1, key2, key3}` — all 32 bytes.
  """
  @spec hkdf_noise_split(binary(), binary()) :: {<<_::256>>, <<_::256>>, <<_::256>>}
  def hkdf_noise_split(chaining_key, input_key_material) do
    temp_key = hmac_blake2s(chaining_key, input_key_material)
    output1 = hmac_blake2s(temp_key, <<1::8>>)
    output2 = hmac_blake2s(temp_key, output1 <> <<2::8>>)
    output3 = hmac_blake2s(temp_key, output2 <> <<3::8>>)
    {output1, output2, output3}
  end

  # ---------------------------------------------------------------------------
  # Ed25519 Signatures (for identity verification)
  # ---------------------------------------------------------------------------

  @doc """
  Generate an Ed25519 keypair for identity signing.

  Returns `{public_key, private_key}` — both 32 bytes.
  OTP 24 returns the private key as just the seed.
  """
  @spec generate_identity_keypair() :: keypair()
  def generate_identity_keypair do
    :crypto.generate_key(:eddsa, :ed25519)
  end

  @doc """
  Sign a message with an Ed25519 private key.

  Returns a 64-byte Ed25519 signature.
  """
  @spec sign(binary(), private_key()) :: binary()
  def sign(message, private_key) when byte_size(private_key) == 32 do
    :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
  end

  @doc """
  Verify an Ed25519 signature.

  Returns `true` if the signature is valid for the given message
  and public key, `false` otherwise.
  """
  @spec verify(binary(), binary(), public_key()) :: boolean()
  def verify(message, signature, public_key)
      when byte_size(public_key) == 32 and byte_size(signature) == 64 do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end
end
