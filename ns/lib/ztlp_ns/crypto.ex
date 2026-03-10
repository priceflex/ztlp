defmodule ZtlpNs.Crypto do
  @moduledoc """
  Ed25519 cryptographic primitives for ZTLP-NS.

  All record signing and verification in ZTLP-NS uses Ed25519 (RFC 8032).
  We use Erlang's built-in `:crypto` module (OTP 24+) which provides
  `:eddsa` support — no external dependencies needed.

  ## Why Ed25519?

  ZTLP chose Ed25519 for namespace record signing because:
  - Deterministic signatures (no nonce reuse risk unlike ECDSA)
  - Small keys (32 bytes public, 64 bytes private) and signatures (64 bytes)
  - Fast verification (~70μs on modern hardware)
  - Widely deployed and audited (SSH, TLS 1.3, WireGuard, Signal)

  ## OTP 24 API

  The `:crypto.sign/5` and `:crypto.verify/6` functions accept `:eddsa` as
  the algorithm and `:ed25519` as the curve. The digest type is `:none`
  because Ed25519 uses SHA-512 internally (PureEdDSA — the message is
  hashed as part of the signing algorithm, not pre-hashed by the caller).
  """

  @type private_key :: binary()
  @type public_key :: binary()
  @type keypair :: {public_key(), private_key()}
  @type signature :: binary()

  @doc """
  Generate a new Ed25519 keypair.

  Returns `{public_key, private_key}` where:
  - `public_key` is 32 bytes (the Ed25519 public point)
  - `private_key` is 64 bytes (seed + precomputed values, OTP internal format)

  The keypair is generated using OTP's crypto module which delegates to
  OpenSSL or libsodium depending on the build.
  """
  @spec generate_keypair() :: keypair()
  def generate_keypair do
    :crypto.generate_key(:eddsa, :ed25519)
  end

  @doc """
  Sign a message with an Ed25519 private key.

  Returns a 64-byte signature. The message is NOT pre-hashed — Ed25519
  uses PureEdDSA which hashes internally with SHA-512.

  ## Parameters
  - `message` — arbitrary binary to sign
  - `private_key` — 64-byte Ed25519 private key from `generate_keypair/0`
  """
  @spec sign(binary(), private_key()) :: signature()
  def sign(message, private_key) when is_binary(message) and is_binary(private_key) do
    :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
  end

  @doc """
  Verify an Ed25519 signature.

  Returns `true` if the signature is valid for the given message and
  public key, `false` otherwise. This is the fundamental trust operation
  in ZTLP-NS — every record lookup verifies signatures.

  ## Parameters
  - `message` — the signed binary
  - `signature` — 64-byte Ed25519 signature
  - `public_key` — 32-byte Ed25519 public key
  """
  @spec verify(binary(), signature(), public_key()) :: boolean()
  def verify(message, signature, public_key)
      when is_binary(message) and is_binary(signature) and is_binary(public_key) do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  @doc """
  Derive the public key from a private key (seed).

  OTP 24's `:crypto.generate_key(:eddsa, :ed25519)` returns the private
  key as a 32-byte seed. To recover the public key, we regenerate the
  keypair from the seed using `:crypto.generate_key/3`.

  This is useful when you have a private key and need to embed the
  corresponding public key in a signed record.
  """
  @spec public_key_from_private(private_key()) :: public_key()
  def public_key_from_private(private_key) when is_binary(private_key) do
    # Re-derive the public key from the private seed.
    # :crypto.generate_key/3 with the seed as third argument returns
    # the same keypair deterministically.
    {pub, _priv} = :crypto.generate_key(:eddsa, :ed25519, private_key)
    pub
  end
end
