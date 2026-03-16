defmodule ZtlpGateway.Handshake do
  @moduledoc """
  Noise_XX_25519_ChaChaPoly_BLAKE2s handshake implementation.

  The gateway always acts as the **responder** in the Noise_XX pattern.
  The three-message flow is:

      → e                    (initiator sends ephemeral public key)
      ← e, ee, s, es         (responder sends ephemeral + static, DH exchange)
      → s, se                (initiator sends static, final DH)

  After the handshake completes, both sides derive transport keys:
  - `i2r_key` — initiator-to-responder encryption key
  - `r2i_key` — responder-to-initiator encryption key

  ## Noise Framework State

  The handshake maintains three pieces of state:

  - `h` — the handshake hash, updated after every token operation.
    Binds the transcript to prevent tampering.
  - `ck` — the chaining key, updated after each DH operation via HKDF.
    Feeds forward DH outputs into future key derivations.
  - `k` — the current symmetric encryption key, derived after the first DH.
    Used to encrypt/decrypt static keys and payloads within the handshake.
  - `n` — nonce counter for the symmetric key (increments per encrypt/decrypt).

  ## Implementation Notes

  - Uses BLAKE2s for all hashing (not SHA-256) since OTP 24 supports it.
  - The protocol name "Noise_XX_25519_ChaChaPoly_BLAKE2s" is 33 bytes,
    which exceeds 32, so we hash it to get the initial `h`.
  - MixHash(prologue) is applied per Noise spec Section 5.3 (empty by default).
  - Empty encryption key (`k = nil`) means data is sent in the clear
    (only the first message's ephemeral key).
  """

  alias ZtlpGateway.Crypto

  # The Noise protocol name determines the initial hash.
  @protocol_name "Noise_XX_25519_ChaChaPoly_BLAKE2s"

  # ---------------------------------------------------------------------------
  # Types
  # ---------------------------------------------------------------------------

  @type state :: %{
          # Noise framework state
          # handshake hash (32 bytes)
          h: binary(),
          # chaining key (32 bytes)
          ck: binary(),
          # current encryption key (32 bytes or nil)
          k: binary() | nil,
          # nonce counter
          n: non_neg_integer(),

          # Our keys
          # our static public key (X25519)
          s_pub: binary(),
          # our static private key (X25519)
          s_priv: binary(),
          # our ephemeral public key
          e_pub: binary() | nil,
          # our ephemeral private key
          e_priv: binary() | nil,

          # Their keys (learned during handshake)
          # remote ephemeral public key
          re: binary() | nil,
          # remote static public key
          rs: binary() | nil,

          # Phase tracking
          phase: :initialized | :received_msg1 | :sent_msg2 | :complete
        }

  @type transport_keys :: %{
          # initiator-to-responder key
          i2r_key: binary(),
          # responder-to-initiator key
          r2i_key: binary()
        }

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Initialize the responder's handshake state.

  Takes a pre-generated static X25519 keypair (the gateway's long-term identity).
  The ephemeral keypair is generated fresh per handshake in `handle_msg1/2`.

  ## Parameters
  - `static_pub` — gateway's X25519 static public key (32 bytes)
  - `static_priv` — gateway's X25519 static private key (32 bytes)
  """
  @spec init_responder(binary(), binary(), binary()) :: state()
  def init_responder(static_pub, static_priv, prologue \\ <<>>)
      when byte_size(static_pub) == 32 and byte_size(static_priv) == 32 do
    # Protocol name is 33 bytes (> 32), so hash it to get initial h and ck.
    h = Crypto.hash(@protocol_name)
    ck = h
    # MixHash(prologue) per Noise spec Section 5.3
    h = Crypto.hash(h <> prologue)

    %{
      h: h,
      ck: ck,
      k: nil,
      n: 0,
      s_pub: static_pub,
      s_priv: static_priv,
      e_pub: nil,
      e_priv: nil,
      re: nil,
      rs: nil,
      phase: :initialized
    }
  end

  @doc """
  Initialize the initiator's handshake state.

  Used primarily for testing — the gateway is always the responder,
  but we need an initiator to test the full handshake flow.

  ## Parameters
  - `static_pub` — initiator's X25519 static public key (32 bytes)
  - `static_priv` — initiator's X25519 static private key (32 bytes)
  """
  @spec init_initiator(binary(), binary(), binary()) :: state()
  def init_initiator(static_pub, static_priv, prologue \\ <<>>)
      when byte_size(static_pub) == 32 and byte_size(static_priv) == 32 do
    h = Crypto.hash(@protocol_name)
    ck = h
    # MixHash(prologue) per Noise spec Section 5.3
    h = Crypto.hash(h <> prologue)

    %{
      h: h,
      ck: ck,
      k: nil,
      n: 0,
      s_pub: static_pub,
      s_priv: static_priv,
      e_pub: nil,
      e_priv: nil,
      re: nil,
      rs: nil,
      phase: :initialized
    }
  end

  # ---------------------------------------------------------------------------
  # Initiator side (for testing)
  # ---------------------------------------------------------------------------

  @doc """
  Initiator creates Message 1: → e

  Generates an ephemeral keypair, sends the ephemeral public key.
  The key is mixed into the handshake hash but NOT encrypted
  (no encryption key exists yet).

  Returns `{updated_state, message_bytes}`.
  """
  @spec create_msg1(state()) :: {state(), binary()}
  def create_msg1(state) do
    # Generate ephemeral keypair
    {e_pub, e_priv} = Crypto.generate_keypair()

    # Mix ephemeral public key into handshake hash
    h = Crypto.hash(state.h <> e_pub)

    # EncryptAndHash(payload): no key yet, so plaintext passthrough + MixHash
    # Even with empty payload, we must MixHash it per the Noise spec
    h = Crypto.hash(h <> <<>>)

    msg = e_pub

    {%{state | e_pub: e_pub, e_priv: e_priv, h: h, phase: :received_msg1}, msg}
  end

  @doc """
  Initiator processes Message 2: ← e, ee, s, es

  Parses the responder's ephemeral key, performs DH(ee) and DH(es),
  decrypts the responder's static key.

  Returns `{updated_state, payload}` or `{:error, reason}`.
  """
  @spec process_msg2(state(), binary()) :: {state(), binary()} | {:error, atom()}
  def process_msg2(state, message) do
    # Extract responder's ephemeral key (first 32 bytes)
    case message do
      <<re::binary-size(32), rest::binary>> ->
        # Mix re into h
        h = Crypto.hash(state.h <> re)

        # ee: DH(our ephemeral, their ephemeral)
        ee_shared = Crypto.dh(re, state.e_priv)
        {ck, k} = Crypto.hkdf_noise(state.ck, ee_shared)
        n = 0

        # Decrypt responder's static key (encrypted under k)
        # Format: encrypted_s (32 + 16 bytes) + encrypted_payload
        case rest do
          <<encrypted_s::binary-size(48), encrypted_payload::binary>> ->
            ct_s = binary_part(encrypted_s, 0, 32)
            tag_s = binary_part(encrypted_s, 32, 16)
            nonce_s = nonce_from_counter(n)

            case Crypto.decrypt(k, nonce_s, ct_s, h, tag_s) do
              :error ->
                {:error, :decrypt_static_failed}

              rs ->
                # Mix decrypted static key into h
                h = Crypto.hash(h <> encrypted_s)
                # n increments past the static key encryption, but resets
                # after the next HKDF — we track it as n2 below.
                _n = n + 1

                # es: DH(our ephemeral, their static)
                es_shared = Crypto.dh(rs, state.e_priv)
                {ck, k} = Crypto.hkdf_noise(ck, es_shared)
                n2 = 0

                # Decrypt payload
                if byte_size(encrypted_payload) >= 16 do
                  payload_ct =
                    binary_part(encrypted_payload, 0, byte_size(encrypted_payload) - 16)

                  payload_tag =
                    binary_part(encrypted_payload, byte_size(encrypted_payload) - 16, 16)

                  nonce_p = nonce_from_counter(n2)

                  case Crypto.decrypt(k, nonce_p, payload_ct, h, payload_tag) do
                    :error ->
                      {:error, :decrypt_payload_failed}

                    payload ->
                      h = Crypto.hash(h <> encrypted_payload)

                      new_state = %{
                        state
                        | h: h,
                          ck: ck,
                          k: k,
                          n: n2 + 1,
                          re: re,
                          rs: rs,
                          phase: :sent_msg2
                      }

                      {new_state, payload}
                  end
                else
                  # Empty payload — just the tag
                  nonce_p = nonce_from_counter(n2)

                  case Crypto.decrypt(k, nonce_p, <<>>, h, encrypted_payload) do
                    :error ->
                      {:error, :decrypt_payload_failed}

                    payload ->
                      h = Crypto.hash(h <> encrypted_payload)

                      new_state = %{
                        state
                        | h: h,
                          ck: ck,
                          k: k,
                          n: n2 + 1,
                          re: re,
                          rs: rs,
                          phase: :sent_msg2
                      }

                      {new_state, payload}
                  end
                end
            end

          _ ->
            {:error, :msg2_too_short}
        end

      _ ->
        {:error, :msg2_too_short}
    end
  end

  @doc """
  Initiator creates Message 3: → s, se

  Encrypts our static key, performs DH(se), encrypts the payload.
  After this message, the handshake is complete and transport keys
  can be derived via `split/1`.

  Returns `{updated_state, message_bytes}`.
  """
  @spec create_msg3(state(), binary()) :: {state(), binary()}
  def create_msg3(state, payload \\ <<>>) do
    # Encrypt our static public key
    nonce_s = nonce_from_counter(state.n)
    {ct_s, tag_s} = Crypto.encrypt(state.k, nonce_s, state.s_pub, state.h)
    encrypted_s = ct_s <> tag_s

    # Mix encrypted static into h
    h = Crypto.hash(state.h <> encrypted_s)

    # se: DH(our static, their ephemeral)
    se_shared = Crypto.dh(state.re, state.s_priv)
    {ck, k} = Crypto.hkdf_noise(state.ck, se_shared)

    # Nonce resets to 0 after HKDF derives a new key
    nonce_p = nonce_from_counter(0)
    {ct_p, tag_p} = Crypto.encrypt(k, nonce_p, payload, h)
    encrypted_payload = ct_p <> tag_p

    h = Crypto.hash(h <> encrypted_payload)

    msg = encrypted_s <> encrypted_payload

    new_state = %{state | h: h, ck: ck, k: k, n: 1, phase: :complete}

    {new_state, msg}
  end

  # ---------------------------------------------------------------------------
  # Responder side (the gateway's primary role)
  # ---------------------------------------------------------------------------

  @doc """
  Responder processes Message 1: → e

  Extracts the initiator's ephemeral public key and mixes it into
  the handshake hash. No encryption/decryption at this stage.

  Returns `{updated_state, <<>>}` (no payload in msg1) or `{:error, reason}`.
  """
  @spec handle_msg1(state(), binary()) :: {state(), binary()} | {:error, atom()}
  def handle_msg1(state, message) do
    case message do
      <<re::binary-size(32), _rest::binary>> ->
        # Mix remote ephemeral into handshake hash
        h = Crypto.hash(state.h <> re)

        # DecryptAndHash(payload): no key yet, so plaintext passthrough + MixHash
        # msg1 has no payload after the ephemeral key, but Noise requires
        # MixHash of the (empty) payload data per the framework spec
        h = Crypto.hash(h <> <<>>)

        {%{state | re: re, h: h, phase: :received_msg1}, <<>>}

      _ ->
        {:error, :msg1_too_short}
    end
  end

  @doc """
  Responder creates Message 2: ← e, ee, s, es

  1. Generates our ephemeral keypair
  2. Performs DH(ee) — our ephemeral × their ephemeral
  3. Encrypts our static public key under the derived key
  4. Performs DH(es) — our static × their ephemeral
  5. Encrypts the payload

  Returns `{updated_state, message_bytes}`.
  """
  @spec create_msg2(state(), binary()) :: {state(), binary()}
  def create_msg2(state, payload \\ <<>>) do
    # Generate ephemeral keypair
    {e_pub, e_priv} = Crypto.generate_keypair()

    # Mix our ephemeral into h
    h = Crypto.hash(state.h <> e_pub)

    # ee: DH(our ephemeral, their ephemeral)
    ee_shared = Crypto.dh(state.re, e_priv)
    {ck, k} = Crypto.hkdf_noise(state.ck, ee_shared)

    # Encrypt our static public key (nonce=0 for first use of this key)
    nonce_s = nonce_from_counter(0)
    {ct_s, tag_s} = Crypto.encrypt(k, nonce_s, state.s_pub, h)
    encrypted_s = ct_s <> tag_s

    # Mix encrypted static into h
    h = Crypto.hash(h <> encrypted_s)

    # es: DH(our static, their ephemeral — note: responder uses s, remote e)
    es_shared = Crypto.dh(state.re, state.s_priv)
    {ck, k} = Crypto.hkdf_noise(ck, es_shared)

    # Encrypt payload (nonce resets to 0 after HKDF derives new key)
    nonce_p = nonce_from_counter(0)
    {ct_p, tag_p} = Crypto.encrypt(k, nonce_p, payload, h)
    encrypted_payload = ct_p <> tag_p

    h = Crypto.hash(h <> encrypted_payload)

    msg = e_pub <> encrypted_s <> encrypted_payload

    new_state = %{
      state
      | e_pub: e_pub,
        e_priv: e_priv,
        h: h,
        ck: ck,
        k: k,
        n: 1,
        phase: :sent_msg2
    }

    {new_state, msg}
  end

  @doc """
  Responder processes Message 3: → s, se

  Decrypts the initiator's static key, performs DH(se),
  decrypts the payload. After this, the handshake is complete.

  Returns `{updated_state, payload}` or `{:error, reason}`.

  The remote static key (`rs`) is the initiator's long-term identity —
  this is what gets checked against ZTLP-NS for authorization.
  """
  @spec handle_msg3(state(), binary()) :: {state(), binary()} | {:error, atom()}
  def handle_msg3(state, message) do
    # Message 3 format: encrypted_s (32 + 16 = 48 bytes) + encrypted_payload
    case message do
      <<encrypted_s::binary-size(48), encrypted_payload::binary>> ->
        ct_s = binary_part(encrypted_s, 0, 32)
        tag_s = binary_part(encrypted_s, 32, 16)
        nonce_s = nonce_from_counter(state.n)

        case Crypto.decrypt(state.k, nonce_s, ct_s, state.h, tag_s) do
          :error ->
            {:error, :decrypt_static_failed}

          rs ->
            # Mix encrypted static into h
            h = Crypto.hash(state.h <> encrypted_s)

            # se: DH(our ephemeral, their static)
            # Note: responder uses e_priv with remote's static
            se_shared = Crypto.dh(rs, state.e_priv)
            {ck, k} = Crypto.hkdf_noise(state.ck, se_shared)

            # Decrypt payload (nonce=0 after fresh HKDF key derivation)
            if byte_size(encrypted_payload) >= 16 do
              payload_ct = binary_part(encrypted_payload, 0, byte_size(encrypted_payload) - 16)
              payload_tag = binary_part(encrypted_payload, byte_size(encrypted_payload) - 16, 16)
              nonce_p = nonce_from_counter(0)

              case Crypto.decrypt(k, nonce_p, payload_ct, h, payload_tag) do
                :error ->
                  {:error, :decrypt_payload_failed}

                payload ->
                  h = Crypto.hash(h <> encrypted_payload)

                  new_state = %{state | h: h, ck: ck, k: k, n: 1, rs: rs, phase: :complete}

                  {new_state, payload}
              end
            else
              # Empty payload — just tag bytes
              nonce_p = nonce_from_counter(0)

              case Crypto.decrypt(k, nonce_p, <<>>, h, encrypted_payload) do
                :error ->
                  {:error, :decrypt_payload_failed}

                payload ->
                  h = Crypto.hash(h <> encrypted_payload)
                  new_state = %{state | h: h, ck: ck, k: k, n: 1, rs: rs, phase: :complete}

                  {new_state, payload}
              end
            end
        end

      _ ->
        {:error, :msg3_too_short}
    end
  end

  # ---------------------------------------------------------------------------
  # Transport Key Derivation
  # ---------------------------------------------------------------------------

  @doc """
  Derive transport keys after handshake completion.

  When `session_id` is provided, uses ZTLP's custom BLAKE2s-based key derivation
  (matching the Rust client's `handshake.rs finalize()`): sorted public keys +
  directional labels + session_id → BLAKE2s-256. Without session_id, falls back
  to standard Noise Split (HKDF from chaining key).

  The responder uses `i2r_key` to decrypt incoming data and
  `r2i_key` to encrypt outgoing data.

  Must only be called after `phase == :complete`.
  """
  def split(state, session_id \\ nil)

  def split(%{phase: :complete, s_pub: our_pub, rs: remote_pub} = _state, session_id)
      when is_binary(session_id) do
    # ZTLP custom key derivation (must match Rust handshake.rs finalize):
    # Sort public keys lexicographically, then BLAKE2s-256 with directional labels
    shared_material =
      if our_pub <= remote_pub do
        our_pub <> remote_pub
      else
        remote_pub <> our_pub
      end

    i2r_key = :crypto.hash(:blake2s, shared_material <> "ztlp_initiator_to_responder" <> session_id)
    r2i_key = :crypto.hash(:blake2s, shared_material <> "ztlp_responder_to_initiator" <> session_id)

    {:ok, %{i2r_key: i2r_key, r2i_key: r2i_key}}
  end

  def split(%{phase: :complete, ck: ck}, _session_id) do
    # Standard Noise Split: HKDF(ck, <<>>) → two transport keys
    {i2r_key, r2i_key} = Crypto.hkdf_noise(ck, <<>>)

    {:ok, %{i2r_key: i2r_key, r2i_key: r2i_key}}
  end

  def split(_state, _session_id), do: {:error, :handshake_incomplete}

  # ---------------------------------------------------------------------------
  # Internal helpers
  # ---------------------------------------------------------------------------

  # Convert a counter to a 12-byte (96-bit) nonce for ChaCha20-Poly1305.
  # The Noise spec uses a 64-bit counter in little-endian, left-padded with 4 zero bytes.
  @spec nonce_from_counter(non_neg_integer()) :: <<_::96>>
  defp nonce_from_counter(n) do
    <<0::32, n::little-64>>
  end
end
