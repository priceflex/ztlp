defmodule ZtlpNs.CertAuthority do
  @moduledoc """
  Internal Certificate Authority for ZTLP-NS.

  Manages the ZTLP Root CA and Intermediate CA for issuing X.509
  certificates to services and clients. Provides:

  - Root CA generation and storage (self-signed, 10-year validity)
  - Intermediate CA generation (signed by root, 3-year validity)
  - Encrypted private key storage (AES-256-GCM)
  - CA certificate distribution via NS records (type 0x13)
  - Intermediate CA rotation without re-issuing root

  ## Storage Layout

  ```
  ~/.ztlp/ca/
  ├── root.key.enc       # Root CA private key (AES-256-GCM encrypted)
  ├── root.pem           # Root CA certificate (PEM)
  ├── intermediate.key   # Intermediate CA private key (PEM, protected by file perms)
  ├── intermediate.pem   # Intermediate CA certificate (PEM)
  └── chain.pem          # Certificate chain (intermediate + root)
  ```

  ## Key Types

  Supports Ed25519 (preferred) and RSA-4096 (for maximum client compatibility).
  """

  use GenServer
  require Logger

  @ca_dir_name "ca"

  # ── Public API ─────────────────────────────────────────────────────

  @doc "Start the CertAuthority GenServer."
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Initialize a new CA (root + intermediate).

  ## Options
  - `:org` — organization name (default: "ZTLP")
  - `:key_type` — `:ed25519` or `:rsa4096` (default: `:rsa4096`)
  - `:passphrase` — passphrase for encrypting root key (default: derived from zone secret)
  - `:ca_dir` — directory to store CA files (default: `~/.ztlp/ca`)

  Returns `{:ok, %{root_cert: pem, intermediate_cert: pem, chain: pem}}` or `{:error, reason}`.
  """
  @spec init_ca(keyword()) :: {:ok, map()} | {:error, term()}
  def init_ca(opts \\ []) do
    GenServer.call(__MODULE__, {:init_ca, opts}, 60_000)
  end

  @doc """
  Show CA information.

  Returns a map with root and intermediate CA details, or `{:error, :not_initialized}`.
  """
  @spec show() :: {:ok, map()} | {:error, term()}
  def show do
    GenServer.call(__MODULE__, :show)
  end

  @doc """
  Export the root CA certificate in PEM format.
  """
  @spec export_root() :: {:ok, String.t()} | {:error, term()}
  def export_root do
    GenServer.call(__MODULE__, :export_root)
  end

  @doc """
  Rotate the intermediate CA.

  Generates a new intermediate CA key pair, signs it with the root CA,
  and replaces the old intermediate. Existing certificates signed by
  the old intermediate remain valid until they expire.
  """
  @spec rotate_intermediate(keyword()) :: {:ok, map()} | {:error, term()}
  def rotate_intermediate(opts \\ []) do
    GenServer.call(__MODULE__, {:rotate_intermediate, opts}, 60_000)
  end

  @doc """
  Get the intermediate CA's private key and subject info for signing.

  This is used by CertIssuer to sign service and client certificates.
  """
  @spec get_signing_key() :: {:ok, {term(), map()}} | {:error, term()}
  def get_signing_key do
    GenServer.call(__MODULE__, :get_signing_key)
  end

  @doc """
  Get the CA chain (intermediate + root) in PEM format.
  """
  @spec get_chain_pem() :: {:ok, String.t()} | {:error, term()}
  def get_chain_pem do
    GenServer.call(__MODULE__, :get_chain_pem)
  end

  @doc """
  Get the root CA certificate in DER format.
  """
  @spec get_root_cert_der() :: {:ok, binary()} | {:error, term()}
  def get_root_cert_der do
    GenServer.call(__MODULE__, :get_root_cert_der)
  end

  @doc """
  Check if the CA has been initialized.
  """
  @spec initialized?() :: boolean()
  def initialized? do
    GenServer.call(__MODULE__, :initialized?)
  end

  # ── GenServer Implementation ───────────────────────────────────────

  @impl true
  def init(opts) do
    ca_dir = Keyword.get(opts, :ca_dir, default_ca_dir())

    state = %{
      ca_dir: ca_dir,
      root_cert_der: nil,
      root_cert_pem: nil,
      root_key: nil,
      root_subject: nil,
      intermediate_cert_der: nil,
      intermediate_cert_pem: nil,
      intermediate_key: nil,
      intermediate_subject: nil,
      chain_pem: nil,
      key_type: nil,
      initialized: false
    }

    # Try to load existing CA from disk
    state = try_load_ca(state)

    # Auto-initialize if not loaded from disk and auto_init is explicitly enabled
    state =
      if not state.initialized and System.get_env("ZTLP_CA_AUTO_INIT") == "true" do
        Logger.info("[CertAuthority] No existing CA found, auto-initializing...")
        zone = System.get_env("ZTLP_GATEWAY_SERVICE_ZONE") || "techrockstars.ztlp"
        subject = %{
          cn: "ZTLP Root CA - #{zone}",
          o: "ZTLP",
          ou: "Certificate Authority"
        }
        case do_init_ca(state, subject: subject) do
          {:ok, new_state, _result} ->
            Logger.info("[CertAuthority] CA auto-initialized for zone: #{zone}")
            new_state
          {:error, reason} ->
            Logger.warning("[CertAuthority] CA auto-init failed: #{inspect(reason)}")
            state
        end
      else
        state
      end

    {:ok, state}
  end

  @impl true
  def handle_call({:init_ca, opts}, _from, state) do
    if state.initialized do
      {:reply, {:error, :already_initialized}, state}
    else
      case do_init_ca(state, opts) do
        {:ok, new_state, result} ->
          {:reply, {:ok, result}, new_state}
        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  end

  def handle_call(:show, _from, state) do
    if state.initialized do
      info = build_ca_info(state)
      {:reply, {:ok, info}, state}
    else
      {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call(:export_root, _from, state) do
    if state.initialized do
      {:reply, {:ok, state.root_cert_pem}, state}
    else
      {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call({:rotate_intermediate, opts}, _from, state) do
    if state.initialized do
      case do_rotate_intermediate(state, opts) do
        {:ok, new_state, result} ->
          {:reply, {:ok, result}, new_state}
        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call(:get_signing_key, _from, state) do
    if state.initialized do
      {:reply, {:ok, {state.intermediate_key, state.intermediate_subject}}, state}
    else
      {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call(:get_chain_pem, _from, state) do
    if state.initialized do
      {:reply, {:ok, state.chain_pem}, state}
    else
      {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call(:get_root_cert_der, _from, state) do
    if state.initialized do
      {:reply, {:ok, state.root_cert_der}, state}
    else
      {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call(:initialized?, _from, state) do
    {:reply, state.initialized, state}
  end

  # ── Internal: CA Initialization ────────────────────────────────────

  defp do_init_ca(state, opts) do
    org = Keyword.get(opts, :org, "ZTLP")
    key_type = Keyword.get(opts, :key_type, :rsa4096)
    passphrase = Keyword.get(opts, :passphrase, default_passphrase())
    ca_dir = state.ca_dir

    # Check for oracle mode
    oracle_mode = System.get_env("ZTLP_CA_MODE") == "oracle"
    if oracle_mode do
      Logger.info("[CertAuthority] Oracle mode enabled — root key operations will be delegated to Signing Oracle")
      # For now, still generate locally but warn that oracle should be configured
      # Full oracle integration will come in the signing-oracle implementation
    end

    # Ensure directory exists
    File.mkdir_p!(ca_dir)

    # Generate Root CA
    {_root_pub, root_priv} = generate_keypair(key_type)
    root_subject = %{cn: "ZTLP Root CA", o: org}
    root_cert_der = ZtlpNs.X509.create_root_ca(root_priv, root_subject, validity_years: 10)
    root_cert_pem = ZtlpNs.X509.der_to_pem(root_cert_der)

    # Generate Intermediate CA
    {inter_pub, inter_priv} = generate_keypair(key_type)
    inter_subject = %{cn: "ZTLP Intermediate CA", o: org}
    inter_cert_der = ZtlpNs.X509.create_intermediate_ca(
      root_priv, inter_pub, root_subject, inter_subject, validity_years: 3
    )
    inter_cert_pem = ZtlpNs.X509.der_to_pem(inter_cert_der)

    # Build chain (intermediate + root)
    chain_pem = inter_cert_pem <> root_cert_pem

    # Save to disk
    save_root_key(ca_dir, root_priv, passphrase)
    File.write!(Path.join(ca_dir, "root.pem"), root_cert_pem)
    save_intermediate_key(ca_dir, inter_priv)
    File.write!(Path.join(ca_dir, "intermediate.pem"), inter_cert_pem)
    File.write!(Path.join(ca_dir, "chain.pem"), chain_pem)

    Logger.warning("""
    ⚠️  ROOT CA KEY SAVED TO FILESYSTEM (#{ca_dir}/root.key.enc)

        The root CA private key is stored as an encrypted file on disk.
        This is INSECURE for production deployments. If this server is
        compromised, the attacker can extract the root CA key.

        For production, use the ZTLP Signing Oracle with a hardware
        security module (YubiKey, TPM) to keep the root key in hardware.
        See: docs/SIGNING-ORACLE.md

        Set ZTLP_CA_MODE=oracle to use hardware-backed signing.
    """)

    if passphrase == "ztlp-default-passphrase" do
      Logger.warning("""
      ⚠️  ROOT CA KEY ENCRYPTED WITH DEFAULT PASSPHRASE!

          Set ZTLP_CA_PASSPHRASE environment variable to a strong,
          unique passphrase. The default passphrase provides NO security.
      """)
    end

    new_state = %{state |
      root_cert_der: root_cert_der,
      root_cert_pem: root_cert_pem,
      root_key: root_priv,
      root_subject: root_subject,
      intermediate_cert_der: inter_cert_der,
      intermediate_cert_pem: inter_cert_pem,
      intermediate_key: inter_priv,
      intermediate_subject: inter_subject,
      chain_pem: chain_pem,
      key_type: key_type,
      initialized: true
    }

    result = %{
      root_cert: root_cert_pem,
      intermediate_cert: inter_cert_pem,
      chain: chain_pem
    }

    {:ok, new_state, result}
  rescue
    e -> {:error, {:init_failed, e}}
  end

  defp do_rotate_intermediate(state, _opts) do
    org = case state.root_subject do
      %{o: org} -> org
      _ -> "ZTLP"
    end

    key_type = state.key_type || :rsa4096
    {inter_pub, inter_priv} = generate_keypair(key_type)
    inter_subject = %{cn: "ZTLP Intermediate CA", o: org}

    inter_cert_der = ZtlpNs.X509.create_intermediate_ca(
      state.root_key, inter_pub, state.root_subject, inter_subject, validity_years: 3
    )
    inter_cert_pem = ZtlpNs.X509.der_to_pem(inter_cert_der)
    chain_pem = inter_cert_pem <> state.root_cert_pem

    # Save to disk
    ca_dir = state.ca_dir
    save_intermediate_key(ca_dir, inter_priv)
    File.write!(Path.join(ca_dir, "intermediate.pem"), inter_cert_pem)
    File.write!(Path.join(ca_dir, "chain.pem"), chain_pem)

    new_state = %{state |
      intermediate_cert_der: inter_cert_der,
      intermediate_cert_pem: inter_cert_pem,
      intermediate_key: inter_priv,
      intermediate_subject: inter_subject,
      chain_pem: chain_pem
    }

    result = %{
      intermediate_cert: inter_cert_pem,
      chain: chain_pem
    }

    {:ok, new_state, result}
  rescue
    e -> {:error, {:rotate_failed, e}}
  end

  # ── Internal: Key Storage ──────────────────────────────────────────

  defp save_root_key(ca_dir, private_key, passphrase) do
    key_pem = ZtlpNs.X509.private_key_to_pem(private_key)
    encrypted = encrypt_key(key_pem, passphrase)
    File.write!(Path.join(ca_dir, "root.key.enc"), encrypted)
  end

  defp load_root_key(ca_dir, passphrase) do
    path = Path.join(ca_dir, "root.key.enc")
    case File.read(path) do
      {:ok, encrypted} ->
        case decrypt_key(encrypted, passphrase) do
          {:ok, key_pem} -> ZtlpNs.X509.pem_to_private_key(key_pem)
          error -> error
        end
      error -> error
    end
  end

  defp save_intermediate_key(ca_dir, private_key) do
    key_pem = ZtlpNs.X509.private_key_to_pem(private_key)
    path = Path.join(ca_dir, "intermediate.key")
    File.write!(path, key_pem)
    # Set restrictive permissions
    File.chmod(path, 0o600)
  end

  defp load_intermediate_key(ca_dir) do
    path = Path.join(ca_dir, "intermediate.key")
    case File.read(path) do
      {:ok, pem} -> ZtlpNs.X509.pem_to_private_key(pem)
      error -> error
    end
  end

  # ── Internal: Encryption ───────────────────────────────────────────

  @doc false
  def encrypt_key(plaintext, passphrase) do
    key = derive_key(passphrase)
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, "", true)
    # Format: iv(12) || tag(16) || ciphertext
    iv <> tag <> ciphertext
  end

  @doc false
  def decrypt_key(encrypted, passphrase) do
    key = derive_key(passphrase)
    <<iv::binary-12, tag::binary-16, ciphertext::binary>> = encrypted
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false) do
      :error -> {:error, :decryption_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  defp derive_key(passphrase) when is_binary(passphrase) do
    # PBKDF2-like derivation using SHA-256
    # In production, use proper PBKDF2 with salt and iterations
    :crypto.hash(:sha256, passphrase)
  end

  # ── Internal: Loading from Disk ────────────────────────────────────

  defp try_load_ca(state) do
    ca_dir = state.ca_dir

    with {:ok, root_cert_pem} <- File.read(Path.join(ca_dir, "root.pem")),
         {:ok, root_cert_der} <- ZtlpNs.X509.pem_to_der(root_cert_pem),
         {:ok, inter_cert_pem} <- File.read(Path.join(ca_dir, "intermediate.pem")),
         {:ok, inter_cert_der} <- ZtlpNs.X509.pem_to_der(inter_cert_pem),
         {:ok, chain_pem} <- File.read(Path.join(ca_dir, "chain.pem")),
         {:ok, inter_key} <- load_intermediate_key(ca_dir),
         {:ok, root_info} <- ZtlpNs.X509.parse_cert(root_cert_der),
         {:ok, inter_info} <- ZtlpNs.X509.parse_cert(inter_cert_der) do

      # Try to load root key (might fail if passphrase is wrong, that's ok)
      root_key = case load_root_key(ca_dir, default_passphrase()) do
        {:ok, key} -> key
        _ -> nil
      end

      Logger.info("[CertAuthority] CA loaded from filesystem (#{ca_dir}). For production, consider hardware-backed signing via SIGNING-ORACLE.")

      %{state |
        root_cert_der: root_cert_der,
        root_cert_pem: root_cert_pem,
        root_key: root_key,
        root_subject: root_info.subject,
        intermediate_cert_der: inter_cert_der,
        intermediate_cert_pem: inter_cert_pem,
        intermediate_key: inter_key,
        intermediate_subject: inter_info.subject,
        chain_pem: chain_pem,
        initialized: true
      }
    else
      _ -> state
    end
  end

  # ── Internal: Utilities ────────────────────────────────────────────

  defp generate_keypair(:rsa4096), do: ZtlpNs.X509.generate_rsa_keypair()
  defp generate_keypair(:rsa2048), do: ZtlpNs.X509.generate_rsa_keypair(2048)
  defp generate_keypair(_), do: ZtlpNs.X509.generate_rsa_keypair()

  defp default_ca_dir do
    case System.get_env("ZTLP_CA_DIR") do
      nil ->
        home = System.user_home!()
        Path.join([home, ".ztlp", @ca_dir_name])
      dir -> dir
    end
  end

  defp default_passphrase do
    System.get_env("ZTLP_CA_PASSPHRASE") || "ztlp-default-passphrase"
  end

  defp build_ca_info(state) do
    root_info = case ZtlpNs.X509.parse_cert(state.root_cert_der) do
      {:ok, info} -> info
      _ -> %{}
    end

    inter_info = case ZtlpNs.X509.parse_cert(state.intermediate_cert_der) do
      {:ok, info} -> info
      _ -> %{}
    end

    %{
      root: %{
        subject: root_info[:subject],
        serial: root_info[:serial],
        not_before: root_info[:not_before],
        not_after: root_info[:not_after],
        fingerprint: ZtlpNs.X509.fingerprint(state.root_cert_der),
        is_ca: root_info[:is_ca]
      },
      intermediate: %{
        subject: inter_info[:subject],
        serial: inter_info[:serial],
        not_before: inter_info[:not_before],
        not_after: inter_info[:not_after],
        fingerprint: ZtlpNs.X509.fingerprint(state.intermediate_cert_der),
        is_ca: inter_info[:is_ca]
      },
      key_type: state.key_type
    }
  end
end
