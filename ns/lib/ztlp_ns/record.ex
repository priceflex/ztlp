defmodule ZtlpNs.Record do
  @moduledoc """
  ZTLP-NS Record — the fundamental data unit of the namespace.

  Every piece of information in ZTLP-NS is a signed record. Records are
  the namespace's equivalent of DNS resource records, but with mandatory
  cryptographic signatures. An unsigned record MUST be rejected — this is
  the core invariant that makes ZTLP-NS trustworthy.

  ## Record Structure

  Each record contains:
  - `name` — hierarchical dotted name (e.g., "node1.office.acme.ztlp")
  - `type` — one of the 6 record types (see below)
  - `data` — type-specific payload (map)
  - `signature` — Ed25519 signature over the canonical binary form
  - `signer_public_key` — the public key that produced the signature
  - `created_at` — Unix timestamp (seconds) when the record was created
  - `ttl` — time-to-live in seconds
  - `serial` — monotonically increasing version number

  ## Record Types

  - `:key` (ZTLP_KEY) — NodeID ↔ public key binding
  - `:svc` (ZTLP_SVC) — Service definition
  - `:relay` (ZTLP_RELAY) — Relay node endpoint info
  - `:policy` (ZTLP_POLICY) — Access control rules
  - `:revoke` (ZTLP_REVOKE) — Revocation notice
  - `:bootstrap` (ZTLP_BOOTSTRAP) — Signed relay list for discovery
  - `:operator` (ZTLP_OPERATOR) — Operator configuration

  ## Canonical Serialization

  Records are serialized to a deterministic binary format for signing.
  The signed bytes are: `type_byte ++ name_len ++ name ++ data_binary ++
  created_at(8 bytes) ++ ttl(4 bytes) ++ serial(8 bytes)`.

  We use CBOR (RFC 8949) with sorted keys for the data field to ensure
  identical maps always produce identical bytes — critical for signature
  verification.
  """

  @enforce_keys [:name, :type, :data, :created_at, :ttl, :serial]
  defstruct [:name, :type, :data, :signature, :signer_public_key, :created_at, :ttl, :serial]

  @type record_type :: :key | :svc | :relay | :policy | :revoke | :bootstrap | :operator | :device | :user | :group

  @type t :: %__MODULE__{
          name: String.t(),
          type: record_type(),
          data: map(),
          signature: binary() | nil,
          signer_public_key: binary() | nil,
          created_at: non_neg_integer(),
          ttl: non_neg_integer(),
          serial: non_neg_integer()
        }

  # ── Type byte mapping ──────────────────────────────────────────────
  # These byte values appear in both the wire format and the canonical
  # serialization. They MUST NOT change without a protocol version bump.
  # Types 0x10-0x12 are reserved for identity/group records (Phase 1+).

  @type_bytes %{key: 1, svc: 2, relay: 3, policy: 4, revoke: 5, bootstrap: 6, operator: 7, device: 0x10, user: 0x11, group: 0x12}
  @byte_types %{1 => :key, 2 => :svc, 3 => :relay, 4 => :policy, 5 => :revoke, 6 => :bootstrap, 7 => :operator, 0x10 => :device, 0x11 => :user, 0x12 => :group}

  @doc "Convert a record type atom to its wire format byte."
  @spec type_to_byte(record_type()) :: non_neg_integer()
  def type_to_byte(type), do: Map.fetch!(@type_bytes, type)

  @doc "Convert a wire format byte to a record type atom."
  @spec byte_to_type(non_neg_integer()) :: record_type()
  def byte_to_type(byte), do: Map.fetch!(@byte_types, byte)

  # ── Canonical Serialization ────────────────────────────────────────
  # This is the binary form that gets signed. It MUST be deterministic —
  # the same record MUST always produce the same bytes. This is why we
  # use CBOR with sorted keys (RFC 8949 §4.2).

  @doc """
  Serialize a record to its canonical binary form (for signing).

  The format is:
  ```
  <<type_byte::8, name_len::16, name::binary, data_len::32, data_binary::binary,
    created_at::64, ttl::32, serial::64>>
  ```

  This function produces the bytes that are signed/verified — it does NOT
  include the signature or signer_public_key fields (those are metadata
  about the signature, not part of the signed content).
  """
  @spec serialize(t()) :: binary()
  def serialize(%__MODULE__{} = record) do
    type_byte = type_to_byte(record.type)
    name_bin = record.name
    name_len = byte_size(name_bin)
    # CBOR with sorted keys ensures identical maps → identical bytes
    data_bin = ZtlpNs.Cbor.encode(record.data)
    data_len = byte_size(data_bin)

    <<type_byte::8, name_len::16, name_bin::binary, data_len::32, data_bin::binary,
      record.created_at::unsigned-big-64, record.ttl::unsigned-big-32,
      record.serial::unsigned-big-64>>
  end

  @doc """
  Deserialize a record from its canonical binary form.

  Returns `{:ok, record}` on success or `{:error, reason}` on failure.
  The returned record has `signature` and `signer_public_key` set to nil —
  those must be attached separately.
  """
  @spec deserialize(binary()) :: {:ok, t()} | {:error, atom()}
  def deserialize(
        <<type_byte::8, name_len::16, name::binary-size(name_len), data_len::32,
          data_bin::binary-size(data_len), created_at::unsigned-big-64, ttl::unsigned-big-32,
          serial::unsigned-big-64>>
      ) do
    type = byte_to_type(type_byte)
    # CBOR decode — returns string keys (no atom creation)
    {:ok, data} = ZtlpNs.Cbor.decode(data_bin)

    {:ok,
     %__MODULE__{
       name: name,
       type: type,
       data: data,
       signature: nil,
       signer_public_key: nil,
       created_at: created_at,
       ttl: ttl,
       serial: serial
     }}
  rescue
    _ -> {:error, :invalid_binary}
  end

  def deserialize(_), do: {:error, :invalid_binary}

  # ── Signing & Verification ────────────────────────────────────────

  @doc """
  Sign a record with an Ed25519 private key.

  Serializes the record to canonical binary, signs it, and attaches
  both the signature and the corresponding public key to the record.

  The public key is derived from the private key (OTP stores Ed25519
  private keys as `<<seed::32, public::32>>`), so we don't need a
  separate public key parameter.
  """
  @spec sign(t(), ZtlpNs.Crypto.private_key()) :: t()
  def sign(%__MODULE__{} = record, private_key) do
    canonical = serialize(record)
    signature = ZtlpNs.Crypto.sign(canonical, private_key)
    public_key = ZtlpNs.Crypto.public_key_from_private(private_key)

    %{record | signature: signature, signer_public_key: public_key}
  end

  @doc """
  Verify a record's Ed25519 signature.

  Returns `true` if the signature is valid for this record's canonical
  binary form, verified against the embedded `signer_public_key`.

  Returns `false` if:
  - The signature is nil (unsigned record)
  - The public key is nil
  - The signature doesn't match
  """
  @spec verify(t()) :: boolean()
  def verify(%__MODULE__{signature: nil}), do: false
  def verify(%__MODULE__{signer_public_key: nil}), do: false

  def verify(%__MODULE__{signature: sig, signer_public_key: pub} = record) do
    canonical = serialize(record)
    ZtlpNs.Crypto.verify(canonical, sig, pub)
  end

  # ── Wire Format Encoding ──────────────────────────────────────────
  # For UDP query responses, we need to send the full record including
  # signature. This is different from the canonical form (which excludes
  # signature for signing purposes).

  @doc """
  Encode a signed record for transmission over the wire.

  Format: `<<canonical_binary, sig_len::16, signature::binary, pub_len::16, public_key::binary>>`

  This includes the signature and public key, unlike `serialize/1` which
  only produces the signed content.
  """
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{signature: sig, signer_public_key: pub} = record)
      when not is_nil(sig) and not is_nil(pub) do
    canonical = serialize(record)
    sig_len = byte_size(sig)
    pub_len = byte_size(pub)

    <<canonical::binary, sig_len::16, sig::binary, pub_len::16, pub::binary>>
  end

  @doc """
  Decode a record from its wire format (including signature).

  Returns `{:ok, record}` on success or `{:error, reason}` on failure.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, atom()}
  def decode(data) when is_binary(data) do
    # Parse the canonical part first to find where signature starts
    <<type_byte::8, name_len::16, rest::binary>> = data
    <<name::binary-size(name_len), rest2::binary>> = rest
    <<data_len::32, rest3::binary>> = rest2
    <<data_bin::binary-size(data_len), rest4::binary>> = rest3

    <<created_at::unsigned-big-64, ttl::unsigned-big-32, serial::unsigned-big-64, rest5::binary>> =
      rest4

    # Now parse signature and public key
    <<sig_len::16, sig::binary-size(sig_len), pub_len::16, pub::binary-size(pub_len)>> = rest5

    type = byte_to_type(type_byte)
    {:ok, record_data} = ZtlpNs.Cbor.decode(data_bin)

    {:ok,
     %__MODULE__{
       name: name,
       type: type,
       data: record_data,
       signature: sig,
       signer_public_key: pub,
       created_at: created_at,
       ttl: ttl,
       serial: serial
     }}
  rescue
    _ -> {:error, :invalid_wire_format}
  end

  # ── Convenience Constructors ───────────────────────────────────────
  # These helpers create records with the right structure for each type.

  @doc "Create a ZTLP_KEY record (NodeID ↔ public key binding)."
  @spec new_key(String.t(), binary(), binary(), keyword()) :: t()
  def new_key(name, node_id, public_key, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :key,
      data: %{
        node_id: Base.encode16(node_id, case: :lower),
        public_key: Base.encode16(public_key, case: :lower),
        algorithm: "Ed25519"
      },
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 86400,
      serial: opts[:serial] || 1
    }
  end

  @doc "Create a ZTLP_SVC record (service definition)."
  @spec new_svc(String.t(), binary(), [binary()], String.t(), keyword()) :: t()
  def new_svc(name, service_id, allowed_node_ids, policy_ref, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :svc,
      data: %{
        service_id: Base.encode16(service_id, case: :lower),
        allowed_node_ids: Enum.map(allowed_node_ids, &Base.encode16(&1, case: :lower)),
        policy_ref: policy_ref
      },
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 86400,
      serial: opts[:serial] || 1
    }
  end

  @doc "Create a ZTLP_RELAY record (relay node endpoint info)."
  @spec new_relay(String.t(), binary(), [String.t()], non_neg_integer(), String.t(), keyword()) ::
          t()
  def new_relay(name, node_id, endpoints, capacity, region, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :relay,
      data: %{
        node_id: Base.encode16(node_id, case: :lower),
        endpoints: endpoints,
        capacity: capacity,
        region: region
      },
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 3600,
      serial: opts[:serial] || 1
    }
  end

  @doc "Create a ZTLP_POLICY record (access control rules)."
  @spec new_policy(String.t(), [binary()], [String.t()], [binary()], keyword()) :: t()
  def new_policy(name, allowed_node_ids, allowed_services, deny_node_ids, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :policy,
      data: %{
        allowed_node_ids: Enum.map(allowed_node_ids, &Base.encode16(&1, case: :lower)),
        allowed_services: allowed_services,
        deny_node_ids: Enum.map(deny_node_ids, &Base.encode16(&1, case: :lower))
      },
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 3600,
      serial: opts[:serial] || 1
    }
  end

  @doc "Create a ZTLP_REVOKE record (revocation notice)."
  @spec new_revoke(String.t(), [binary()], String.t(), String.t(), keyword()) :: t()
  def new_revoke(name, revoked_ids, reason, effective_at, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :revoke,
      data: %{
        revoked_ids: Enum.map(revoked_ids, &Base.encode16(&1, case: :lower)),
        reason: reason,
        effective_at: effective_at
      },
      created_at: opts[:created_at] || System.system_time(:second),
      # Revocations don't expire
      ttl: opts[:ttl] || 0,
      serial: opts[:serial] || 1
    }
  end

  @doc "Create a ZTLP_BOOTSTRAP record (signed relay list for initial discovery)."
  @spec new_bootstrap(String.t(), [map()], keyword()) :: t()
  def new_bootstrap(name, relays, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :bootstrap,
      data: %{relays: relays},
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 86400,
      serial: opts[:serial] || 1
    }
  end

  @doc """
  Create a ZTLP_DEVICE record (device identity bound to hardware/machine).

  Fields:
  - `name` — FQDN like "laptop-01.techrockstars.ztlp"
  - `node_id` — 128-bit hardware-bound identifier (16 bytes)
  - `pubkey` — X25519 device key (32 bytes, hex-encoded in data)
  - `opts` — keyword list with optional `:owner`, `:hardware_id`, `:created_at`, `:ttl`, `:serial`
  """
  @spec new_device(String.t(), binary(), binary(), keyword()) :: t()
  def new_device(name, node_id, pubkey, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :device,
      data: %{
        node_id: Base.encode16(node_id, case: :lower),
        public_key: Base.encode16(pubkey, case: :lower),
        owner: opts[:owner] || "",
        hardware_id: opts[:hardware_id] || ""
      },
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 86400,
      serial: opts[:serial] || 1
    }
  end

  @doc """
  Create a ZTLP_USER record (user identity bound to a person).

  Fields:
  - `name` — email-style FQDN like "steve@techrockstars.ztlp"
  - `pubkey` — Ed25519 user signing key (32 bytes, hex-encoded in data)
  - `opts` — keyword list with optional `:devices`, `:email`, `:role`, `:created_at`, `:ttl`, `:serial`

  Role values: "user" (default), "tech", "admin"
  """
  @spec new_user(String.t(), binary(), keyword()) :: t()
  def new_user(name, pubkey, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :user,
      data: %{
        public_key: Base.encode16(pubkey, case: :lower),
        devices: opts[:devices] || [],
        email: opts[:email] || "",
        role: opts[:role] || "user"
      },
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 86400,
      serial: opts[:serial] || 1
    }
  end

  @doc """
  Validate a DEVICE record's data fields.

  Returns `:ok` or `{:error, reason}`.
  """
  @spec validate_device(map()) :: :ok | {:error, atom()}
  def validate_device(data) do
    node_id = Map.get(data, :node_id) || Map.get(data, "node_id")
    pubkey = Map.get(data, :public_key) || Map.get(data, "public_key")

    cond do
      is_nil(node_id) or node_id == "" -> {:error, :missing_node_id}
      is_nil(pubkey) or pubkey == "" -> {:error, :missing_public_key}
      true -> :ok
    end
  end

  @doc """
  Validate a USER record's data fields.

  Returns `:ok` or `{:error, reason}`.
  """
  @spec validate_user(map()) :: :ok | {:error, atom()}
  def validate_user(data) do
    pubkey = Map.get(data, :public_key) || Map.get(data, "public_key")
    role = Map.get(data, :role) || Map.get(data, "role")

    cond do
      is_nil(pubkey) or pubkey == "" -> {:error, :missing_public_key}
      not is_nil(role) and role not in ["user", "tech", "admin"] -> {:error, :invalid_role}
      true -> :ok
    end
  end

  @doc """
  Create a ZTLP_GROUP record (group membership record).

  Fields:
  - `name` — group FQDN like "admins@techrockstars.ztlp"
  - `members` — list of user names (e.g., ["steve@techrockstars.ztlp"])
  - `opts` — keyword list with optional `:description`, `:created_at`, `:ttl`, `:serial`

  Groups can ONLY be created/modified by zone signing key (not self-registration).
  Nested groups are NOT supported — members must be user names, not group names.
  """
  @spec new_group(String.t(), [String.t()], keyword()) :: t()
  def new_group(name, members, opts \\ []) do
    %__MODULE__{
      name: name,
      type: :group,
      data: %{
        members: members,
        description: opts[:description] || ""
      },
      created_at: opts[:created_at] || System.system_time(:second),
      ttl: opts[:ttl] || 86400,
      serial: opts[:serial] || 1
    }
  end

  @doc """
  Validate a GROUP record's data fields.

  Returns `:ok` or `{:error, reason}`.
  """
  @spec validate_group(map()) :: :ok | {:error, atom()}
  def validate_group(data) do
    members = Map.get(data, :members) || Map.get(data, "members")

    cond do
      is_nil(members) -> {:error, :missing_members}
      not is_list(members) -> {:error, :invalid_members}
      length(members) > 255 -> {:error, :too_many_members}
      true -> :ok
    end
  end

  @doc """
  Check if a record has expired based on its created_at + ttl.

  A TTL of 0 means the record never expires (used for revocations).
  """
  @spec expired?(t()) :: boolean()
  def expired?(%__MODULE__{ttl: 0}), do: false

  def expired?(%__MODULE__{created_at: ca, ttl: ttl}) do
    System.system_time(:second) > ca + ttl
  end
end
