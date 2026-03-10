defmodule ZtlpNs.ZoneAuthority do
  @moduledoc """
  Zone authority management — handles zone delegation and trust chains.

  A zone authority is an entity that controls a zone in the ZTLP-NS
  namespace. It holds an Ed25519 keypair and can:

  1. **Sign records** within its zone
  2. **Delegate sub-zones** by signing a ZTLP_KEY record for the child
     zone's authority public key
  3. **Revoke** identities within its zone

  ## Trust Chain

  Trust flows from root → operator → tenant → node:

  ```
  Root Authority (trust anchor, hardcoded public key)
    signs → Operator Zone Authority key
      signs → Tenant Zone Authority key
        signs → Individual node/service records
  ```

  To verify any record, walk the chain upward:
  1. Verify the record's signature against the zone authority's public key
  2. Verify the zone authority's key is signed by the parent zone
  3. Continue until you reach a trusted root anchor

  ## Example

      root_auth = ZtlpNs.ZoneAuthority.generate("ztlp")
      operator_auth = ZtlpNs.ZoneAuthority.generate("example.ztlp")

      # Root delegates to operator by signing the operator's public key
      delegation = ZtlpNs.ZoneAuthority.delegate(root_auth, operator_auth)
  """

  alias ZtlpNs.{Crypto, Record, Zone}

  @type t :: %__MODULE__{
    zone: Zone.t(),
    public_key: Crypto.public_key(),
    private_key: Crypto.private_key()
  }

  defstruct [:zone, :public_key, :private_key]

  @doc """
  Generate a new zone authority with a fresh Ed25519 keypair.

  The zone's parent is inferred from the name (e.g., "acme.ztlp" → parent "ztlp").
  """
  @spec generate(String.t()) :: t()
  def generate(zone_name) do
    {pub, priv} = Crypto.generate_keypair()
    parent = Zone.parent_name(zone_name)

    %__MODULE__{
      zone: Zone.new(zone_name, pub, parent),
      public_key: pub,
      private_key: priv
    }
  end

  @doc """
  Sign a record using this zone authority's private key.

  The record must belong to this zone (its name must be within the
  zone's namespace). Returns `{:ok, signed_record}` or
  `{:error, :not_in_zone}`.
  """
  @spec sign_record(t(), Record.t()) :: {:ok, Record.t()} | {:error, :not_in_zone}
  def sign_record(%__MODULE__{zone: zone, private_key: priv}, %Record{} = record) do
    if Zone.contains?(zone, record.name) do
      {:ok, Record.sign(record, priv)}
    else
      {:error, :not_in_zone}
    end
  end

  @doc """
  Create a delegation record — the parent zone authority signs a
  ZTLP_KEY record binding the child zone's name to its public key.

  This is how trust chains are built: the root authority signs the
  operator's key, the operator signs the tenant's key, etc.

  Returns the signed delegation record.
  """
  @spec delegate(t(), t()) :: Record.t()
  def delegate(%__MODULE__{private_key: parent_priv}, %__MODULE__{zone: child_zone, public_key: child_pub}) do
    # A delegation is a ZTLP_KEY record for the child zone's authority.
    # The name is the child zone's name, and the "node_id" field contains
    # a special marker indicating this is a zone delegation, not a node key.
    delegation_record = %Record{
      name: child_zone.name,
      type: :key,
      data: %{
        node_id: "zone:" <> child_zone.name,
        public_key: Base.encode16(child_pub, case: :lower),
        algorithm: "Ed25519",
        delegation: true
      },
      created_at: System.system_time(:second),
      ttl: 86400 * 365,  # Zone delegations are long-lived (1 year)
      serial: 1
    }

    Record.sign(delegation_record, parent_priv)
  end

  @doc """
  Verify that a record was signed by a specific zone authority's public key.
  """
  @spec verify_record(Record.t(), Crypto.public_key()) :: boolean()
  def verify_record(%Record{signer_public_key: signer_pub} = record, expected_pub) do
    signer_pub == expected_pub and Record.verify(record)
  end
end
