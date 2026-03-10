defmodule ZtlpNs.TrustAnchor do
  @moduledoc """
  Root trust anchor management for ZTLP-NS.

  Trust anchors are the foundation of the ZTLP-NS trust chain. They are
  Ed25519 public keys that are hardcoded into ZTLP implementations or
  configured at deployment time. Every trust chain terminates at one of
  these anchors.

  ## Trust Anchor Categories (from the spec)

  - **Public ZTLP Root** — maintained by the protocol governance body
  - **Enterprise Root** — self-hosted by organizations for private deployments
  - **Industry Roots** — sector-specific (healthcare, government, finance)

  A node MAY trust multiple roots simultaneously. This is critical for
  ZTLP's philosophy: "the protocol does not trust any single authority,
  including the one that published this specification."

  ## Implementation

  For the prototype, trust anchors are stored in an ETS table that is
  populated at startup. In production, the public root anchors would be
  compiled into the binary as constants.
  """

  use GenServer

  alias ZtlpNs.Crypto

  @table :ztlp_ns_trust_anchors

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(_args) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @doc """
  Add a trust anchor (root public key) with a label.

  Labels are human-readable identifiers like "public-ztlp-root" or
  "acme-enterprise-root". They're used for logging and debugging,
  not for trust decisions.
  """
  @spec add(String.t(), Crypto.public_key()) :: :ok
  def add(label, public_key) when is_binary(label) and is_binary(public_key) do
    :ets.insert(@table, {label, public_key})
    :ok
  end

  @doc """
  Check if a public key is a trusted root anchor.

  This is the terminal condition in trust chain verification:
  if we walk the delegation chain and reach a key that's in this
  table, the chain is valid.
  """
  @spec trusted?(Crypto.public_key()) :: boolean()
  def trusted?(public_key) when is_binary(public_key) do
    # Scan the table for any entry with this public key.
    # This is O(n) but the trust anchor table is tiny (< 10 entries).
    :ets.foldl(fn {_label, pk}, acc -> acc or pk == public_key end, false, @table)
  end

  @doc "List all trust anchors as `{label, public_key}` tuples."
  @spec list() :: [{String.t(), Crypto.public_key()}]
  def list do
    :ets.tab2list(@table)
  end

  @doc "Remove a trust anchor by label."
  @spec remove(String.t()) :: :ok
  def remove(label) when is_binary(label) do
    :ets.delete(@table, label)
    :ok
  end

  @doc "Remove all trust anchors."
  @spec clear() :: :ok
  def clear do
    :ets.delete_all_objects(@table)
    :ok
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(:ok) do
    # Create the trust anchor table. It's a :set keyed by label.
    # Public so other processes (Store, Query) can read directly
    # without going through the GenServer.
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    {:ok, %{}}
  end
end
