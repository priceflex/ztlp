defmodule ZtlpNs.Zone do
  @moduledoc """
  Represents a ZTLP-NS zone — a namespace delegation boundary.

  Zones in ZTLP-NS work like DNS zones: they define a portion of the
  namespace tree that is managed by a single authority. For example:

  ```
  ztlp                          ← root zone
  ├── example.ztlp              ← operator zone
  │   ├── acme.example.ztlp     ← tenant zone
  │   │   ├── node1.acme.example.ztlp  ← node record
  │   │   └── rdp.acme.example.ztlp    ← service record
  ```

  Each zone has:
  - A name (the zone's apex, e.g., "example.ztlp")
  - An authority keypair (the zone authority signs all records in the zone)
  - An optional parent zone (for trust chain verification)

  ## Name Resolution

  Names are hierarchical, dot-separated, read right-to-left:
  - "node1.office.acme.ztlp" belongs to zone "acme.ztlp"
  - "acme.ztlp" belongs to zone "ztlp" (root)
  - The root zone "ztlp" is the trust anchor

  To find which zone a name belongs to, strip labels from the left until
  you find a registered zone.
  """

  @type t :: %__MODULE__{
          name: String.t(),
          public_key: binary() | nil,
          parent_name: String.t() | nil
        }

  defstruct [:name, :public_key, :parent_name]

  @doc """
  Create a new zone.

  ## Parameters
  - `name` — the zone's apex name (e.g., "example.ztlp")
  - `public_key` — the zone authority's Ed25519 public key
  - `parent_name` — the parent zone's name (nil for root zones)
  """
  @spec new(String.t(), binary(), String.t() | nil) :: t()
  def new(name, public_key, parent_name \\ nil) do
    %__MODULE__{name: name, public_key: public_key, parent_name: parent_name}
  end

  @doc """
  Extract the parent zone name from a dotted name.

  "node1.office.acme.ztlp" → "office.acme.ztlp"
  "acme.ztlp" → "ztlp"
  "ztlp" → nil (root)
  """
  @spec parent_name(String.t()) :: String.t() | nil
  def parent_name(name) do
    case String.split(name, ".", parts: 2) do
      [_single] -> nil
      [_head, rest] -> rest
    end
  end

  @doc """
  Check if a record name falls within this zone.

  A name belongs to a zone if it equals the zone name or ends with
  "." followed by the zone name.

  ## Examples

      iex> zone = ZtlpNs.Zone.new("acme.ztlp", <<>>, "ztlp")
      iex> ZtlpNs.Zone.contains?(zone, "node1.acme.ztlp")
      true
      iex> ZtlpNs.Zone.contains?(zone, "other.ztlp")
      false
  """
  @spec contains?(t(), String.t()) :: boolean()
  def contains?(%__MODULE__{name: zone_name}, record_name) do
    record_name == zone_name or String.ends_with?(record_name, "." <> zone_name)
  end
end
