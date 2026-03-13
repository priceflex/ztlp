defmodule ZtlpNs.RegistrationAuth do
  @moduledoc """
  Zone authorization logic for ZTLP-NS registrations.

  Verifies that a registration request is authorized:

  1. **Signature verification** — The registrant must provide an Ed25519
     signature over the canonical record form, verified against their pubkey.

  2. **Zone authorization** — The registrant's pubkey must be authorized
     for the target zone. Three paths:
     - Zone authority key (direct zone ownership)
     - Delegated key (signed by zone authority)
     - Self-registration (node updating its own KEY/SVC record)

  3. **Revocation check** — The NodeID in the record data must not be
     revoked.

  ## Security Rationale

  Without registration auth, anyone can register any name in any zone.
  This module enforces that only authorized keys can write to a zone,
  preventing namespace squatting and identity spoofing.
  """

  alias ZtlpNs.{Record, Store, Zone}

  @doc """
  Verify an Ed25519 signature over the canonical form of a record.

  The canonical form is: type_byte + name + type + data (CBOR encoded),
  matching the format produced by `Record.serialize/1` but without
  timestamps (since the registrant doesn't set those).

  For registration, the canonical form signed by the client is:
  `<<type_byte::8, name_len::16, name::binary, data_binary::binary>>`

  Returns `:ok` or `{:error, :invalid_signature}`.
  """
  @spec verify_signature(binary(), binary(), binary()) :: :ok | {:error, :invalid_signature}
  def verify_signature(canonical, signature, pubkey) do
    if ZtlpNs.Crypto.verify(canonical, signature, pubkey) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  @doc """
  Build the canonical form that the registrant signs.

  This is the data portion of the registration message that the
  signature covers: type_byte + name + CBOR-encoded data.
  """
  @spec build_canonical(String.t(), atom(), binary()) :: binary()
  def build_canonical(name, type, data_bin) do
    type_byte = Record.type_to_byte(type)
    name_len = byte_size(name)
    <<type_byte::8, name_len::16, name::binary, data_bin::binary>>
  end

  @doc """
  Check if the registrant's pubkey is authorized for the target zone.

  Authorization paths (checked in order):
  1. **Zone authority** — pubkey matches a KEY record with `delegation: true`
     for the zone (or any parent zone up to root)
  2. **Self-registration** — for KEY/SVC records, the registrant's pubkey
     matches the `public_key` in the record data (node updating itself)

  Returns `:ok` or `{:error, reason}`.
  """
  @spec authorize(binary(), String.t(), atom(), map()) :: :ok | {:error, atom()}
  def authorize(pubkey, name, type, data) do
    pubkey_hex = Base.encode16(pubkey, case: :lower)

    # Path 1: Check if pubkey is a zone authority (delegation key) for this zone
    case check_zone_authority(pubkey_hex, name) do
      :ok ->
        :ok

      {:error, :not_zone_authority} ->
        # Path 2: Self-registration — node updating its own KEY or SVC record
        case check_self_registration(pubkey_hex, name, type, data) do
          :ok -> :ok
          {:error, _} -> {:error, :unauthorized}
        end
    end
  end

  @doc """
  Check if a NodeID from record data has been revoked.

  Extracts the node_id from the record data map and checks the
  revocation table. Returns `:ok` or `{:error, :revoked}`.
  """
  @spec check_revocation(map()) :: :ok | {:error, :revoked}
  def check_revocation(data) do
    node_id = Map.get(data, "node_id") || Map.get(data, :node_id)

    if node_id && Store.revoked?(node_id) do
      {:error, :revoked}
    else
      :ok
    end
  end

  # ── Private Helpers ────────────────────────────────────────────────

  # Check if pubkey_hex is a zone authority for the name's zone.
  # Walk up the zone hierarchy checking for delegation records.
  defp check_zone_authority(pubkey_hex, name) do
    # Try each zone level from the name's immediate zone up to root
    zone_names = zone_hierarchy(name)

    found =
      Enum.any?(zone_names, fn zone_name ->
        case Store.lookup(zone_name, :key) do
          {:ok, record} ->
            record_pubkey = Map.get(record.data, "public_key") || Map.get(record.data, :public_key)
            delegation = Map.get(record.data, "delegation") || Map.get(record.data, :delegation)
            record_pubkey == pubkey_hex and delegation == true

          _ ->
            false
        end
      end)

    if found, do: :ok, else: {:error, :not_zone_authority}
  end

  # Self-registration: for KEY records, the registrant's pubkey must match
  # the public_key field in the record data. For SVC records, the registrant
  # must own the corresponding KEY record for that name.
  defp check_self_registration(pubkey_hex, _name, :key, data) do
    record_pubkey = Map.get(data, "public_key") || Map.get(data, :public_key)

    if record_pubkey == pubkey_hex do
      :ok
    else
      {:error, :not_self_registration}
    end
  end

  defp check_self_registration(pubkey_hex, name, :svc, _data) do
    # For SVC records, check if the registrant owns the KEY record for this name
    case Store.lookup(name, :key) do
      {:ok, key_record} ->
        key_pubkey = Map.get(key_record.data, "public_key") || Map.get(key_record.data, :public_key)

        if key_pubkey == pubkey_hex do
          :ok
        else
          {:error, :not_key_owner}
        end

      _ ->
        {:error, :no_key_record}
    end
  end

  defp check_self_registration(_pubkey_hex, _name, _type, _data) do
    # Other record types require zone authority
    {:error, :zone_authority_required}
  end

  # Build the zone hierarchy for a name.
  # "node1.acme.example.ztlp" → ["acme.example.ztlp", "example.ztlp", "ztlp"]
  defp zone_hierarchy(name) do
    case Zone.parent_name(name) do
      nil -> [name]
      parent -> [parent | zone_hierarchy(parent)]
    end
  end
end
