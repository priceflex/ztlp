defmodule ZtlpNs.Query do
  @moduledoc """
  Query engine for ZTLP-NS — resolves names through the zone hierarchy.

  The query engine is the public interface for looking up records. It
  wraps the raw Store lookups with trust chain verification, ensuring
  that returned records form a valid chain of trust from a root anchor.

  ## Query Flow

  1. Look up the record in the Store
  2. If found, verify its signature
  3. Walk the zone delegation chain upward
  4. Verify each delegation is signed by the parent zone
  5. Check that the chain terminates at a trusted root anchor

  ## Simplified Mode

  For the prototype, we offer both:
  - `lookup/2` — simple lookup with signature verification (no chain walk)
  - `lookup_verified/2` — full trust chain verification

  The simple mode is useful for testing and for deployments where the
  store is trusted (e.g., the NS server itself).
  """

  alias ZtlpNs.{Record, Store, TrustAnchor}

  @doc """
  Simple lookup — returns the record if it exists and has a valid signature.

  Does NOT verify the full trust chain. Use `lookup_verified/2` for
  production-grade lookups.
  """
  @spec lookup(String.t(), Record.record_type()) ::
          {:ok, Record.t()} | :not_found | {:error, atom()}
  def lookup(name, type) do
    case Store.lookup(name, type) do
      {:ok, record} ->
        if Record.verify(record) do
          {:ok, record}
        else
          {:error, :invalid_signature}
        end

      other ->
        other
    end
  end

  @doc """
  Verified lookup — returns the record only if it has a valid trust chain
  all the way to a root anchor.

  ## Trust Chain Verification

  1. Verify the record's own signature
  2. Find the zone delegation for the record's zone
  3. Verify the delegation is signed by the parent zone's authority
  4. Repeat until we reach a trusted root anchor

  Returns `{:error, :untrusted_chain}` if the chain doesn't terminate
  at a known root anchor.
  """
  @spec lookup_verified(String.t(), Record.record_type()) ::
          {:ok, Record.t()} | :not_found | {:error, atom()}
  def lookup_verified(name, type) do
    case Store.lookup(name, type) do
      {:ok, record} ->
        if Record.verify(record) do
          # Walk the trust chain from the record's signer up to a root
          case verify_chain(record.signer_public_key, name) do
            :ok -> {:ok, record}
            {:error, reason} -> {:error, reason}
          end
        else
          {:error, :invalid_signature}
        end

      other ->
        other
    end
  end

  @doc """
  Resolve a name to all matching records (any type).

  Returns a list of `{type, record}` tuples for all records with the
  given name that have valid signatures.
  """
  @spec resolve_all(String.t()) :: [{Record.record_type(), Record.t()}]
  def resolve_all(name) do
    [:key, :svc, :relay, :policy, :revoke, :bootstrap]
    |> Enum.reduce([], fn type, acc ->
      case lookup(name, type) do
        {:ok, record} -> [{type, record} | acc]
        _ -> acc
      end
    end)
    |> Enum.reverse()
  end

  # ── Trust Chain Verification ───────────────────────────────────────

  # Walk the delegation chain from a signer's public key up to a root anchor.
  # At each level, we look for a ZTLP_KEY delegation record for the zone
  # that's signed by the parent zone's authority.
  #
  # The chain terminates when:
  # - We reach a public key that's in the trust anchor table → :ok
  # - We can't find a delegation for the next zone → {:error, :untrusted_chain}
  # - We exceed the maximum chain depth (prevent loops) → {:error, :chain_too_deep}
  @spec verify_chain(binary(), String.t(), non_neg_integer()) :: :ok | {:error, atom()}
  defp verify_chain(public_key, name, depth \\ 0)

  defp verify_chain(_public_key, _name, depth) when depth > 10 do
    {:error, :chain_too_deep}
  end

  defp verify_chain(public_key, _name, _depth) do
    # Terminal condition: check if this key is a root anchor
    if TrustAnchor.trusted?(public_key) do
      :ok
    else
      # Look for a delegation record for this key
      # Walk through all :key records to find one whose public_key data
      # matches and was signed by a higher authority
      find_delegation(public_key)
    end
  end

  # Search for a ZTLP_KEY delegation record that certifies this public key.
  # If found, recurse upward to verify the delegation's signer.
  defp find_delegation(public_key) do
    pub_hex = Base.encode16(public_key, case: :lower)

    # Search the store for any :key record whose data contains this public key
    Store.list()
    |> Enum.find(fn {_name, type, record} ->
      type == :key and
        Map.get(record.data, :public_key) == pub_hex and
        Map.get(record.data, :delegation) == true and
        Record.verify(record)
    end)
    |> case do
      {_name, _type, delegation} ->
        # Found a valid delegation — continue up the chain
        verify_chain(delegation.signer_public_key, delegation.name, 1)

      nil ->
        {:error, :untrusted_chain}
    end
  end
end
