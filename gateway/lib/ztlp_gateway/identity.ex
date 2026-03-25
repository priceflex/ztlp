defmodule ZtlpGateway.Identity do
  require Logger

  @moduledoc """
  Client identity extraction and verification.

  After the Noise_XX handshake completes, the gateway knows the client's
  static X25519 public key (`rs` in Noise terminology). This module maps
  that key to a ZTLP identity for policy evaluation.

  ## Identity Flow

  1. Handshake completes → `rs` (client's static pubkey) is known
  2. `resolve/1` maps the pubkey to a zone name or identity string
  3. `PolicyEngine.authorize?/2` checks if that identity can access the service

  ## Identity Resolution

  Resolution checks the local ETS cache first. On a cache miss, if the
  `NsClient` GenServer is running, it queries ZTLP-NS for a ZTLP_KEY
  record whose `data.public_key` matches the hex-encoded X25519 pubkey.
  Successful NS lookups are cached locally for subsequent requests.
  """

  @table :ztlp_gateway_identity_cache

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc """
  Initialize the identity cache.

  Called during application startup. Creates the ETS table used
  for local pubkey → identity mappings.
  """
  @spec init_cache() :: :ok
  def init_cache do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    end

    :ok
  end

  @doc """
  Register a pubkey → identity mapping in the local cache.

  ## Parameters
  - `pubkey` — X25519 static public key (32 bytes)
  - `identity` — zone name or identity string (e.g., "node1.example.ztlp")
  """
  @spec register(binary(), String.t()) :: :ok
  def register(pubkey, identity) when byte_size(pubkey) == 32 do
    :ets.insert(@table, {pubkey, identity})
    :ok
  end

  @doc """
  Resolve a public key to an identity string.

  Returns `{:ok, identity}` if the key is known, `:unknown` otherwise.

  Resolution flow:
  1. Check local ETS cache
  2. On cache miss, query ZTLP-NS via `NsClient` (if running)
  3. On NS hit, cache the identity locally and return it
  4. If NS is unreachable or returns not-found, return `:unknown`
  """
  @spec resolve(binary()) :: {:ok, String.t()} | :unknown
  def resolve(pubkey) when byte_size(pubkey) == 32 do
    case :ets.lookup(@table, pubkey) do
      [{^pubkey, identity}] ->
        {:ok, identity}

      [] ->
        # Cache miss — try NS lookup
        resolve_via_ns(pubkey)
    end
  end

  @doc """
  Resolve a public key, falling back to hex-encoding for unknown keys.

  This ensures the policy engine always gets a string to evaluate.
  Unknown keys get a hex representation like "unknown:aabbccdd..."
  which won't match any policy rule (fail-closed).
  """
  @spec resolve_or_hex(binary()) :: String.t()
  def resolve_or_hex(pubkey) when byte_size(pubkey) == 32 do
    case resolve(pubkey) do
      {:ok, identity} -> identity
      :unknown -> "unknown:" <> Base.encode16(pubkey, case: :lower)
    end
  end

  # ---------------------------------------------------------------------------
  # Private: NS-backed resolution
  # ---------------------------------------------------------------------------

  defp resolve_via_ns(pubkey) do
    # Only attempt NS lookup if NsClient is running
    case Process.whereis(ZtlpGateway.NsClient) do
      nil ->
        :unknown

      _pid ->
        # Use a short timeout (2s) to prevent session crashes when the NsClient
        # is overloaded by concurrent handshakes.  The default GenServer.call
        # timeout of 10s meant that 6+ simultaneous sessions would queue up in
        # the NsClient and later callers would crash with EXIT timeout,
        # killing the session before data exchange could begin.
        try do
          case ZtlpGateway.NsClient.query_key(pubkey, 2_000) do
            {:ok, record_map} ->
              identity = record_map.name
              :ets.insert(@table, {pubkey, identity})
              {:ok, identity}

            {:error, _reason} ->
              :unknown
          end
        catch
          :exit, {:timeout, _} ->
            Logger.debug("[Identity] NS lookup timed out, falling back to hex identity")
            :unknown
        end
    end
  end

  @doc "Clear the identity cache."
  @spec clear() :: :ok
  def clear do
    if :ets.whereis(@table) != :undefined do
      :ets.delete_all_objects(@table)
    end

    :ok
  end
end
