defmodule ZtlpNs.EndpointAuth do
  @moduledoc """
  Ed25519 authentication for PEER_ENDPOINTS (0x0A) and PUNCH_REPORT
  (0x0C) endpoint-tracking requests.

  ## Background (irt-rwzo)

  The 0x0A and 0x0C UDP handlers accept a `requester_node_id`/`node_id`
  directly from the packet with zero authentication. Any UDP sender can
  claim to BE any node_id, and `ZtlpNs.Server` will happily associate
  the sender's source address (and any endpoints it claims) with that
  node_id in `ZtlpNs.EndpointStore` -- poisoning where future
  PUNCH_NOTIFY coordination gets sent for that victim node_id
  (endpoint-store poisoning / hole-punch hijack; CWE-284).

  The Rust client side (`proto/src/punch.rs`) was already fixed to send
  an Ed25519 signature + timestamp + verifying key alongside every
  PEER_ENDPOINTS/PUNCH_REPORT request (see `encode_peer_endpoints_request`
  and `encode_punch_report`). This module implements the NS-side half:
  verifying that signature AND deciding when a pubkey is allowed to
  speak for a given node_id.

  ## Why signature verification alone is not enough

  A signature over `node_id || timestamp` proves the sender controls
  the *signing key they supplied in the packet* -- it does NOT prove
  that key is the LEGITIMATE key for that node_id. Nothing stops an
  attacker from generating a fresh throwaway Ed25519 key and
  self-signing a false claim about a victim's real node_id. The
  signature check is necessary (rules out passive/blind spoofing where
  the attacker doesn't even control a valid keypair) but not sufficient
  on its own.

  ## Policy: strict-if-registered, TOFU otherwise

  1. **If a KEY or DEVICE record already exists** binding this node_id
     to a registered public key (via the normal, already-authenticated
     0x09 registration path -- Ed25519-signed, zone-authorized), the
     claimed pubkey in this endpoint request MUST match the registered
     one exactly. Any mismatch is rejected -- this is the case that
     actually matters: it stops an attacker from hijacking a REAL,
     already-enrolled node's hole-punch coordination.

  2. **If no such record exists yet** (the node hasn't completed
     enrollment/registration, but wants to start NAT-punching in
     parallel -- a real, supported flow in this codebase), NS pins the
     first pubkey it sees for that node_id in a small in-memory table
     (Trust-On-First-Use, like SSH host keys). Subsequent claims for
     the same node_id must use the same pinned key; a mismatch is
     rejected. This doesn't cryptographically prove the FIRST claimant
     was legitimate, but it closes the practical race window and
     prevents a second attacker from later hijacking a
     pre-registration node's coordination out from under the real
     owner, without blocking the documented parallel enroll+punch flow.

  Pins are soft state (ETS, not Mnesia) -- they exist only to prevent
  mid-flight hijacking during a punch session, not as a durable trust
  anchor. They expire independently of any TTL here; a restart clears
  them, which is fine because a genuinely enrolled node re-pins itself
  (or better, graduates to the strict registered-record path) on its
  next request.
  """

  require Logger
  alias ZtlpNs.{Crypto, Record, Store}

  @pin_table :ztlp_ns_endpoint_auth_pins

  # How far the claimed timestamp may drift from NS's clock (replay
  # protection). Generous enough for real clock skew across a WAN
  # deployment, tight enough that a captured packet can't be replayed
  # hours/days later to re-poison a node_id's endpoint entry.
  @max_skew_seconds 120

  @doc """
  Initialize the pin table. Called once at application startup,
  mirroring `ZtlpNs.RegistrationAuth.init_rate_limit/0`. No-op if the
  table already exists (e.g. tests that restart components).
  """
  @spec init() :: :ok
  def init do
    if :ets.whereis(@pin_table) == :undefined do
      :ets.new(@pin_table, [:named_table, :set, :public, write_concurrency: true])
    end

    :ok
  end

  @doc """
  Verify that `pubkey` is authorized to make endpoint claims for
  `node_id`, given a signature over `node_id || timestamp`.

  Returns `:ok` or `{:error, reason}` where reason is one of:
  `:stale_timestamp`, `:invalid_signature`, `:not_key_owner`,
  `:pubkey_mismatch`.
  """
  @spec verify_and_bind(binary(), non_neg_integer(), binary(), binary()) ::
          :ok | {:error, atom()}
  def verify_and_bind(node_id, timestamp, sig, pubkey)
      when is_binary(node_id) and byte_size(node_id) == 16 and is_integer(timestamp) and
             is_binary(sig) and is_binary(pubkey) do
    with :ok <- check_timestamp(timestamp),
         :ok <- check_signature(node_id, timestamp, sig, pubkey),
         :ok <- check_ownership(node_id, pubkey) do
      :ok
    end
  end

  def verify_and_bind(_node_id, _timestamp, _sig, _pubkey), do: {:error, :malformed}

  @doc """
  Clear all pins (used in tests).
  """
  @spec clear_pins() :: :ok
  def clear_pins do
    if :ets.whereis(@pin_table) != :undefined do
      :ets.delete_all_objects(@pin_table)
    end

    :ok
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp check_timestamp(timestamp) do
    now = System.system_time(:second)

    if abs(now - timestamp) <= @max_skew_seconds do
      :ok
    else
      {:error, :stale_timestamp}
    end
  end

  defp check_signature(node_id, timestamp, sig, pubkey) do
    message = <<node_id::binary-size(16), timestamp::unsigned-big-64>>

    if Crypto.verify(message, sig, pubkey) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  # Strict path: a KEY/DEVICE record already binds this node_id to a
  # registered pubkey -- the claimed pubkey MUST match it exactly.
  #
  # TOFU path: no such record exists yet -- pin the first pubkey seen
  # for this node_id, or verify against an existing pin.
  defp check_ownership(node_id, pubkey) do
    case find_registered_pubkey(node_id) do
      {:ok, registered_pubkey} ->
        if registered_pubkey == pubkey do
          :ok
        else
          {:error, :not_key_owner}
        end

      :not_registered ->
        check_or_set_pin(node_id, pubkey)
    end
  end

  defp check_or_set_pin(node_id, pubkey) do
    case :ets.lookup(@pin_table, node_id) do
      [{^node_id, ^pubkey}] ->
        :ok

      [{^node_id, _other_pubkey}] ->
        {:error, :pubkey_mismatch}

      [] ->
        # First claim for this node_id -- pin it (TOFU).
        :ets.insert_new(@pin_table, {node_id, pubkey})
        # insert_new races benignly: if another request won the race
        # with a DIFFERENT pubkey, re-check rather than silently
        # trusting our own losing insert.
        case :ets.lookup(@pin_table, node_id) do
          [{^node_id, ^pubkey}] -> :ok
          [{^node_id, _other}] -> {:error, :pubkey_mismatch}
        end
    end
  end

  # Scan KEY/DEVICE records for one whose data.node_id matches. Mirrors
  # the existing fallback_pubkey_scan pattern in ZtlpNs.Server -- O(n)
  # over the record store, acceptable here because this only runs on
  # the (rarer) pre-registration TOFU path once a node has no pin yet;
  # once pinned, subsequent requests hit the O(1) ETS pin table instead.
  defp find_registered_pubkey(node_id) do
    node_id_hex = Base.encode16(node_id, case: :lower)

    result =
      Store.list()
      |> Enum.find(fn {_name, type, record} ->
        type in [:key, :device] and record_node_id_hex(record) == node_id_hex
      end)

    case result do
      {_name, _type, record} ->
        case record_pubkey_hex(record) do
          nil -> :not_registered
          pubkey_hex -> {:ok, decode_pubkey_hex(pubkey_hex)}
        end

      nil ->
        :not_registered
    end
  end

  defp record_node_id_hex(%Record{data: data}) do
    value = Map.get(data, "node_id") || Map.get(data, :node_id)
    if is_binary(value), do: String.downcase(value), else: nil
  end

  defp record_pubkey_hex(%Record{data: data}) do
    Map.get(data, "public_key") || Map.get(data, :public_key)
  end

  defp decode_pubkey_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> bin
      :error -> <<>>
    end
  end
end
