defmodule ZtlpRelay.Pipeline do
  @moduledoc """
  Three-layer admission pipeline for the ZTLP relay.

  Processes inbound packets through three layers ordered by computational cost:

  1. **Layer 1 — Magic check** (nanoseconds, no crypto): Rejects non-ZTLP UDP noise.
  2. **Layer 2 — SessionID lookup** (microseconds, no crypto): Rejects unknown sessions.
  3. **Layer 3 — HeaderAuthTag verification** (real crypto cost): Rejects forged packets.

  Returns `{:pass, parsed_packet}` or `{:drop, layer, reason}`.
  Increments stats counters on each decision.
  """

  alias ZtlpRelay.{Packet, Crypto, SessionRegistry, Stats}

  @type admission_result ::
          {:pass, Packet.parsed_packet()}
          | {:drop, 1 | 2 | 3, atom()}

  @doc """
  Run the full three-layer admission pipeline on a raw packet.

  For Layer 3 (HeaderAuthTag verification), a `session_key` must be
  provided. If nil, Layer 3 is skipped (useful for relay-only mode
  where the relay doesn't have session keys).

  Returns `{:pass, parsed_packet}` or `{:drop, layer, reason}`.
  """
  @spec process(binary(), binary() | nil) :: admission_result()
  def process(data, session_key \\ nil) do
    with {:layer1, :ok} <- {:layer1, layer1_magic(data)},
         {:layer2, :ok} <- {:layer2, layer2_session(data)},
         {:layer3, :ok} <- {:layer3, layer3_auth(data, session_key)},
         {:parse, {:ok, parsed}} <- {:parse, Packet.parse(data)} do
      Stats.increment(:passed)
      {:pass, parsed}
    else
      {:layer1, {:drop, reason}} ->
        Stats.increment(:layer1_drops)
        {:drop, 1, reason}

      {:layer2, {:drop, reason}} ->
        Stats.increment(:layer2_drops)
        {:drop, 2, reason}

      {:layer3, {:drop, reason}} ->
        Stats.increment(:layer3_drops)
        {:drop, 3, reason}

      {:parse, {:error, reason}} ->
        # Packet passed all layers but failed to parse — shouldn't happen
        # but treat as layer 1 drop
        Stats.increment(:layer1_drops)
        {:drop, 1, reason}
    end
  end

  @doc """
  Layer 1: Magic byte check.

  Cost: single 16-bit comparison, nanoseconds, no crypto.
  """
  @spec layer1_magic(binary()) :: :ok | {:drop, atom()}
  def layer1_magic(data) do
    if Packet.valid_magic?(data) do
      :ok
    else
      {:drop, :invalid_magic}
    end
  end

  @doc """
  Layer 2: SessionID lookup in the ETS registry.

  Cost: O(1) hash lookup, microseconds, no crypto.
  HELLO/HELLO_ACK messages pass through (they establish sessions).
  """
  @spec layer2_session(binary()) :: :ok | {:drop, atom()}
  def layer2_session(data) do
    # HELLO and HELLO_ACK pass through Layer 2 (they establish sessions)
    if Packet.hello?(data) or Packet.hello_ack?(data) do
      :ok
    else
      case Packet.extract_session_id(data) do
        {:ok, session_id} ->
          if SessionRegistry.session_exists?(session_id) do
            :ok
          else
            {:drop, :unknown_session}
          end

        {:error, _} ->
          {:drop, :cannot_extract_session}
      end
    end
  end

  @doc """
  Layer 3: HeaderAuthTag AEAD verification.

  Cost: real cryptographic work (ChaCha20-Poly1305).
  Only reached by packets that passed Layers 1 and 2.

  If `session_key` is nil, this layer is skipped (relay mode).
  HELLO messages are also passed through since they have no session keys yet.
  """
  @spec layer3_auth(binary(), binary() | nil) :: :ok | {:drop, atom()}
  def layer3_auth(_data, nil), do: :ok

  def layer3_auth(data, session_key) when byte_size(session_key) == 32 do
    # HELLO has no session keys yet — skip auth check
    if Packet.hello?(data) do
      :ok
    else
      with {:ok, aad} <- Packet.extract_aad(data),
           {:ok, tag} <- Packet.extract_auth_tag(data) do
        if Crypto.verify_header_auth_tag(session_key, aad, tag) do
          :ok
        else
          {:drop, :invalid_auth_tag}
        end
      else
        {:error, _} -> {:drop, :cannot_extract_auth}
      end
    end
  end

  def layer3_auth(_data, _bad_key), do: {:drop, :invalid_key}
end
