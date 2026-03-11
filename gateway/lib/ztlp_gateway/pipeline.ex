defmodule ZtlpGateway.Pipeline do
  @moduledoc """
  Three-layer admission pipeline for the ZTLP Gateway.

  Mirrors the relay's pipeline but with a critical difference:
  the gateway CAN perform Layer 3 (HeaderAuthTag AEAD verification)
  because it holds session keys.

  ## Layer 1 — Magic Byte Check (O(1), nanoseconds)

  Verifies the first two bytes are `0x5A37`. Rejects non-ZTLP traffic
  immediately — the cheapest possible filter.

  ## Layer 2 — SessionID Lookup (O(1), microseconds)

  Checks the SessionID (bytes 4-19) against the session registry.
  Allows packets for known sessions and HELLO packets (zero SessionID)
  through. Rejects unknown SessionIDs.

  ## Layer 3 — HeaderAuthTag Verification (O(1), microseconds)

  For established sessions, verifies the header authentication tag
  using the session's derived keys. This proves the packet was sent
  by the handshake peer (not spoofed).

  Only applies to data packets. Handshake packets are authenticated
  by the Noise framework itself.

  ## Pipeline Order

  The layers are ordered cheapest-first. Most garbage traffic is
  rejected at Layer 1 (two byte comparisons) before any state
  lookup occurs.
  """

  alias ZtlpGateway.{Packet, SessionRegistry}

  # ---------------------------------------------------------------------------
  # Types
  # ---------------------------------------------------------------------------

  @type admission_result ::
          {:ok, :new_session}
          | {:ok, :known_session, pid()}
          | {:reject, :bad_magic}
          | {:reject, :unknown_session}
          | {:reject, :truncated}

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Run a packet through the admission pipeline.

  Returns:
  - `{:ok, :new_session}` — HELLO packet, caller should create a new session
  - `{:ok, :known_session, pid}` — routed to existing session
  - `{:reject, reason}` — packet rejected

  Layer 3 is NOT checked here — it's the Session's responsibility
  since only the Session holds the encryption keys.
  """
  @spec admit(binary()) :: admission_result()
  def admit(packet) do
    with :ok <- layer1_magic(packet),
         result <- layer2_session(packet) do
      result
    end
  end

  # ---------------------------------------------------------------------------
  # Layer 1 — Magic byte check
  # ---------------------------------------------------------------------------

  @doc """
  Layer 1: verify ZTLP magic bytes.

  Cost: 2 byte comparisons, nanoseconds.
  """
  @spec layer1_magic(binary()) :: :ok | {:reject, :bad_magic}
  def layer1_magic(<<0x5A, 0x37, _rest::binary>>), do: :ok
  def layer1_magic(_), do: {:reject, :bad_magic}

  # ---------------------------------------------------------------------------
  # Layer 2 — SessionID lookup
  # ---------------------------------------------------------------------------

  @doc """
  Layer 2: look up SessionID in the session registry.

  HELLO packets (zero SessionID + handshake type) are allowed through
  as new session requests. All other packets must match a registered session.
  """
  @spec layer2_session(binary()) :: admission_result()
  def layer2_session(packet) do
    if Packet.hello?(packet) do
      {:ok, :new_session}
    else
      case Packet.extract_session_id(packet) do
        {:ok, session_id} ->
          case SessionRegistry.lookup(session_id) do
            {:ok, pid} -> {:ok, :known_session, pid}
            :error -> {:reject, :unknown_session}
          end

        :error ->
          {:reject, :truncated}
      end
    end
  end
end
