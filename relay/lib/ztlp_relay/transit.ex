defmodule ZtlpRelay.Transit do
  @moduledoc """
  Transit relay behavior: only accepts pre-authenticated traffic.

  Transit relays sit between ingress and service relays in the mesh.
  They do not perform authentication — they only accept packets that:

  1. Belong to an existing session (SessionID found in the registry), OR
  2. Carry a valid Relay Admission Token (RAT) in the extension area

  If a packet has a valid RAT but no existing session, the transit relay
  establishes the session locally. Packets with neither a session nor a
  valid RAT are dropped.

  ## RAT in Extension Area

  For handshake packets, the RAT is embedded in the payload when `ext_len > 0`.
  The first `ext_len * 4` bytes of the payload are the extension area.
  The RAT (93 bytes) is placed at the start of the extension area.
  """

  alias ZtlpRelay.{AdmissionToken, Config, Packet, SessionRegistry}

  @rat_size 93

  @type sender :: {:inet.ip_address(), :inet.port_number()}

  @type accept_result ::
    {:accept, :existing_session}
    | {:accept, :new_session, binary()}
    | :drop

  @doc """
  Check if a packet should be accepted by the transit relay.

  ## Parameters

    - `packet` — parsed packet (handshake or data_compact)
    - `sender` — `{ip, port}` tuple

  ## Options

    - `:secret_key` — RAT verification key (default: from config)
    - `:secret_key_previous` — previous key for rotation (default: from config)

  ## Returns

    - `{:accept, :existing_session}` — packet belongs to a known session
    - `{:accept, :new_session, rat}` — packet has valid RAT, session created
    - `:drop` — no session, no valid RAT
  """
  @spec accept_packet?(Packet.parsed_packet(), sender(), keyword()) :: accept_result()
  def accept_packet?(packet, sender, opts \\ []) do
    session_id = packet.session_id

    if SessionRegistry.session_exists?(session_id) do
      {:accept, :existing_session}
    else
      # No existing session — check for RAT in extension area
      case extract_and_verify_rat(packet, opts) do
        {:ok, rat_binary} ->
          # Valid RAT — establish session locally
          establish_session(session_id, sender)
          {:accept, :new_session, rat_binary}

        :no_rat ->
          :drop
      end
    end
  end

  @doc """
  Extract a RAT from a handshake packet's extension area.

  The RAT is embedded in the first 93 bytes of the extension area when
  `ext_len > 0` and the extension area is large enough.
  """
  @spec extract_rat(Packet.parsed_packet()) :: {:ok, binary()} | :no_rat
  def extract_rat(%{type: :handshake, ext_len: ext_len, payload: payload})
      when ext_len > 0 do
    ext_area_size = ext_len * 4

    if ext_area_size >= @rat_size and byte_size(payload) >= @rat_size do
      <<rat::binary-size(@rat_size), _rest::binary>> = payload
      {:ok, rat}
    else
      :no_rat
    end
  end

  def extract_rat(_packet), do: :no_rat

  # Internal

  defp extract_and_verify_rat(packet, opts) do
    case extract_rat(packet) do
      {:ok, rat_binary} ->
        secret_key = Keyword.get(opts, :secret_key, Config.rat_secret())
        secret_previous = Keyword.get(opts, :secret_key_previous, Config.rat_secret_previous())

        case AdmissionToken.verify_with_rotation(rat_binary, secret_key, secret_previous) do
          {:ok, _fields} ->
            {:ok, rat_binary}

          {:error, _reason} ->
            :no_rat
        end

      :no_rat ->
        :no_rat
    end
  end

  defp establish_session(session_id, sender) do
    # For transit relay, we register with the sender as peer_a
    # and a placeholder for peer_b (will be updated when the other side responds)
    placeholder = {{0, 0, 0, 0}, 0}
    SessionRegistry.register_session(session_id, sender, placeholder)
  end
end
