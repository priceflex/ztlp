defmodule ZtlpRelay.Ingress do
  @moduledoc """
  Ingress admission logic for first-contact HELLO processing.

  Ingress relays handle the initial HELLO messages from nodes seeking
  to establish sessions. The ingress applies rate limiting (per-IP and
  per-NodeID), optionally issues a Stateless Admission Challenge (SAC)
  under load, and issues Relay Admission Tokens (RATs) for accepted nodes.

  ## Stateless Admission Challenge (SAC)

  Similar to DTLS HelloVerifyRequest, when the relay is under load
  (session count exceeds the configured threshold), clients must solve
  a challenge before being admitted. The challenge is:

      BLAKE2s(sender_ip || sender_port || timestamp_window || relay_secret)

  This is completely stateless — the relay can verify the challenge
  without storing any per-client state.
  """

  alias ZtlpRelay.{AdmissionToken, Config, Packet, RateLimiter, SessionRegistry}

  @challenge_window_seconds 30

  @type sender :: {:inet.ip_address(), :inet.port_number()}

  @type hello_result ::
          {:ok, :admitted, binary()}
          | {:challenge, binary()}
          | {:error, atom()}

  @type state :: %{
          rate_limiter_table: atom()
        }

  @doc """
  Create a default ingress state.
  """
  @spec new_state(keyword()) :: state()
  def new_state(opts \\ []) do
    %{
      rate_limiter_table: Keyword.get(opts, :rate_limiter_table, :ztlp_rate_limiter)
    }
  end

  @doc """
  Process a HELLO message from a new node.

  ## Steps

  1. Extract the initiator's NodeID from the HELLO packet
  2. Check rate limits (per-IP and per-NodeID)
  3. If under load, apply Stateless Admission Challenge
  4. If accepted: issue a RAT and return it
  5. If rejected: return an error

  ## Parameters

    - `packet` — parsed handshake packet (must be msg_type: :hello)
    - `sender` — `{ip, port}` tuple
    - `state` — ingress state

  ## Options

    - `:challenge_response` — the challenge response from the client (if any)
    - `:secret_key` — RAT signing key (default: from config)
    - `:session_count` — current session count (default: from registry)
    - `:max_sessions` — max sessions (default: from config)
    - `:sac_threshold` — SAC load threshold (default: from config)

  ## Returns

    - `{:ok, :admitted, rat_binary}` — node is admitted, RAT issued
    - `{:challenge, challenge_binary}` — node must solve challenge first
    - `{:error, reason}` — admission rejected
  """
  @spec handle_hello(Packet.handshake_packet(), sender(), state(), keyword()) :: hello_result()
  def handle_hello(packet, sender, state, opts \\ [])

  def handle_hello(%{type: :handshake, msg_type: :hello} = packet, sender, state, opts) do
    {ip, _port} = sender
    node_id = packet.src_node_id
    table = state.rate_limiter_table

    ip_limit = Keyword.get(opts, :ip_limit, Config.ingress_rate_limit_per_ip())
    node_limit = Keyword.get(opts, :node_limit, Config.ingress_rate_limit_per_node())

    # Step 1: Check per-IP rate limit
    case RateLimiter.check({:ip, ip}, ip_limit, 60_000, table: table) do
      {:error, :rate_limited} ->
        {:error, :ip_rate_limited}

      :ok ->
        # Step 2: Check per-NodeID rate limit
        case RateLimiter.check({:node, node_id}, node_limit, 60_000, table: table) do
          {:error, :rate_limited} ->
            {:error, :node_rate_limited}

          :ok ->
            # Step 3: Check load and maybe challenge
            maybe_challenge_or_admit(packet, sender, opts)
        end
    end
  end

  def handle_hello(_packet, _sender, _state, _opts) do
    {:error, :not_hello}
  end

  @doc """
  Generate a Stateless Admission Challenge for a sender.

  The challenge is: BLAKE2s(sender_ip || sender_port || timestamp_window || relay_secret)

  The timestamp_window is floor(now / window_seconds) to allow verification
  within the same time window.
  """
  @spec generate_challenge(sender(), keyword()) :: binary()
  def generate_challenge(sender, opts \\ []) do
    secret = Keyword.get(opts, :secret_key, Config.rat_secret())
    window = Keyword.get(opts, :window_seconds, @challenge_window_seconds)
    generate_challenge_for_time(sender, System.system_time(:second), window, secret)
  end

  @doc """
  Verify a Stateless Admission Challenge response.

  Checks both the current and previous time windows to handle
  challenges issued near window boundaries.
  """
  @spec verify_challenge(binary(), sender(), keyword()) :: boolean()
  def verify_challenge(challenge, sender, opts \\ []) do
    secret = Keyword.get(opts, :secret_key, Config.rat_secret())
    window = Keyword.get(opts, :window_seconds, @challenge_window_seconds)
    now = System.system_time(:second)

    # Check current window and previous window
    current = generate_challenge_for_time(sender, now, window, secret)
    previous = generate_challenge_for_time(sender, now - window, window, secret)

    challenge == current or challenge == previous
  end

  # Internal

  defp maybe_challenge_or_admit(packet, sender, opts) do
    session_count = Keyword.get(opts, :session_count, SessionRegistry.count())
    max_sessions = Keyword.get(opts, :max_sessions, Config.max_sessions())
    threshold = Keyword.get(opts, :sac_threshold, Config.sac_load_threshold())

    load = session_count / max(max_sessions, 1)

    if load >= threshold do
      # Under load — require challenge
      case Keyword.get(opts, :challenge_response) do
        nil ->
          # No challenge response — issue challenge
          challenge = generate_challenge(sender, opts)
          {:challenge, challenge}

        response ->
          # Verify challenge response
          if verify_challenge(response, sender, opts) do
            admit(packet, opts)
          else
            {:error, :invalid_challenge}
          end
      end
    else
      # Under threshold — admit directly
      admit(packet, opts)
    end
  end

  defp admit(packet, opts) do
    secret_key = Keyword.get(opts, :secret_key, Config.rat_secret())
    issuer_id = Keyword.get(opts, :issuer_id, Config.relay_node_id())
    ttl = Keyword.get(opts, :ttl_seconds, Config.rat_ttl_seconds())

    session_scope = packet.session_id

    rat =
      AdmissionToken.issue(
        packet.src_node_id,
        session_scope,
        secret_key: secret_key,
        issuer_id: issuer_id,
        ttl_seconds: ttl
      )

    {:ok, :admitted, rat}
  end

  defp generate_challenge_for_time({ip, port}, time, window, secret) do
    ip_bin = encode_ip(ip)
    time_window = div(time, window)

    data = <<
      ip_bin::binary,
      port::big-unsigned-16,
      time_window::big-unsigned-64,
      secret::binary
    >>

    :crypto.hash(:blake2s, data)
  end

  defp encode_ip({a, b, c, d}), do: <<a, b, c, d>>

  defp encode_ip({a, b, c, d, e, f, g, h}),
    do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
end
