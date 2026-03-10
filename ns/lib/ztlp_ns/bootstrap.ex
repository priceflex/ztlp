defmodule ZtlpNs.Bootstrap do
  @moduledoc """
  Bootstrap discovery for ZTLP-NS.

  When a ZTLP node starts with no prior state, it needs to discover at
  least one relay to connect to. The bootstrap sequence defined in the
  spec (Section 10) is a three-step fallback:

  1. **HTTPS Discovery (REQUIRED)** — Fetch a signed JSON relay list
     from well-known URLs. The response must be signed by a trust anchor.

  2. **DNS-SRV Discovery (RECOMMENDED)** — Query `_ztlprelay._udp.bootstrap.ztlp`
     for SRV records with DNSSEC validation.

  3. **Hardcoded Fallback** — Use the built-in relay list (min 15 relays,
     5 ASNs, 3 geographic regions).

  ## Prototype Limitations

  This prototype implements:
  - The HTTPS validation logic (signature verification of bootstrap response)
  - The fallback chain logic (try each step, fall through on failure)
  - Mock bootstrap data for testing

  It does NOT make actual HTTPS/DNS calls — the `:httpc` call is wrapped
  in a function that can be mocked for testing, and the real HTTPS endpoint
  doesn't exist yet.
  """

  alias ZtlpNs.Record

  @doc """
  Run the full bootstrap sequence. Returns a list of relay records.

  Tries each step in order, returns the first successful result.
  If all steps fail, returns `{:error, :bootstrap_failed}`.
  """
  @spec discover() :: {:ok, [Record.t()]} | {:error, atom()}
  def discover do
    with {:error, _} <- discover_https(),
         {:error, _} <- discover_dns_srv(),
         {:error, _} <- discover_hardcoded() do
      {:error, :bootstrap_failed}
    end
  end

  @doc """
  Step 1: HTTPS Discovery.

  Attempts to fetch and verify a signed relay list from each configured
  bootstrap URL. The response must be a JSON object containing:
  - A list of relay addresses with Node IDs and public keys
  - A validity timestamp and TTL
  - A signature verifiable against a trust anchor

  For the prototype, this validates the response format and signature
  but uses a pluggable fetch function for testing.
  """
  @spec discover_https() :: {:ok, [Record.t()]} | {:error, atom()}
  def discover_https do
    urls = ZtlpNs.Config.bootstrap_urls()

    Enum.reduce_while(urls, {:error, :no_urls}, fn url, _acc ->
      case fetch_and_verify(url) do
        {:ok, relays} -> {:halt, {:ok, relays}}
        {:error, _} -> {:cont, {:error, :https_failed}}
      end
    end)
  end

  @doc """
  Step 2: DNS-SRV Discovery.

  Would query `_ztlprelay._udp.bootstrap.ztlp` for SRV records.
  Not implemented in the prototype — always returns an error to fall
  through to Step 3.
  """
  @spec discover_dns_srv() :: {:error, :not_implemented}
  def discover_dns_srv do
    {:error, :not_implemented}
  end

  @doc """
  Step 3: Hardcoded Fallback.

  Returns a static list of bootstrap relay records. In a real deployment
  this would be compiled into the binary with pinned public keys.

  For the prototype, returns an error (no real relays to hardcode).
  Override with `set_hardcoded_relays/1` for testing.
  """
  @spec discover_hardcoded() :: {:ok, [Record.t()]} | {:error, :no_hardcoded_relays}
  def discover_hardcoded do
    case Process.get(:ztlp_hardcoded_relays) do
      nil -> {:error, :no_hardcoded_relays}
      relays -> {:ok, relays}
    end
  end

  @doc """
  Set hardcoded relays for testing. Stored in process dictionary.
  """
  @spec set_hardcoded_relays([Record.t()]) :: :ok
  def set_hardcoded_relays(relays) when is_list(relays) do
    Process.put(:ztlp_hardcoded_relays, relays)
    :ok
  end

  @doc """
  Verify a bootstrap response.

  A valid bootstrap response is a signed ZTLP_BOOTSTRAP record. The
  signature must be verifiable against one of the configured trust anchors.

  Returns `{:ok, relay_records}` if valid, `{:error, reason}` otherwise.
  """
  @spec verify_response(Record.t()) :: {:ok, [map()]} | {:error, atom()}
  def verify_response(%Record{type: :bootstrap} = record) do
    if Record.verify(record) do
      case record.data do
        %{relays: relays} when is_list(relays) ->
          {:ok, relays}
        _ ->
          {:error, :invalid_bootstrap_data}
      end
    else
      {:error, :invalid_signature}
    end
  end

  def verify_response(_), do: {:error, :not_a_bootstrap_record}

  # ── Private helpers ────────────────────────────────────────────────

  # Fetch from a URL and verify the response. In the prototype, this
  # uses a pluggable function (for testing) rather than making real
  # HTTP calls.
  defp fetch_and_verify(_url) do
    # TODO: In production, use :httpc.request/1 to fetch the URL,
    # parse the JSON response, extract the signature, and verify
    # against trust anchors.
    #
    # For now, return an error to fall through to the next step.
    {:error, :not_implemented}
  end
end
