defmodule ZtlpRelay do
  @moduledoc """
  ZTLP Relay — Zero Trust Layer Protocol relay node.

  A pure OTP application that relays encrypted ZTLP packets between peers
  by SessionID. The relay never sees plaintext — it only forwards packets
  based on the 96-bit SessionID routing key.

  ## Architecture

  The relay implements the ZTLP three-layer admission pipeline:

  1. **Layer 1 — Magic check** (nanoseconds, no crypto): Rejects non-ZTLP UDP noise.
  2. **Layer 2 — SessionID lookup** (microseconds, no crypto): Rejects unknown sessions.
  3. **Layer 3 — HeaderAuthTag verification** (real crypto cost): Rejects forged packets.

  After admission, the relay looks up the peer's address in the session
  registry and forwards the raw packet unchanged.
  """

  @doc """
  Returns the ZTLP magic value: 0x5A37 ('Z7').
  """
  @spec magic() :: 0x5A37
  def magic, do: 0x5A37

  @doc """
  Returns the current protocol version.
  """
  @spec version() :: 1
  def version, do: 1
end
