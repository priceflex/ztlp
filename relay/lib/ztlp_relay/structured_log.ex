defmodule ZtlpRelay.StructuredLog do
  @moduledoc """
  Structured logging helpers for the ZTLP Relay.

  Provides convenience functions that emit structured log events
  with consistent metadata. Uses the standard Elixir Logger with
  metadata keywords for structured output.

  ## Log Levels

  - `info` — Production operational messages
  - `debug` — Troubleshooting detail
  - `trace` — Deep protocol analysis (emitted as debug + trace metadata)

  ## Usage

      ZtlpRelay.StructuredLog.info(:session_opened, session_id: sid, peer: addr)
      ZtlpRelay.StructuredLog.debug(:pipeline_decision, session_id: sid, layer: 2, result: :drop)
      ZtlpRelay.StructuredLog.trace(:raw_packet, hex: Base.encode16(data))
  """

  require Logger

  @doc "Log at info level with structured metadata."
  @spec info(atom(), keyword()) :: :ok
  def info(event, metadata \\ []) do
    Logger.info(fn -> event_message(event) end, [event: event] ++ metadata)
  end

  @doc "Log at debug level with structured metadata."
  @spec debug(atom(), keyword()) :: :ok
  def debug(event, metadata \\ []) do
    Logger.debug(fn -> event_message(event) end, [event: event] ++ metadata)
  end

  @doc """
  Log at trace level (debug + trace: true metadata).

  Only visible when log level is :debug AND trace filtering is enabled.
  """
  @spec trace(atom(), keyword()) :: :ok
  def trace(event, metadata \\ []) do
    Logger.debug(fn -> event_message(event) end, [event: event, trace: true] ++ metadata)
  end

  @doc "Log a warning with structured metadata."
  @spec warn(atom(), keyword()) :: :ok
  def warn(event, metadata \\ []) do
    Logger.warning(fn -> event_message(event) end, [event: event] ++ metadata)
  end

  @doc "Log an error with structured metadata."
  @spec error(atom(), keyword()) :: :ok
  def error(event, metadata \\ []) do
    Logger.error(fn -> event_message(event) end, [event: event] ++ metadata)
  end

  # ── Event descriptions (for console format) ──────────────────────────

  defp event_message(:startup), do: "Relay starting"
  defp event_message(:config_loaded), do: "Configuration loaded"
  defp event_message(:listening), do: "UDP listener started"
  defp event_message(:session_opened), do: "Session opened"
  defp event_message(:session_closed), do: "Session closed"
  defp event_message(:session_timeout), do: "Session timed out"
  defp event_message(:pipeline_drop_l1), do: "Pipeline drop: magic check"
  defp event_message(:pipeline_drop_l2), do: "Pipeline drop: session lookup"
  defp event_message(:pipeline_drop_l3), do: "Pipeline drop: auth tag"
  defp event_message(:pipeline_pass), do: "Pipeline pass"
  defp event_message(:packet_forwarded), do: "Packet forwarded"
  defp event_message(:mesh_peer_joined), do: "Mesh peer joined"
  defp event_message(:mesh_peer_left), do: "Mesh peer left"
  defp event_message(:mesh_peer_degraded), do: "Mesh peer degraded"
  defp event_message(:admission_rat_issued), do: "RAT issued"
  defp event_message(:admission_rat_verified), do: "RAT verified"
  defp event_message(:admission_sac_triggered), do: "SAC challenge triggered"
  defp event_message(:stats_summary), do: "Periodic stats"
  defp event_message(:drain_started), do: "Drain mode started"
  defp event_message(:drain_complete), do: "Drain complete"
  defp event_message(:drain_cancelled), do: "Drain cancelled"
  defp event_message(:raw_packet), do: "Raw packet"
  defp event_message(:handshake_state), do: "Handshake state transition"
  defp event_message(:hash_ring_update), do: "Hash ring updated"
  defp event_message(event), do: Atom.to_string(event)
end
