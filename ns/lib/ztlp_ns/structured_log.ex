defmodule ZtlpNs.StructuredLog do
  @moduledoc """
  Structured logging helpers for the ZTLP Namespace Server.

  Provides convenience functions that emit structured log events
  with consistent metadata. Uses the standard Elixir Logger with
  metadata keywords for structured output.

  ## Log Levels

  - `info` — Production operational messages
  - `debug` — Troubleshooting detail
  - `trace` — Deep protocol analysis (emitted as debug + trace metadata)

  ## Usage

      ZtlpNs.StructuredLog.info(:record_created, name: "web.example.ztlp", type: :A)
      ZtlpNs.StructuredLog.debug(:query_received, name: "web.example.ztlp", peer: addr)
      ZtlpNs.StructuredLog.trace(:bootstrap_started, target: "ns.root.ztlp")
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

  defp event_message(:startup), do: "NS starting"
  defp event_message(:config_loaded), do: "Configuration loaded"
  defp event_message(:listening), do: "UDP listener started"
  defp event_message(:record_created), do: "Record created"
  defp event_message(:record_updated), do: "Record updated"
  defp event_message(:record_expired), do: "Record expired"
  defp event_message(:record_deleted), do: "Record deleted"
  defp event_message(:zone_delegated), do: "Zone delegated"
  defp event_message(:zone_revoked), do: "Zone revoked"
  defp event_message(:query_received), do: "Query received"
  defp event_message(:query_resolved), do: "Query resolved"
  defp event_message(:query_not_found), do: "Query not found"
  defp event_message(:registration_received), do: "Registration received"
  defp event_message(:registration_accepted), do: "Registration accepted"
  defp event_message(:registration_rejected), do: "Registration rejected"
  defp event_message(:rate_limited), do: "Rate limited"
  defp event_message(:oversized_packet), do: "Oversized packet dropped"
  defp event_message(:auth_failure), do: "Authentication failure"
  defp event_message(:bootstrap_started), do: "Bootstrap started"
  defp event_message(:bootstrap_complete), do: "Bootstrap complete"
  defp event_message(:stats_summary), do: "Periodic stats"
  defp event_message(event), do: Atom.to_string(event)
end
