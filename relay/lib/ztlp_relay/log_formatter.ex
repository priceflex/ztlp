defmodule ZtlpRelay.LogFormatter do
  @moduledoc """
  Custom Logger formatter for the ZTLP Relay.

  Supports three output formats:

  - `:structured` (production) — key=value pairs for machine parsing:
    ```
    2026-03-11T14:30:00.000Z level=info component=relay event=session_opened session_id=abc123
    ```

  - `:json` (production) — JSON lines for log aggregation (ELK, Loki, Datadog):
    ```json
    {"timestamp":"2026-03-11T14:30:00.000Z","level":"info","component":"relay","event":"session_opened","session_id":"abc123","msg":"Session opened"}
    ```

  - `:console` (development) — human-readable:
    ```
    14:30:00.000 [info] Session opened: abc123 from 192.168.1.10:4567
    ```

  ## Configuration

  Set via environment variable `ZTLP_LOG_FORMAT`:
  - `structured` → structured format
  - `json` → JSON lines format
  - `console` → console format (default)

  Set log level via `ZTLP_LOG_LEVEL`:
  - `info` (default for production)
  - `debug` (troubleshooting)

  Trace level is implemented as debug + `[trace: true]` metadata.
  """

  @doc """
  Logger formatter callback.

  Called by the Elixir Logger backend for each log message.
  """
  @spec format(Logger.level(), Logger.message(), Logger.Formatter.time(), keyword()) :: IO.chardata()
  def format(level, message, timestamp, metadata) do
    case log_format() do
      :structured -> format_structured(level, message, timestamp, metadata)
      :json -> format_json(level, message, timestamp, metadata)
      :console -> format_console(level, message, timestamp, metadata)
    end
  rescue
    _ -> "#{inspect(timestamp)} [#{level}] #{message}\n"
  end

  # ── Structured format ─────────────────────────────────────────────────

  defp format_structured(level, message, timestamp, metadata) do
    ts = format_iso8601(timestamp)
    base = "#{ts} level=#{level} component=relay"

    meta_str = metadata
    |> Keyword.drop([:trace, :ansi_color, :erl_level])
    |> Enum.map(fn {k, v} -> "#{k}=#{format_value(v)}" end)
    |> Enum.join(" ")

    msg = IO.chardata_to_string(message)

    parts = [base]
    parts = if meta_str != "", do: parts ++ [meta_str], else: parts
    parts = if msg != "", do: parts ++ ["msg=#{quote_if_needed(msg)}"], else: parts

    [Enum.join(parts, " "), "\n"]
  end

  # ── JSON format ───────────────────────────────────────────────────────

  defp format_json(level, message, timestamp, metadata) do
    ts = format_iso8601(timestamp)
    msg = IO.chardata_to_string(message)

    fields = [{"timestamp", ts}, {"level", Atom.to_string(level)}, {"component", "relay"}]

    meta_fields = metadata
    |> Keyword.drop([:trace, :ansi_color, :erl_level])
    |> Enum.map(fn {k, v} -> {Atom.to_string(k), json_value(v)} end)

    fields = fields ++ meta_fields
    fields = if msg != "", do: fields ++ [{"msg", msg}], else: fields

    [encode_json_object(fields), "\n"]
  end

  # ── Console format ────────────────────────────────────────────────────

  defp format_console(level, message, timestamp, _metadata) do
    ts = format_time_only(timestamp)
    [ts, " [", Atom.to_string(level), "] ", message, "\n"]
  end

  # ── Helpers ───────────────────────────────────────────────────────────

  @doc false
  def log_format do
    case System.get_env("ZTLP_LOG_FORMAT") do
      "structured" -> :structured
      "json" -> :json
      _ -> :console
    end
  end

  defp format_iso8601({date, {h, m, s, ms}}) do
    {year, month, day} = date
    :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~3..0BZ",
      [year, month, day, h, m, s, ms])
    |> IO.chardata_to_string()
  end

  defp format_time_only({_date, {h, m, s, ms}}) do
    :io_lib.format("~2..0B:~2..0B:~2..0B.~3..0B", [h, m, s, ms])
    |> IO.chardata_to_string()
  end

  defp format_value(v) when is_binary(v), do: quote_if_needed(v)
  defp format_value(v) when is_atom(v), do: Atom.to_string(v)
  defp format_value(v) when is_integer(v), do: Integer.to_string(v)
  defp format_value(v) when is_float(v), do: Float.to_string(v)
  defp format_value(v) when is_tuple(v), do: inspect(v)
  defp format_value(v), do: inspect(v)

  defp quote_if_needed(s) do
    if String.contains?(s, [" ", "=", "\""]) do
      "\"#{String.replace(s, "\"", "\\\"")}\""
    else
      s
    end
  end

  # ── JSON encoding (no external deps) ─────────────────────────────────

  @doc false
  def encode_json_object(pairs) do
    inner = pairs
    |> Enum.map(fn {k, v} -> [json_encode_string(k), ":", json_encode(v)] end)
    |> Enum.intersperse(",")
    ["{", inner, "}"]
  end

  defp json_encode(v) when is_binary(v), do: json_encode_string(v)
  defp json_encode(v) when is_atom(v), do: json_encode_string(Atom.to_string(v))
  defp json_encode(v) when is_integer(v), do: Integer.to_string(v)
  defp json_encode(v) when is_float(v), do: Float.to_string(v)
  defp json_encode(v), do: json_encode_string(inspect(v))

  defp json_encode_string(s) do
    escaped = s
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
    |> String.replace("\n", "\\n")
    |> String.replace("\r", "\\r")
    |> String.replace("\t", "\\t")
    ["\"", escaped, "\""]
  end

  defp json_value(v) when is_binary(v), do: v
  defp json_value(v) when is_atom(v), do: Atom.to_string(v)
  defp json_value(v) when is_integer(v), do: v
  defp json_value(v) when is_float(v), do: v
  defp json_value(v), do: inspect(v)
end
