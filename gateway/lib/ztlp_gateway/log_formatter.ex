defmodule ZtlpGateway.LogFormatter do
  @moduledoc """
  Custom Logger formatter for the ZTLP Gateway.

  Supports structured (key=value) and console (human-readable) formats.
  Set via `ZTLP_LOG_FORMAT=structured|console` env var.
  """

  @spec format(Logger.level(), Logger.message(), Logger.Formatter.time(), keyword()) :: IO.chardata()
  def format(level, message, timestamp, metadata) do
    case log_format() do
      :structured -> format_structured(level, message, timestamp, metadata)
      :console -> format_console(level, message, timestamp, metadata)
    end
  rescue
    _ -> "#{inspect(timestamp)} [#{level}] #{message}\n"
  end

  defp format_structured(level, message, timestamp, metadata) do
    ts = format_iso8601(timestamp)
    base = "#{ts} level=#{level} component=gateway"
    meta_str = metadata
    |> Keyword.drop([:trace, :ansi_color, :erl_level])
    |> Enum.map(fn {k, v} -> "#{k}=#{inspect(v)}" end)
    |> Enum.join(" ")

    msg = IO.chardata_to_string(message)
    parts = [base]
    parts = if meta_str != "", do: parts ++ [meta_str], else: parts
    parts = if msg != "", do: parts ++ ["msg=\"#{msg}\""], else: parts
    [Enum.join(parts, " "), "\n"]
  end

  defp format_console(level, message, timestamp, _metadata) do
    ts = format_time_only(timestamp)
    [ts, " [", Atom.to_string(level), "] ", message, "\n"]
  end

  defp log_format do
    case System.get_env("ZTLP_LOG_FORMAT") do
      "structured" -> :structured
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
end
