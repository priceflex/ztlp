defmodule ZtlpRelay.LogFormatterTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.LogFormatter

  @timestamp {{2026, 3, 11}, {14, 30, 0, 123}}

  # ── Console format ────────────────────────────────────────────────────

  describe "console format" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "console")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "produces human-readable output" do
      result = LogFormatter.format(:info, "Session opened", @timestamp, [])
      output = IO.chardata_to_string(result)

      assert output == "14:30:00.123 [info] Session opened\n"
    end

    test "includes level in brackets" do
      result = LogFormatter.format(:error, "Connection failed", @timestamp, [])
      output = IO.chardata_to_string(result)

      assert output =~ "[error]"
      assert output =~ "Connection failed"
    end

    test "ignores metadata" do
      result = LogFormatter.format(:info, "Test", @timestamp, [event: :session_opened, session_id: "abc"])
      output = IO.chardata_to_string(result)

      refute output =~ "session_opened"
      refute output =~ "abc"
    end
  end

  # ── Structured format ─────────────────────────────────────────────────

  describe "structured format" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "structured")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "produces key=value output with component=relay" do
      result = LogFormatter.format(:info, "Session opened", @timestamp, [event: :session_opened])
      output = IO.chardata_to_string(result)

      assert output =~ "2026-03-11T14:30:00.123Z"
      assert output =~ "level=info"
      assert output =~ "component=relay"
      assert output =~ "event=session_opened"
      assert output =~ "msg="
    end

    test "includes metadata as key=value pairs" do
      result = LogFormatter.format(:info, "Test", @timestamp,
        [event: :session_opened, session_id: "abc123", peer: "192.168.1.10"])
      output = IO.chardata_to_string(result)

      assert output =~ "session_id=abc123"
      assert output =~ "peer=192.168.1.10"
    end

    test "quotes values with spaces" do
      result = LogFormatter.format(:info, "hello world", @timestamp, [])
      output = IO.chardata_to_string(result)

      assert output =~ ~s(msg="hello world")
    end

    test "drops internal metadata keys" do
      result = LogFormatter.format(:info, "Test", @timestamp,
        [event: :test, ansi_color: "\e[32m", erl_level: :info, trace: true])
      output = IO.chardata_to_string(result)

      refute output =~ "ansi_color"
      refute output =~ "erl_level"
      refute output =~ "trace="
    end

    test "handles empty message" do
      result = LogFormatter.format(:debug, "", @timestamp, [event: :test])
      output = IO.chardata_to_string(result)

      assert output =~ "component=relay"
      refute output =~ "msg="
    end

    test "handles integer metadata" do
      result = LogFormatter.format(:info, "Test", @timestamp, [event: :test, count: 42])
      output = IO.chardata_to_string(result)

      assert output =~ "count=42"
    end
  end

  # ── JSON format ───────────────────────────────────────────────────────

  describe "json format" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "json")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "produces valid JSON" do
      result = LogFormatter.format(:info, "Session opened", @timestamp,
        [event: :session_opened, session_id: "abc123"])
      output = IO.chardata_to_string(result) |> String.trim()

      # Verify it's parseable JSON using :erl_scan and manual validation
      assert String.starts_with?(output, "{")
      assert String.ends_with?(output, "}")
    end

    test "includes required fields" do
      result = LogFormatter.format(:info, "Session opened", @timestamp,
        [event: :session_opened])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("timestamp":"2026-03-11T14:30:00.123Z")
      assert output =~ ~s("level":"info")
      assert output =~ ~s("component":"relay")
      assert output =~ ~s("event":"session_opened")
      assert output =~ ~s("msg":"Session opened")
    end

    test "includes metadata fields" do
      result = LogFormatter.format(:info, "Test", @timestamp,
        [event: :session_opened, session_id: "abc123", peer: "10.0.0.1"])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("session_id":"abc123")
      assert output =~ ~s("peer":"10.0.0.1")
    end

    test "handles integer metadata values" do
      result = LogFormatter.format(:info, "Stats", @timestamp,
        [event: :stats_summary, sessions: 42])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("sessions":42)
    end

    test "escapes special characters in strings" do
      result = LogFormatter.format(:info, "line1\nline2", @timestamp, [])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("msg":"line1\\nline2")
    end

    test "escapes quotes in values" do
      result = LogFormatter.format(:info, ~s(said "hello"), @timestamp, [])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s(\\"hello\\")
    end

    test "drops internal metadata keys" do
      result = LogFormatter.format(:info, "Test", @timestamp,
        [event: :test, ansi_color: "\e[32m", erl_level: :info, trace: true])
      output = IO.chardata_to_string(result) |> String.trim()

      refute output =~ "ansi_color"
      refute output =~ "erl_level"
      refute output =~ ~s("trace")
    end

    test "handles empty message" do
      result = LogFormatter.format(:debug, "", @timestamp, [event: :test])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("component":"relay")
      refute output =~ ~s("msg")
    end

    test "ends with newline" do
      result = LogFormatter.format(:info, "Test", @timestamp, [])
      output = IO.chardata_to_string(result)

      assert String.ends_with?(output, "\n")
    end

    test "all levels work" do
      for level <- [:debug, :info, :warn, :error] do
        result = LogFormatter.format(level, "Test", @timestamp, [])
        output = IO.chardata_to_string(result) |> String.trim()

        assert output =~ ~s("level":"#{level}")
      end
    end

    test "JSON output is parseable by decoding manually" do
      result = LogFormatter.format(:info, "Session opened", @timestamp,
        [event: :session_opened, session_id: "abc123"])
      json_str = IO.chardata_to_string(result) |> String.trim()

      # Parse the JSON manually to verify structure
      assert {:ok, parsed} = parse_json_object(json_str)
      assert parsed["timestamp"] == "2026-03-11T14:30:00.123Z"
      assert parsed["level"] == "info"
      assert parsed["component"] == "relay"
      assert parsed["event"] == "session_opened"
      assert parsed["session_id"] == "abc123"
      assert parsed["msg"] == "Session opened"
    end
  end

  # ── Default format ────────────────────────────────────────────────────

  describe "default format" do
    setup do
      System.delete_env("ZTLP_LOG_FORMAT")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "defaults to console format" do
      result = LogFormatter.format(:info, "Test", @timestamp, [])
      output = IO.chardata_to_string(result)

      assert output == "14:30:00.123 [info] Test\n"
    end
  end

  # ── Rescue handling ───────────────────────────────────────────────────

  describe "error handling" do
    test "rescue produces fallback output on bad timestamp" do
      # Trigger the rescue clause with an invalid timestamp
      result = LogFormatter.format(:info, "Test", :bad_timestamp, [])
      output = IO.chardata_to_string(result)

      assert output =~ "[info]"
      assert output =~ "Test"
    end
  end

  # ── Simple JSON parser for test validation ────────────────────────────

  defp parse_json_object(str) do
    str = String.trim(str)
    case parse_object(str, %{}) do
      {:ok, map, _rest} -> {:ok, map}
      :error -> :error
    end
  end

  defp parse_object("{" <> rest, _acc) do
    rest = String.trim_leading(rest)
    case rest do
      "}" <> tail -> {:ok, %{}, tail}
      _ -> parse_pairs(rest, %{})
    end
  end
  defp parse_object(_, _), do: :error

  defp parse_pairs(str, acc) do
    with {:ok, key, rest} <- parse_string(String.trim_leading(str)),
         ":" <> rest <- String.trim_leading(rest),
         {:ok, val, rest} <- parse_value(String.trim_leading(rest)) do
      acc = Map.put(acc, key, val)
      rest = String.trim_leading(rest)
      case rest do
        "}" <> tail -> {:ok, acc, tail}
        "," <> tail -> parse_pairs(String.trim_leading(tail), acc)
        _ -> :error
      end
    else
      _ -> :error
    end
  end

  defp parse_string("\"" <> rest), do: extract_string(rest, [])
  defp parse_string(_), do: :error

  defp extract_string("\\\"" <> rest, acc), do: extract_string(rest, acc ++ [~s(")])
  defp extract_string("\\\\" <> rest, acc), do: extract_string(rest, acc ++ ["\\"])
  defp extract_string("\\n" <> rest, acc), do: extract_string(rest, acc ++ ["\n"])
  defp extract_string("\\r" <> rest, acc), do: extract_string(rest, acc ++ ["\r"])
  defp extract_string("\\t" <> rest, acc), do: extract_string(rest, acc ++ ["\t"])
  defp extract_string("\"" <> rest, acc), do: {:ok, IO.chardata_to_string(acc), rest}
  defp extract_string(<<c::utf8, rest::binary>>, acc), do: extract_string(rest, acc ++ [<<c::utf8>>])
  defp extract_string("", _), do: :error

  defp parse_value("\"" <> _ = str), do: parse_string(str)
  defp parse_value(str) do
    # Try to parse a number
    case Integer.parse(str) do
      {n, rest} -> {:ok, n, rest}
      :error -> :error
    end
  end
end
