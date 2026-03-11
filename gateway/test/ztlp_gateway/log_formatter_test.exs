defmodule ZtlpGateway.LogFormatterTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.LogFormatter

  @timestamp {{2026, 3, 11}, {14, 30, 0, 123}}

  # ── Console format ────────────────────────────────────────────────────

  describe "console format" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "console")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "produces human-readable output" do
      result = LogFormatter.format(:info, "Handshake complete", @timestamp, [])
      output = IO.chardata_to_string(result)

      assert output == "14:30:00.123 [info] Handshake complete\n"
    end

    test "includes level in brackets" do
      result = LogFormatter.format(:error, "Backend unreachable", @timestamp, [])
      output = IO.chardata_to_string(result)

      assert output =~ "[error]"
      assert output =~ "Backend unreachable"
    end

    test "ignores metadata" do
      result = LogFormatter.format(:info, "Test", @timestamp, [event: :handshake_complete, session_id: "xyz"])
      output = IO.chardata_to_string(result)

      refute output =~ "handshake_complete"
      refute output =~ "xyz"
    end
  end

  # ── Structured format ─────────────────────────────────────────────────

  describe "structured format" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "structured")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "produces key=value output with component=gateway" do
      result = LogFormatter.format(:info, "Handshake complete", @timestamp, [event: :handshake_complete])
      output = IO.chardata_to_string(result)

      assert output =~ "2026-03-11T14:30:00.123Z"
      assert output =~ "level=info"
      assert output =~ "component=gateway"
      assert output =~ "event="
    end

    test "includes metadata" do
      result = LogFormatter.format(:info, "Test", @timestamp,
        [event: :handshake_complete, session_id: "xyz"])
      output = IO.chardata_to_string(result)

      assert output =~ "session_id="
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

      assert output =~ "component=gateway"
      refute output =~ ~s(msg=)
    end
  end

  # ── JSON format ───────────────────────────────────────────────────────

  describe "json format" do
    setup do
      System.put_env("ZTLP_LOG_FORMAT", "json")
      on_exit(fn -> System.delete_env("ZTLP_LOG_FORMAT") end)
    end

    test "produces valid JSON" do
      result = LogFormatter.format(:info, "Test", @timestamp, [event: :handshake_complete])
      output = IO.chardata_to_string(result) |> String.trim()

      assert String.starts_with?(output, "{")
      assert String.ends_with?(output, "}")
    end

    test "includes required fields with component=gateway" do
      result = LogFormatter.format(:info, "Handshake complete", @timestamp,
        [event: :handshake_complete])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("timestamp":"2026-03-11T14:30:00.123Z")
      assert output =~ ~s("level":"info")
      assert output =~ ~s("component":"gateway")
      assert output =~ ~s("event":"handshake_complete")
      assert output =~ ~s("msg":"Handshake complete")
    end

    test "includes metadata fields" do
      result = LogFormatter.format(:info, "Test", @timestamp,
        [event: :test, session_id: "xyz", backend: "web"])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("session_id":"xyz")
      assert output =~ ~s("backend":"web")
    end

    test "handles integer metadata" do
      result = LogFormatter.format(:info, "Stats", @timestamp,
        [event: :stats, sessions: 99])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("sessions":99)
    end

    test "escapes special characters" do
      result = LogFormatter.format(:info, "line1\nline2", @timestamp, [])
      output = IO.chardata_to_string(result) |> String.trim()

      assert output =~ ~s("msg":"line1\\nline2")
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

      assert output =~ ~s("component":"gateway")
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

    test "JSON output is parseable" do
      result = LogFormatter.format(:info, "Handshake complete", @timestamp,
        [event: :handshake_complete, session_id: "xyz"])
      json_str = IO.chardata_to_string(result) |> String.trim()

      assert {:ok, parsed} = parse_json_object(json_str)
      assert parsed["timestamp"] == "2026-03-11T14:30:00.123Z"
      assert parsed["level"] == "info"
      assert parsed["component"] == "gateway"
      assert parsed["event"] == "handshake_complete"
      assert parsed["session_id"] == "xyz"
      assert parsed["msg"] == "Handshake complete"
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

  # ── Error handling ────────────────────────────────────────────────────

  describe "error handling" do
    test "rescue produces fallback output" do
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
    case Integer.parse(str) do
      {n, rest} -> {:ok, n, rest}
      :error -> :error
    end
  end
end
