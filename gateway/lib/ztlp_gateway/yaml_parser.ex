defmodule ZtlpGateway.YamlParser do
  @moduledoc """
  Minimal YAML subset parser for ZTLP configuration files.

  Supports the subset of YAML needed for config files:
  - Key-value mappings (nested)
  - Sequences (lists with `- item` syntax)
  - Scalars: strings, integers, floats, booleans, null
  - Quoted strings (single and double)
  - Comments (# to end of line)
  - Blank lines

  Does NOT support:
  - Anchors/aliases (&, *)
  - Multi-line strings (|, >)
  - Flow syntax ({}, [])
  - Tags (!!)
  - Multiple documents (---)

  This is intentional — config files should be simple.
  Zero external dependencies.
  """

  @doc """
  Parse a YAML string into an Elixir term.

  Returns {:ok, map | list | scalar} or {:error, reason}.
  """
  @spec parse(String.t()) :: {:ok, term()} | {:error, String.t()}
  def parse(content) when is_binary(content) do
    lines = content
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.map(fn {line, num} -> {strip_comment(line), num} end)
    |> Enum.reject(fn {line, _num} -> blank?(line) end)

    case lines do
      [] -> {:ok, nil}
      _ ->
        try do
          {result, _rest} = parse_node(lines, 0)
          {:ok, result}
        rescue
          e in RuntimeError -> {:error, e.message}
        end
    end
  end

  # ── Line helpers ──────────────────────────────────────────────────────

  defp strip_comment(line) do
    # Remove inline comments, but not inside quoted strings
    case Regex.run(~r/^((?:[^#"']|"[^"]*"|'[^']*')*)#/, line) do
      [_, before] -> String.trim_trailing(before)
      nil -> line
    end
  end

  defp blank?(line), do: String.trim(line) == ""

  defp indent_level(line) do
    len = byte_size(line) - byte_size(String.trim_leading(line))
    len
  end

  # ── Parser ────────────────────────────────────────────────────────────

  defp parse_node([], _min_indent), do: {nil, []}
  defp parse_node([{line, _num} | _] = lines, min_indent) do
    trimmed = String.trim(line)
    indent = indent_level(line)

    cond do
      indent < min_indent ->
        {nil, lines}

      String.starts_with?(trimmed, "- ") ->
        parse_sequence(lines, indent)

      trimmed == "-" ->
        parse_sequence(lines, indent)

      String.contains?(trimmed, ":") ->
        parse_mapping(lines, indent)

      true ->
        {parse_scalar(trimmed), tl(lines)}
    end
  end

  defp parse_mapping(lines, base_indent) do
    parse_mapping_entries(lines, base_indent, %{})
  end

  defp parse_mapping_entries([], _base_indent, acc), do: {acc, []}
  defp parse_mapping_entries([{line, _num} | rest] = lines, base_indent, acc) do
    indent = indent_level(line)

    cond do
      indent < base_indent ->
        {acc, lines}

      indent > base_indent ->
        # Unexpected deeper indent at this level
        {acc, lines}

      true ->
        trimmed = String.trim(line)

        case parse_key_value(trimmed) do
          {:key_only, key} ->
            # Value is on subsequent indented lines
            {value, remaining} = parse_node(rest, indent + 1)
            parse_mapping_entries(remaining, base_indent, Map.put(acc, key, value))

          {:key_value, key, value} ->
            parse_mapping_entries(rest, base_indent, Map.put(acc, key, value))

          :not_a_mapping ->
            {acc, lines}
        end
    end
  end

  defp parse_key_value(trimmed) do
    # Find the first colon that's not inside quotes
    case split_key_value(trimmed) do
      {key, ""} -> {:key_only, key}
      {key, value_str} -> {:key_value, key, parse_scalar(String.trim(value_str))}
      nil -> :not_a_mapping
    end
  end

  defp split_key_value(str) do
    # Simple split on first ": " or trailing ":"
    case :binary.match(str, ": ") do
      {pos, 2} ->
        key = binary_part(str, 0, pos)
        value = binary_part(str, pos + 2, byte_size(str) - pos - 2)
        {String.trim(key), String.trim(value)}

      :nomatch ->
        # Check for key with no value (trailing colon)
        if String.ends_with?(str, ":") do
          key = String.slice(str, 0, String.length(str) - 1)
          {String.trim(key), ""}
        else
          nil
        end
    end
  end

  defp parse_sequence(lines, base_indent) do
    parse_sequence_items(lines, base_indent, [])
  end

  defp parse_sequence_items([], _base_indent, acc), do: {Enum.reverse(acc), []}
  defp parse_sequence_items([{line, _num} | _rest] = lines, base_indent, acc) do
    indent = indent_level(line)
    trimmed = String.trim(line)

    cond do
      indent < base_indent ->
        {Enum.reverse(acc), lines}

      indent > base_indent ->
        {Enum.reverse(acc), lines}

      String.starts_with?(trimmed, "- ") ->
        value_str = String.trim(String.slice(trimmed, 2, String.length(trimmed)))

        if String.contains?(value_str, ": ") or String.ends_with?(value_str, ":") do
          # Sequence item is a mapping — parse nested
          [{_line, _num} | rest] = lines
          # Rewrite as a mapping line with proper indent
          inner_lines = [{String.duplicate(" ", indent + 2) <> value_str, 0} | rest]
          {value, remaining} = parse_node(inner_lines, indent + 2)
          parse_sequence_items(remaining, base_indent, [value | acc])
        else
          [{_line, _num} | rest] = lines
          parse_sequence_items(rest, base_indent, [parse_scalar(value_str) | acc])
        end

      trimmed == "-" ->
        [{_line, _num} | rest] = lines
        {value, remaining} = parse_node(rest, indent + 2)
        parse_sequence_items(remaining, base_indent, [value | acc])

      true ->
        {Enum.reverse(acc), lines}
    end
  end

  # ── Scalar parsing ───────────────────────────────────────────────────

  defp parse_scalar(""), do: nil
  defp parse_scalar("~"), do: nil
  defp parse_scalar("null"), do: nil
  defp parse_scalar("true"), do: true
  defp parse_scalar("false"), do: false

  # Quoted strings
  defp parse_scalar("\"" <> _ = s) do
    s
    |> String.trim_leading("\"")
    |> String.trim_trailing("\"")
  end

  defp parse_scalar("'" <> _ = s) do
    s
    |> String.trim_leading("'")
    |> String.trim_trailing("'")
  end

  # Numbers
  defp parse_scalar(s) do
    cond do
      Regex.match?(~r/^-?\d+$/, s) ->
        String.to_integer(s)

      Regex.match?(~r/^-?\d+\.\d+$/, s) ->
        String.to_float(s)

      true ->
        s
    end
  end
end
