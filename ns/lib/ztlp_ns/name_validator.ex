defmodule ZtlpNs.NameValidator do
  @moduledoc """
  DNS-compatible name validation for ZTLP-NS.

  Validates record names against a strict format:
  - Max 253 bytes total (DNS compatibility)
  - Lowercase alphanumeric, hyphens, and dots only
  - Labels separated by dots
  - No leading/trailing hyphens per label
  - Each label max 63 bytes
  - Must have at least one label

  ## Security Rationale

  Name validation prevents:
  - Injection attacks via special characters
  - Namespace confusion via homoglyph or unicode names
  - Oversized names that could exhaust storage or bandwidth
  """

  @max_name_length 253
  @max_label_length 63
  # Matches a single DNS-compatible label: starts and ends with alnum, hyphens allowed in middle.
  # The `@` character is also permitted to support ZTLP identity names (e.g., steve@zone.ztlp).
  @label_pattern ~r/^[a-z0-9@]([a-z0-9\-@]*[a-z0-9@])?$/

  @doc """
  Validate a name for use in ZTLP-NS registration.

  Returns `:ok` if the name is valid, or `{:error, reason}` with a
  descriptive reason atom.

  ZTLP names are **case-insensitive** (DNS-aligned). Mixed-case input
  is accepted and considered valid; callers that need the canonical
  storage / lookup form should call `canonicalize/1` to lowercase the
  name before keying into the Store.

  ## Examples

      iex> ZtlpNs.NameValidator.validate("node1.acme.ztlp")
      :ok

      iex> ZtlpNs.NameValidator.validate("")
      {:error, :empty_name}

      iex> ZtlpNs.NameValidator.validate("Node1.Acme.Ztlp")
      :ok
  """
  @spec validate(String.t()) :: :ok | {:error, atom()}
  def validate(name) when is_binary(name) do
    cond do
      byte_size(name) == 0 ->
        {:error, :empty_name}

      byte_size(name) > @max_name_length ->
        {:error, :name_too_long}

      # Check for null bytes or non-printable characters
      String.contains?(name, <<0>>) ->
        {:error, :invalid_characters}

      true ->
        validate_labels(canonicalize(name))
    end
  end

  def validate(_), do: {:error, :invalid_name_type}

  @doc """
  Return the canonical (storage / lookup) form of a name.

  ZTLP names are case-insensitive per DNS conventions. The canonical
  form is the ASCII-lowercased string. Callers MUST use this form as
  the Mnesia key when inserting or looking up records so that
  `Foo.ztlp` and `foo.ztlp` resolve to the same record.

  This is intentionally a no-op for already-lowercase input so that
  the v0.34.0..v0.34.2 on-disk schema (which is uniformly lowercase
  except for one stale TRSDC ghost) is binary-compatible.

  ## Examples

      iex> ZtlpNs.NameValidator.canonicalize("TRSDC.trs.ztlp")
      "trsdc.trs.ztlp"

      iex> ZtlpNs.NameValidator.canonicalize("acme.ztlp")
      "acme.ztlp"
  """
  @spec canonicalize(String.t()) :: String.t()
  def canonicalize(name) when is_binary(name) do
    String.downcase(name, :ascii)
  end

  @doc """
  Validate a name and check it ends with the expected zone suffix.

  The suffix check is optional — pass `nil` to skip it.

  ## Examples

      iex> ZtlpNs.NameValidator.validate_with_suffix("node1.acme.ztlp", "ztlp")
      :ok

      iex> ZtlpNs.NameValidator.validate_with_suffix("node1.acme.other", "ztlp")
      {:error, :invalid_zone_suffix}
  """
  @spec validate_with_suffix(String.t(), String.t() | nil) :: :ok | {:error, atom()}
  def validate_with_suffix(name, nil), do: validate(name)

  def validate_with_suffix(name, suffix) when is_binary(name) and is_binary(suffix) do
    case validate(name) do
      :ok ->
        # Case-insensitive suffix match — both sides canonicalized.
        canon_name = canonicalize(name)
        canon_suffix = canonicalize(suffix)

        if canon_name == canon_suffix or String.ends_with?(canon_name, "." <> canon_suffix) do
          :ok
        else
          {:error, :invalid_zone_suffix}
        end

      error ->
        error
    end
  end

  # Validate each dot-separated label
  defp validate_labels(name) do
    labels = String.split(name, ".")

    cond do
      labels == [""] ->
        {:error, :empty_name}

      Enum.any?(labels, &(&1 == "")) ->
        {:error, :empty_label}

      Enum.any?(labels, &(byte_size(&1) > @max_label_length)) ->
        {:error, :label_too_long}

      Enum.all?(labels, &Regex.match?(@label_pattern, &1)) ->
        :ok

      true ->
        {:error, :invalid_characters}
    end
  end
end
