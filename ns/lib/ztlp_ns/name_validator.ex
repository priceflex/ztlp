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
  # Matches a single DNS-compatible label: starts and ends with alnum, hyphens allowed in middle
  @label_pattern ~r/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/

  @doc """
  Validate a name for use in ZTLP-NS registration.

  Returns `:ok` if the name is valid, or `{:error, reason}` with a
  descriptive reason atom.

  ## Examples

      iex> ZtlpNs.NameValidator.validate("node1.acme.ztlp")
      :ok

      iex> ZtlpNs.NameValidator.validate("")
      {:error, :empty_name}

      iex> ZtlpNs.NameValidator.validate("UPPER.ztlp")
      {:error, :invalid_characters}
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
        validate_labels(name)
    end
  end

  def validate(_), do: {:error, :invalid_name_type}

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
        if name == suffix or String.ends_with?(name, "." <> suffix) do
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
