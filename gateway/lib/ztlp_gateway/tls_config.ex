defmodule ZtlpGateway.TlsConfig do
  @moduledoc """
  TLS/SSL configuration for ZTLP Gateway inter-component communication.

  The gateway only acts as a TLS client (connecting to NS for queries).
  When TLS is disabled (the default), returns empty option lists.
  """

  @doc """
  Returns TLS client options for outbound connections to NS.

  When TLS is disabled, returns an empty keyword list.
  """
  @spec client_opts() :: keyword()
  def client_opts do
    if enabled?() do
      base_opts = [
        verify: :verify_peer,
        depth: 3
      ]

      base_opts
      |> maybe_add_certfile()
      |> maybe_add_keyfile()
      |> maybe_add_cacertfile()
    else
      []
    end
  end

  @doc """
  Returns whether TLS is enabled.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:ztlp_gateway, :tls_enabled, false)
  end

  @doc """
  Validates that configured TLS cert files exist.

  Returns `:ok` if TLS is disabled or all files exist.
  """
  @spec validate_cert_files() :: :ok | {:error, [String.t()]}
  def validate_cert_files do
    if enabled?() do
      errors =
        [:tls_cert_file, :tls_key_file, :tls_ca_cert_file]
        |> Enum.reduce([], fn key, acc ->
          case Application.get_env(:ztlp_gateway, key) do
            nil -> acc
            path ->
              if File.exists?(path) do
                acc
              else
                ["#{key}: file not found: #{path}" | acc]
              end
          end
        end)

      case errors do
        [] -> :ok
        _ -> {:error, Enum.reverse(errors)}
      end
    else
      :ok
    end
  end

  defp maybe_add_certfile(opts) do
    case Application.get_env(:ztlp_gateway, :tls_cert_file) do
      nil -> opts
      path -> [{:certfile, String.to_charlist(path)} | opts]
    end
  end

  defp maybe_add_keyfile(opts) do
    case Application.get_env(:ztlp_gateway, :tls_key_file) do
      nil -> opts
      path -> [{:keyfile, String.to_charlist(path)} | opts]
    end
  end

  defp maybe_add_cacertfile(opts) do
    case Application.get_env(:ztlp_gateway, :tls_ca_cert_file) do
      nil -> opts
      path -> [{:cacertfile, String.to_charlist(path)} | opts]
    end
  end
end
