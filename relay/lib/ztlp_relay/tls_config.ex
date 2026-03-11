defmodule ZtlpRelay.TlsConfig do
  @moduledoc """
  TLS/SSL configuration for ZTLP Relay inter-component communication.

  Provides client and server TLS options using Erlang's built-in `:ssl` module.
  When TLS is disabled (the default), returns empty option lists so plain UDP
  continues to work unchanged.

  ## Configuration

  TLS settings are read from the OTP application environment under `:ztlp_relay`:

  - `:tls_enabled` — boolean, default `false`
  - `:tls_cert_file` — path to PEM-encoded certificate
  - `:tls_key_file` — path to PEM-encoded private key
  - `:tls_ca_cert_file` — path to PEM-encoded CA certificate bundle

  These are populated by `ZtlpRelay.YamlConfig` from the `tls:` YAML section.
  """

  require Logger

  @doc """
  Returns TLS client options for outbound connections (e.g., to NS).

  When TLS is disabled, returns an empty keyword list.
  When enabled, returns options suitable for `:ssl.connect/3`.
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
  Returns TLS server options for accepting inbound connections (e.g., mesh listener).

  When TLS is disabled, returns an empty keyword list.
  When enabled, returns options suitable for `:ssl.listen/2` or handshake.
  """
  @spec server_opts() :: keyword()
  def server_opts do
    if enabled?() do
      base_opts = [
        verify: :verify_peer,
        fail_if_no_peer_cert: true,
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
    Application.get_env(:ztlp_relay, :tls_enabled, false)
  end

  @doc """
  Validates that configured TLS cert files exist.

  Returns `:ok` if TLS is disabled or all files exist,
  `{:error, reasons}` if any configured files are missing.
  """
  @spec validate_cert_files() :: :ok | {:error, [String.t()]}
  def validate_cert_files do
    if enabled?() do
      errors =
        [:tls_cert_file, :tls_key_file, :tls_ca_cert_file]
        |> Enum.reduce([], fn key, acc ->
          case Application.get_env(:ztlp_relay, key) do
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

  # ── Internal ──────────────────────────────────────────────────────────

  defp maybe_add_certfile(opts) do
    case Application.get_env(:ztlp_relay, :tls_cert_file) do
      nil -> opts
      path -> [{:certfile, ensure_charlist(path)} | opts]
    end
  end

  defp maybe_add_keyfile(opts) do
    case Application.get_env(:ztlp_relay, :tls_key_file) do
      nil -> opts
      path -> [{:keyfile, ensure_charlist(path)} | opts]
    end
  end

  defp maybe_add_cacertfile(opts) do
    case Application.get_env(:ztlp_relay, :tls_ca_cert_file) do
      nil -> opts
      path -> [{:cacertfile, ensure_charlist(path)} | opts]
    end
  end

  defp ensure_charlist(s) when is_binary(s), do: String.to_charlist(s)
  defp ensure_charlist(s) when is_list(s), do: s
end
