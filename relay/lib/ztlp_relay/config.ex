defmodule ZtlpRelay.Config do
  @moduledoc """
  Runtime configuration helpers for the ZTLP Relay.

  Reads values from application environment with sensible defaults.
  """

  @doc """
  UDP listen port. Default: 23095 (0x5A37).
  """
  @spec listen_port() :: non_neg_integer()
  def listen_port do
    case System.get_env("ZTLP_RELAY_PORT") do
      nil -> Application.get_env(:ztlp_relay, :listen_port, 23095)
      port -> String.to_integer(port)
    end
  end

  @doc """
  UDP listen address. Default: {0, 0, 0, 0} (all interfaces).
  """
  @spec listen_address() :: :inet.ip_address()
  def listen_address do
    Application.get_env(:ztlp_relay, :listen_address, {0, 0, 0, 0})
  end

  @doc """
  Session inactivity timeout in milliseconds. Default: 300_000 (5 minutes).
  """
  @spec session_timeout_ms() :: non_neg_integer()
  def session_timeout_ms do
    case System.get_env("ZTLP_RELAY_SESSION_TIMEOUT_MS") do
      nil -> Application.get_env(:ztlp_relay, :session_timeout_ms, 300_000)
      ms -> String.to_integer(ms)
    end
  end

  @doc """
  Maximum number of concurrent sessions. Default: 10_000.
  """
  @spec max_sessions() :: non_neg_integer()
  def max_sessions do
    case System.get_env("ZTLP_RELAY_MAX_SESSIONS") do
      nil -> Application.get_env(:ztlp_relay, :max_sessions, 10_000)
      n -> String.to_integer(n)
    end
  end
end
