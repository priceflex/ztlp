defmodule ZtlpNs.Config do
  @moduledoc """
  Runtime configuration for ZTLP-NS.

  All configuration is read from application environment at runtime
  (not compile time) so it can be overridden in config files or at boot.

  ## Configuration Keys

  - `:port` — UDP port for the namespace query server (default: 23096).
    Use 0 for OS-assigned port (useful in tests and dev).
  - `:max_records` — Maximum records in the store (default: 100_000).
  - `:bootstrap_urls` — List of HTTPS URLs for bootstrap discovery.
  """

  @doc "UDP port for the namespace query server."
  @spec port() :: non_neg_integer()
  def port do
    case System.get_env("ZTLP_NS_PORT") do
      nil -> Application.get_env(:ztlp_ns, :port, 23096)
      port -> String.to_integer(port)
    end
  end

  @doc "Maximum records allowed in the store."
  @spec max_records() :: non_neg_integer()
  def max_records do
    case System.get_env("ZTLP_NS_MAX_RECORDS") do
      nil -> Application.get_env(:ztlp_ns, :max_records, 100_000)
      n -> String.to_integer(n)
    end
  end

  @doc "HTTPS URLs for bootstrap relay discovery (Step 1 of NIP)."
  @spec bootstrap_urls() :: [String.t()]
  def bootstrap_urls do
    Application.get_env(:ztlp_ns, :bootstrap_urls, [
      "https://bootstrap.ztlp.org/.well-known/ztlp-relays.json"
    ])
  end
end
