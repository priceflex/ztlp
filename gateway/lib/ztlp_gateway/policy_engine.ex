defmodule ZtlpGateway.PolicyEngine do
  @moduledoc """
  Access control policy engine for the ZTLP Gateway.

  Evaluates whether a given identity (represented by a zone name or
  NodeID binding) is authorized to access a specific backend service.

  ## Policy Rules

  Rules are loaded from config at startup. Each rule is a map:

      %{service: "web", allow: :all}
      %{service: "ssh", allow: ["admin.example.ztlp", "*.ops.ztlp"]}

  - `:all` — any authenticated node may access the service
  - A list of strings — only nodes whose name matches are allowed
  - Wildcards: `"*.zone.ztlp"` matches any name ending in `.zone.ztlp`

  ## Identity Representation

  In the prototype, identity is the client's static X25519 public key
  hex-encoded, or a zone name from ZTLP-NS. In production this would
  be a verified NodeID binding from the namespace.
  """

  use GenServer

  @table :ztlp_gateway_policies

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the policy engine and load rules from config."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if an identity is authorized for a service.

  ## Parameters
  - `identity` — the client's identity string (zone name, hex pubkey, etc.)
  - `service` — the backend service name

  Returns `true` if authorized, `false` if denied.
  """
  @spec authorize?(String.t(), String.t()) :: boolean()
  def authorize?(identity, service) do
    case :ets.lookup(@table, service) do
      [{^service, :all}] ->
        true

      [{^service, allowed}] when is_list(allowed) ->
        Enum.any?(allowed, fn pattern -> matches?(identity, pattern) end)

      [] ->
        # No rule for this service — deny by default (zero trust!)
        false
    end
  end

  @doc """
  Add or update a policy rule at runtime.

  ## Parameters
  - `service` — service name
  - `allow` — `:all` or list of identity patterns
  """
  @spec put_rule(String.t(), :all | [String.t()]) :: :ok
  def put_rule(service, allow) do
    :ets.insert(@table, {service, allow})
    :ok
  end

  @doc "Remove a policy rule."
  @spec delete_rule(String.t()) :: :ok
  def delete_rule(service) do
    :ets.delete(@table, service)
    :ok
  end

  @doc "List all current policy rules."
  @spec rules() :: [{String.t(), :all | [String.t()]}]
  def rules do
    :ets.tab2list(@table)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])

    # Load policies from config
    policies = ZtlpGateway.Config.get(:policies)

    Enum.each(policies, fn %{service: svc, allow: allow} ->
      :ets.insert(@table, {svc, allow})
    end)

    {:ok, %{}}
  end

  # ---------------------------------------------------------------------------
  # Pattern matching
  # ---------------------------------------------------------------------------

  # Exact match
  defp matches?(identity, pattern) when identity == pattern, do: true

  # Wildcard: "*.zone.ztlp" matches "anything.zone.ztlp"
  defp matches?(identity, <<"*.", suffix::binary>>) do
    String.ends_with?(identity, "." <> suffix)
  end

  # No match
  defp matches?(_identity, _pattern), do: false
end
