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
  - Group: `"group:admins@zone.ztlp"` matches any member of that group
  - Role: `"role:admin"` matches any user with that role

  ## Group-Based Policy

  Group membership patterns use the `group:` prefix:

      %{service: "admin-panel", allow: ["group:admins@techrockstars.ztlp"]}

  When the policy engine encounters a `group:` pattern, it queries the
  group membership resolver (configurable, defaults to NsClient) to
  check if the identity is a member of the specified group.

  ## Role-Based Policy

  Role patterns use the `role:` prefix:

      %{service: "admin-panel", allow: ["role:admin"]}

  When the policy engine encounters a `role:` pattern, it queries the
  user record resolver to check if the identity has the specified role.

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
    authorize?(identity, service, [])
  end

  @doc """
  Check if an identity is authorized for a service, with options.

  ## Options
  - `:group_resolver` — function `(group_name, identity) -> boolean()` to check
    group membership. Defaults to `ZtlpGateway.NsClient.is_group_member?/2`.
  - `:role_resolver` — function `(identity) -> String.t() | nil` to get user role.
    Defaults to `ZtlpGateway.NsClient.user_role/1`.
  """
  @spec authorize?(String.t(), String.t(), keyword()) :: boolean()
  def authorize?(identity, service, opts) do
    case :ets.lookup(@table, service) do
      [{^service, :all}] ->
        true

      [{^service, allowed}] when is_list(allowed) ->
        Enum.any?(allowed, fn pattern -> matches?(identity, pattern, opts) end)

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
  defp matches?(identity, pattern, _opts) when identity == pattern, do: true

  # Group membership: "group:admins@zone.ztlp"
  defp matches?(identity, <<"group:", group_name::binary>>, opts) do
    resolver = Keyword.get(opts, :group_resolver)

    try do
      if resolver do
        resolver.(group_name, identity)
      else
        ZtlpGateway.NsClient.is_group_member?(group_name, identity)
      end
    rescue
      _ -> false
    catch
      :exit, _ -> false
    end
  end

  # Role matching: "role:admin"
  defp matches?(identity, <<"role:", role::binary>>, opts) do
    resolver = Keyword.get(opts, :role_resolver)

    user_role =
      try do
        if resolver do
          resolver.(identity)
        else
          ZtlpGateway.NsClient.user_role(identity)
        end
      rescue
        _ -> nil
      catch
        :exit, _ -> nil
      end

    user_role == role
  end

  # Wildcard: "*.zone.ztlp" matches "anything.zone.ztlp"
  defp matches?(identity, <<"*.", suffix::binary>>, _opts) do
    String.ends_with?(identity, "." <> suffix)
  end

  # No match
  defp matches?(_identity, _pattern, _opts), do: false
end
