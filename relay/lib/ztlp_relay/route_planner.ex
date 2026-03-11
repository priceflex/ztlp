defmodule ZtlpRelay.RoutePlanner do
  @moduledoc """
  Multi-hop route planning for the ZTLP relay mesh.

  Given a source relay and destination relay, computes the path through
  the mesh considering relay roles:

  - **Ingress** relays accept first-contact traffic from clients
  - **Transit** relays forward between ingress and service relays
  - **Service** relays deliver to the final backend destination

  The planner produces an ordered list of relay node_ids representing
  the forwarding path from source to destination (exclusive of source,
  inclusive of destination).

  ## Algorithm

  1. If source == dest → empty path (local)
  2. If both are directly known → direct forward `[dest]`
  3. If source is ingress and dest is service → look for transit relays
     to form `[transit, dest]`
  4. Maximum hop count enforced (default 4) to prevent routing loops

  ## Configuration

  - `:max_hops` — maximum number of hops in a path (default 4)
  """

  @default_max_hops 4

  @type relay_entry :: %{
          node_id: binary(),
          address: {:inet.ip_address(), :inet.port_number()},
          role: atom()
        }

  @type plan_result :: {:ok, [relay_entry()]} | {:error, :no_route | :max_hops_exceeded}

  @doc """
  Plan a multi-hop route from `source_node_id` to `dest_node_id`.

  `registry` is a list of `relay_entry()` maps representing all known relays.

  Returns `{:ok, path}` where `path` is the ordered list of relay entries
  from next-hop to destination (source is NOT included), or `{:error, reason}`.

  An empty path `{:ok, []}` means the destination is the source itself (local).

  ## Options
  - `:max_hops` — maximum hops allowed (default #{@default_max_hops})
  """
  @spec plan(binary(), binary(), [relay_entry()], keyword()) :: plan_result()
  def plan(source_node_id, dest_node_id, registry, opts \\ [])

  def plan(source_node_id, dest_node_id, _registry, _opts)
      when source_node_id == dest_node_id do
    {:ok, []}
  end

  def plan(source_node_id, dest_node_id, registry, opts) do
    max_hops = Keyword.get(opts, :max_hops, @default_max_hops)
    registry_map = Map.new(registry, fn r -> {r.node_id, r} end)

    source = Map.get(registry_map, source_node_id)
    dest = Map.get(registry_map, dest_node_id)

    cond do
      is_nil(dest) ->
        {:error, :no_route}

      is_nil(source) ->
        # Source not in registry but dest is — direct forward
        if max_hops >= 1 do
          {:ok, [dest]}
        else
          {:error, :max_hops_exceeded}
        end

      true ->
        plan_with_roles(source, dest, registry, max_hops)
    end
  end

  @doc """
  Compute the next hop from an ordered path given the current relay's node_id.

  Returns `{:ok, next_relay}` if there's a next hop, or `:done` if the
  current relay is the final destination (or past the end of the path).
  """
  @spec next_hop(binary(), [relay_entry()]) :: {:ok, relay_entry()} | :done
  def next_hop(_current_node_id, []), do: :done

  def next_hop(current_node_id, path) do
    case Enum.find_index(path, fn r -> r.node_id == current_node_id end) do
      nil ->
        # Not in the path — forward to first entry in path
        {:ok, hd(path)}

      idx ->
        # We're at position idx — next hop is idx+1
        if idx + 1 < length(path) do
          {:ok, Enum.at(path, idx + 1)}
        else
          :done
        end
    end
  end

  @doc """
  Extract the remaining path after the current relay.

  Returns the sublist of path entries after the current relay's position.
  If the current relay is not in the path, returns the full path.
  """
  @spec remaining_path(binary(), [relay_entry()]) :: [relay_entry()]
  def remaining_path(_current_node_id, []), do: []

  def remaining_path(current_node_id, path) do
    case Enum.find_index(path, fn r -> r.node_id == current_node_id end) do
      nil -> path
      idx -> Enum.drop(path, idx + 1)
    end
  end

  # Private implementation

  defp plan_with_roles(source, dest, registry, max_hops) do
    source_role = normalize_role(source.role)
    dest_role = normalize_role(dest.role)

    path =
      case {source_role, dest_role} do
        # Ingress → Service: look for transit relays
        {:ingress, :service} ->
          find_transit_path(source, dest, registry)

        # Service → Ingress: reverse path, look for transit
        {:service, :ingress} ->
          find_transit_path(source, dest, registry)

        # Ingress → Transit: direct
        {:ingress, :transit} ->
          [dest]

        # Transit → Service: direct
        {:transit, :service} ->
          [dest]

        # Transit → Ingress: direct
        {:transit, :ingress} ->
          [dest]

        # Service → Transit: direct
        {:service, :transit} ->
          [dest]

        # Transit → Transit: direct (peer transit)
        {:transit, :transit} ->
          [dest]

        # Same role or :all — direct
        _ ->
          [dest]
      end

    if length(path) > max_hops do
      {:error, :max_hops_exceeded}
    else
      {:ok, path}
    end
  end

  defp find_transit_path(source, dest, registry) do
    # Look for transit relays (or :all relays) that could bridge
    transit_relays =
      Enum.filter(registry, fn r ->
        r.node_id != source.node_id and
          r.node_id != dest.node_id and
          r.role in [:transit, :all]
      end)

    case transit_relays do
      [] ->
        # No transit available — direct forward
        [dest]

      [transit | _rest] ->
        # Use the first available transit relay
        # In a real system, we'd score these by metrics
        [transit, dest]
    end
  end

  defp normalize_role(:all), do: :all
  defp normalize_role(:ingress), do: :ingress
  defp normalize_role(:transit), do: :transit
  defp normalize_role(:service), do: :service
  defp normalize_role(_), do: :all
end
