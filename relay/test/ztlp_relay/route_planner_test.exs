defmodule ZtlpRelay.RoutePlannerTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.RoutePlanner

  defp make_relay(role) do
    node_id = :crypto.strong_rand_bytes(16)

    %{
      node_id: node_id,
      address: {{127, 0, 0, 1}, Enum.random(10000..60000)},
      role: role
    }
  end

  describe "plan/4" do
    test "returns empty path when source equals destination" do
      node_id = :crypto.strong_rand_bytes(16)
      registry = [%{node_id: node_id, address: {{127, 0, 0, 1}, 9000}, role: :ingress}]
      assert {:ok, []} = RoutePlanner.plan(node_id, node_id, registry)
    end

    test "returns direct path when both relays are known" do
      ingress = make_relay(:ingress)
      service = make_relay(:ingress)
      registry = [ingress, service]

      assert {:ok, [dest]} = RoutePlanner.plan(ingress.node_id, service.node_id, registry)
      assert dest.node_id == service.node_id
    end

    test "returns transit route when ingress → service with transit available" do
      ingress = make_relay(:ingress)
      transit = make_relay(:transit)
      service = make_relay(:service)
      registry = [ingress, transit, service]

      assert {:ok, path} = RoutePlanner.plan(ingress.node_id, service.node_id, registry)
      assert length(path) == 2
      assert hd(path).node_id == transit.node_id
      assert List.last(path).node_id == service.node_id
    end

    test "returns direct route for ingress → service with no transit" do
      ingress = make_relay(:ingress)
      service = make_relay(:service)
      registry = [ingress, service]

      assert {:ok, [dest]} = RoutePlanner.plan(ingress.node_id, service.node_id, registry)
      assert dest.node_id == service.node_id
    end

    test "returns transit route for service → ingress" do
      ingress = make_relay(:ingress)
      transit = make_relay(:transit)
      service = make_relay(:service)
      registry = [ingress, transit, service]

      assert {:ok, path} = RoutePlanner.plan(service.node_id, ingress.node_id, registry)
      assert length(path) == 2
    end

    test "returns direct route for transit → service" do
      transit = make_relay(:transit)
      service = make_relay(:service)
      registry = [transit, service]

      assert {:ok, [dest]} = RoutePlanner.plan(transit.node_id, service.node_id, registry)
      assert dest.node_id == service.node_id
    end

    test "returns direct route for ingress → transit" do
      ingress = make_relay(:ingress)
      transit = make_relay(:transit)
      registry = [ingress, transit]

      assert {:ok, [dest]} = RoutePlanner.plan(ingress.node_id, transit.node_id, registry)
      assert dest.node_id == transit.node_id
    end

    test "returns :no_route when destination is not in registry" do
      source = make_relay(:ingress)
      unknown_id = :crypto.strong_rand_bytes(16)
      registry = [source]

      assert {:error, :no_route} = RoutePlanner.plan(source.node_id, unknown_id, registry)
    end

    test "returns :max_hops_exceeded when path exceeds max hops" do
      ingress = make_relay(:ingress)
      transit = make_relay(:transit)
      service = make_relay(:service)
      registry = [ingress, transit, service]

      # With max_hops = 1, the 2-hop ingress → transit → service path should fail
      assert {:error, :max_hops_exceeded} =
               RoutePlanner.plan(ingress.node_id, service.node_id, registry, max_hops: 1)
    end

    test "handles :all role relays (direct route)" do
      relay_a = make_relay(:all)
      relay_b = make_relay(:all)
      registry = [relay_a, relay_b]

      assert {:ok, [dest]} = RoutePlanner.plan(relay_a.node_id, relay_b.node_id, registry)
      assert dest.node_id == relay_b.node_id
    end

    test ":all role relay can serve as transit" do
      ingress = make_relay(:ingress)
      all_relay = make_relay(:all)
      service = make_relay(:service)
      registry = [ingress, all_relay, service]

      assert {:ok, path} = RoutePlanner.plan(ingress.node_id, service.node_id, registry)
      # Should use the :all relay as transit
      assert length(path) == 2
      transit_node = hd(path)
      assert transit_node.node_id == all_relay.node_id
    end

    test "source not in registry but dest is — direct forward" do
      unknown_source = :crypto.strong_rand_bytes(16)
      dest = make_relay(:service)
      registry = [dest]

      assert {:ok, [d]} = RoutePlanner.plan(unknown_source, dest.node_id, registry)
      assert d.node_id == dest.node_id
    end
  end

  describe "next_hop/2" do
    test "returns first entry when current not in path" do
      relay_a = make_relay(:transit)
      relay_b = make_relay(:service)
      path = [relay_a, relay_b]

      current = :crypto.strong_rand_bytes(16)
      assert {:ok, ^relay_a} = RoutePlanner.next_hop(current, path)
    end

    test "returns next entry when current is in path" do
      relay_a = make_relay(:transit)
      relay_b = make_relay(:service)
      path = [relay_a, relay_b]

      assert {:ok, ^relay_b} = RoutePlanner.next_hop(relay_a.node_id, path)
    end

    test "returns :done when current is last in path" do
      relay_a = make_relay(:transit)
      relay_b = make_relay(:service)
      path = [relay_a, relay_b]

      assert :done = RoutePlanner.next_hop(relay_b.node_id, path)
    end

    test "returns :done for empty path" do
      assert :done = RoutePlanner.next_hop(:crypto.strong_rand_bytes(16), [])
    end
  end

  describe "remaining_path/2" do
    test "returns entries after current relay" do
      relay_a = make_relay(:transit)
      relay_b = make_relay(:transit)
      relay_c = make_relay(:service)
      path = [relay_a, relay_b, relay_c]

      remaining = RoutePlanner.remaining_path(relay_a.node_id, path)
      assert length(remaining) == 2
      assert hd(remaining).node_id == relay_b.node_id
    end

    test "returns full path when current not found" do
      path = [make_relay(:transit), make_relay(:service)]
      unknown = :crypto.strong_rand_bytes(16)

      assert RoutePlanner.remaining_path(unknown, path) == path
    end

    test "returns empty list when current is last" do
      relay = make_relay(:service)
      assert RoutePlanner.remaining_path(relay.node_id, [relay]) == []
    end
  end
end
