defmodule ZtlpGateway.SniRouterTest do
  use ExUnit.Case

  alias ZtlpGateway.SniRouter

  setup do
    # Stop existing router if running
    case GenServer.whereis(SniRouter) do
      nil -> :ok
      pid ->
        GenServer.stop(pid, :normal, 5000)
        Process.sleep(50)
    end

    {:ok, pid} = SniRouter.start_link(routes: [])

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5000)
    end)

    :ok
  end

  describe "put_route/3 and resolve/1" do
    test "adds and resolves a route" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080")
      assert SniRouter.resolve("web.corp.ztlp") == "web.corp.ztlp"
    end

    test "resolves with custom service name" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080", service: "web-service")
      assert SniRouter.resolve("web.corp.ztlp") == "web-service"
    end

    test "resolve returns hostname for unknown routes" do
      assert SniRouter.resolve("unknown.ztlp") == "unknown.ztlp"
    end

    test "resolve handles nil" do
      assert SniRouter.resolve(nil) == nil
    end

    test "resolve handles charlist" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080")
      assert SniRouter.resolve('web.corp.ztlp') == "web.corp.ztlp"
    end
  end

  describe "backend_for/1" do
    test "returns backend host and port" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080")
      assert {:ok, {{127, 0, 0, 1}, 8080}} = SniRouter.backend_for("web.corp.ztlp")
    end

    test "returns error for unknown service" do
      assert {:error, :no_route} = SniRouter.backend_for("nonexistent.ztlp")
    end

    test "returns error for nil" do
      assert {:error, :no_route} = SniRouter.backend_for(nil)
    end
  end

  describe "get_route/1" do
    test "returns route config" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080",
        auth_mode: :enforce, min_assurance: :software)
      {:ok, route} = SniRouter.get_route("web.corp.ztlp")
      assert route.auth_mode == :enforce
      assert route.min_assurance == :software
      assert route.backend == "127.0.0.1:8080"
    end

    test "returns error for unknown hostname" do
      assert {:error, :not_found} = SniRouter.get_route("missing.ztlp")
    end
  end

  describe "delete_route/1" do
    test "removes a route" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080")
      :ok = SniRouter.delete_route("web.corp.ztlp")
      assert {:error, :not_found} = SniRouter.get_route("web.corp.ztlp")
    end
  end

  describe "list_routes/0" do
    test "lists all routes" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080")
      :ok = SniRouter.put_route("api.corp.ztlp", "127.0.0.1:3000")
      routes = SniRouter.list_routes()
      assert length(routes) >= 2
    end
  end

  describe "auth modes" do
    test "passthrough is default" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080")
      {:ok, route} = SniRouter.get_route("web.corp.ztlp")
      assert route.auth_mode == :passthrough
    end

    test "identity mode" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080", auth_mode: :identity)
      {:ok, route} = SniRouter.get_route("web.corp.ztlp")
      assert route.auth_mode == :identity
    end

    test "enforce mode" do
      :ok = SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080", auth_mode: :enforce)
      {:ok, route} = SniRouter.get_route("web.corp.ztlp")
      assert route.auth_mode == :enforce
    end
  end
end
