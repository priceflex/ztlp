defmodule ZtlpGateway.ServiceRouterTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.ServiceRouter
  alias ZtlpGateway.ServiceRouter.Backend
  alias ZtlpGateway.ServiceRouter.CircuitBreaker

  # Helper to start a uniquely-named router per test
  defp start_router(opts) do
    name = :"router_#{System.unique_integer([:positive])}"
    opts = Keyword.put(opts, :name, name)
    {:ok, pid} = ServiceRouter.start_link(opts)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    name
  end

  # Wait for a cast to be processed by doing a synchronous call afterwards
  defp flush_casts(server), do: ServiceRouter.stats(server)

  describe "startup and backend config parsing" do
    test "starts with parsed backend config" do
      router = start_router(backends: "web:127.0.0.1:8080")
      assert {:ok, %{host: "127.0.0.1", port: 8080}} = ServiceRouter.route(router, "web")
    end

    test "parse_backend_config parses service:host:port format" do
      result = ServiceRouter.parse_backend_config("web:10.0.0.1:3000")
      assert %{"web" => [%Backend{host: "10.0.0.1", port: 3000}]} = result
    end

    test "parse_backend_config handles empty string" do
      assert %{} = ServiceRouter.parse_backend_config("")
    end

    test "parse_backend_config handles invalid entries gracefully" do
      result = ServiceRouter.parse_backend_config("bad_entry,web:10.0.0.1:3000")
      assert Map.has_key?(result, "web")
      refute Map.has_key?(result, "bad_entry")
    end

    test "parse_backend_config handles non-binary input" do
      assert %{} = ServiceRouter.parse_backend_config(nil)
    end
  end

  describe "route/2" do
    test "returns {:ok, backend} for known service" do
      router = start_router(backends: "api:10.0.0.1:4000")
      assert {:ok, %{host: "10.0.0.1", port: 4000}} = ServiceRouter.route(router, "api")
    end

    test "returns {:error, :service_not_found} for unknown service" do
      router = start_router(backends: "")
      assert {:error, :service_not_found} = ServiceRouter.route(router, "missing")
    end

    test "round-robins across multiple backends" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "a", 1)
      :ok = ServiceRouter.add_backend(router, "svc", "b", 2)

      results =
        for _ <- 1..4 do
          {:ok, backend} = ServiceRouter.route(router, "svc")
          {backend.host, backend.port}
        end

      # add_backend prepends, so order is [b, a]; round-robin cycles
      assert Enum.member?(results, {"a", 1})
      assert Enum.member?(results, {"b", 2})
      # Should cycle: we see at least 2 distinct backends
      assert length(Enum.uniq(results)) == 2
    end
  end

  describe "add_backend/5 and remove_backend/4" do
    test "adds new backend to existing service" do
      router = start_router(backends: "svc:10.0.0.1:80")
      :ok = ServiceRouter.add_backend(router, "svc", "10.0.0.2", 80)

      # Route multiple times to confirm both backends are reachable
      hosts =
        for _ <- 1..4 do
          {:ok, b} = ServiceRouter.route(router, "svc")
          b.host
        end

      assert "10.0.0.1" in hosts
      assert "10.0.0.2" in hosts
    end

    test "creates new service entry" do
      router = start_router(backends: "")
      assert {:error, :service_not_found} = ServiceRouter.route(router, "new_svc")
      :ok = ServiceRouter.add_backend(router, "new_svc", "host1", 9000)
      assert {:ok, %{host: "host1", port: 9000}} = ServiceRouter.route(router, "new_svc")
    end

    test "remove_backend removes specific backend" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "a", 1)
      :ok = ServiceRouter.add_backend(router, "svc", "b", 2)
      :ok = ServiceRouter.remove_backend(router, "svc", "b", 2)

      # Only "a" should remain
      results =
        for _ <- 1..3 do
          {:ok, b} = ServiceRouter.route(router, "svc")
          {b.host, b.port}
        end

      assert Enum.all?(results, fn r -> r == {"a", 1} end)
    end
  end

  describe "circuit breaker" do
    test "CircuitBreaker starts closed" do
      cb = %CircuitBreaker{}
      assert cb.state == :closed
    end

    test "circuit opens after failure_threshold (5) failures" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "h", 80)
      bk = "svc:h:80"

      for _ <- 1..5 do
        ServiceRouter.report_failure(router, "svc", bk)
      end

      flush_casts(router)

      # The backend should now be unhealthy
      assert {:error, :all_backends_unhealthy} = ServiceRouter.route(router, "svc")
    end

    test "open circuit rejects requests" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "h", 80)
      bk = "svc:h:80"

      # Trip the breaker
      for _ <- 1..5 do
        ServiceRouter.report_failure(router, "svc", bk)
      end

      flush_casts(router)
      assert {:error, :all_backends_unhealthy} = ServiceRouter.route(router, "svc")
    end

    test "open circuit transitions to half_open after timeout" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "h", 80)
      bk = "svc:h:80"

      # Trip the breaker
      for _ <- 1..5 do
        ServiceRouter.report_failure(router, "svc", bk)
      end

      flush_casts(router)

      # Manually set the circuit breaker last_failure to far in the past
      # to simulate timeout expiry
      :sys.replace_state(router, fn state ->
        cb = Map.get(state.circuit_breakers, bk)
        # Set last_failure to well before now - 30s
        cb = %{cb | last_failure: System.monotonic_time(:millisecond) - 60_000}
        %{state | circuit_breakers: Map.put(state.circuit_breakers, bk, cb)}
      end)

      # Should now allow a probe request
      assert {:ok, %{host: "h", port: 80}} = ServiceRouter.route(router, "svc")
    end

    test "half_open transitions to closed after success_threshold (3) successes" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "h", 80)
      bk = "svc:h:80"

      # Set up a half_open circuit breaker directly
      :sys.replace_state(router, fn state ->
        cb = %CircuitBreaker{state: :half_open, success_count: 0, success_threshold: 3}
        %{state | circuit_breakers: Map.put(state.circuit_breakers, bk, cb)}
      end)

      # Report 3 successes
      for _ <- 1..3 do
        ServiceRouter.report_success(router, "svc", bk, 10)
      end

      flush_casts(router)

      # Verify circuit is now closed by inspecting state
      state = :sys.get_state(router)
      cb = Map.get(state.circuit_breakers, bk)
      assert cb.state == :closed
      assert cb.failure_count == 0
      assert cb.success_count == 0
    end

    test "report_success resets failure count" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "h", 80)
      bk = "svc:h:80"

      # Report a few failures (but below threshold)
      for _ <- 1..3 do
        ServiceRouter.report_failure(router, "svc", bk)
      end

      flush_casts(router)
      state = :sys.get_state(router)
      assert Map.get(state.circuit_breakers, bk).failure_count == 3

      # Now a success should reset the failure count
      ServiceRouter.report_success(router, "svc", bk, 5)
      flush_casts(router)

      state = :sys.get_state(router)
      assert Map.get(state.circuit_breakers, bk).failure_count == 0
    end

    test "report_failure increments failure count" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "h", 80)
      bk = "svc:h:80"

      ServiceRouter.report_failure(router, "svc", bk)
      flush_casts(router)

      state = :sys.get_state(router)
      assert Map.get(state.circuit_breakers, bk).failure_count == 1

      ServiceRouter.report_failure(router, "svc", bk)
      flush_casts(router)

      state = :sys.get_state(router)
      assert Map.get(state.circuit_breakers, bk).failure_count == 2
    end
  end

  describe "stats/1" do
    test "returns request counts and avg latency" do
      router = start_router(backends: "svc:h:80")

      # Make some requests
      {:ok, _} = ServiceRouter.route(router, "svc")
      {:ok, _} = ServiceRouter.route(router, "svc")

      # Report latency
      ServiceRouter.report_success(router, "svc", "svc:h:80", 100)
      ServiceRouter.report_success(router, "svc", "svc:h:80", 200)
      flush_casts(router)

      stats = ServiceRouter.stats(router)
      assert %{"svc" => svc_stats} = stats
      assert svc_stats.requests == 2
      assert svc_stats.avg_latency_ms == 150.0
    end

    test "shows healthy vs total backend counts" do
      router = start_router(backends: "")
      :ok = ServiceRouter.add_backend(router, "svc", "a", 1)
      :ok = ServiceRouter.add_backend(router, "svc", "b", 2)

      # Route once to create stats entry
      {:ok, _} = ServiceRouter.route(router, "svc")

      # Trip circuit breaker for one backend
      bk = "svc:a:1"

      for _ <- 1..5 do
        ServiceRouter.report_failure(router, "svc", bk)
      end

      flush_casts(router)

      stats = ServiceRouter.stats(router)
      assert %{"svc" => svc_stats} = stats
      assert svc_stats.backends_total == 2
      assert svc_stats.backends_healthy == 1
    end
  end

  describe "SERVICE_REDIRECT frame" do
    test "build_redirect_frame produces correct wire format" do
      frame = ServiceRouter.build_redirect_frame("web", "10.0.0.1", 8443)

      # Frame type byte
      assert <<0x10, rest::binary>> = frame
      # Service name length + name
      assert <<3, "web", rest2::binary>> = rest
      # Port (16-bit big-endian)
      assert <<8443::16, "10.0.0.1">> = rest2
    end

    test "parse_redirect_frame roundtrips correctly" do
      frame = ServiceRouter.build_redirect_frame("myservice", "gw.example.com", 4433)
      assert {:ok, parsed} = ServiceRouter.parse_redirect_frame(frame)
      assert parsed.service == "myservice"
      assert parsed.addr == "gw.example.com"
      assert parsed.port == 4433
    end

    test "parse_redirect_frame rejects invalid data" do
      assert {:error, :invalid_redirect} = ServiceRouter.parse_redirect_frame(<<>>)
      assert {:error, :invalid_redirect} = ServiceRouter.parse_redirect_frame(<<0xFF, 0x00>>)
      assert {:error, :invalid_redirect} = ServiceRouter.parse_redirect_frame("garbage")
    end

    test "FRAME_SERVICE_REDIRECT constant is 0x10" do
      assert ServiceRouter.frame_service_redirect() == 0x10
    end
  end

  describe "Backend struct" do
    test "defaults are nil" do
      b = %Backend{}
      assert b.host == nil
      assert b.port == nil
      assert b.weight == nil
      assert b.max_conns == nil
      assert b.current_conns == nil
      assert b.healthy == nil
      assert b.last_check == nil
    end
  end
end
