defmodule ZtlpGateway.HttpHeaderInjectorTest do
  use ExUnit.Case

  alias ZtlpGateway.HttpHeaderInjector
  alias ZtlpGateway.SniRouter

  setup do
    # Start SniRouter for route lookups
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

  defp make_http_request(method \\ "GET", path \\ "/", headers \\ []) do
    header_lines = Enum.map(headers, fn {k, v} -> "#{k}: #{v}" end)
    lines = ["#{method} #{path} HTTP/1.1" | header_lines]
    Enum.join(lines, "\r\n") <> "\r\n\r\n"
  end

  defp make_identity(opts \\ []) do
    %{
      node_id: Keyword.get(opts, :node_id, "abcdef1234567890"),
      node_name: Keyword.get(opts, :node_name, "test-node.corp.ztlp"),
      zone: Keyword.get(opts, :zone, "corp.ztlp"),
      assurance: Keyword.get(opts, :assurance, :software),
      key_source: Keyword.get(opts, :key_source, "file"),
      attestation_verified: Keyword.get(opts, :attestation_verified, false),
      cert_fingerprint: Keyword.get(opts, :cert_fingerprint, "aa" <> String.duplicate("bb", 31)),
      cert_serial: Keyword.get(opts, :cert_serial, "12345"),
      authenticated: Keyword.get(opts, :authenticated, true)
    }
  end

  describe "build_headers/1" do
    test "builds all 11 identity headers" do
      identity = make_identity()
      headers = HttpHeaderInjector.build_headers(identity)
      assert length(headers) == 11

      header_map = Map.new(headers)
      assert header_map["X-ZTLP-Node-ID"] == "abcdef1234567890"
      assert header_map["X-ZTLP-Node-Name"] == "test-node.corp.ztlp"
      assert header_map["X-ZTLP-Zone"] == "corp.ztlp"
      assert header_map["X-ZTLP-Authenticated"] == "true"
      assert header_map["X-ZTLP-Assurance"] == "software"
      assert header_map["X-ZTLP-Key-Source"] == "file"
      assert header_map["X-ZTLP-Key-Attestation"] == "unverified"
      assert header_map["X-ZTLP-Cert-Fingerprint"] != nil
      assert header_map["X-ZTLP-Cert-Serial"] == "12345"
      assert header_map["X-ZTLP-Timestamp"] != nil
      assert header_map["X-ZTLP-Signature"] != nil
    end

    test "hardware assurance shows 'hardware'" do
      identity = make_identity(assurance: :hardware)
      headers = Map.new(HttpHeaderInjector.build_headers(identity))
      assert headers["X-ZTLP-Assurance"] == "hardware"
    end

    test "device-bound assurance" do
      identity = make_identity(assurance: :device_bound)
      headers = Map.new(HttpHeaderInjector.build_headers(identity))
      assert headers["X-ZTLP-Assurance"] == "device-bound"
    end

    test "verified attestation" do
      identity = make_identity(attestation_verified: true)
      headers = Map.new(HttpHeaderInjector.build_headers(identity))
      assert headers["X-ZTLP-Key-Attestation"] == "verified"
    end

    test "nil identity produces anonymous headers" do
      headers = Map.new(HttpHeaderInjector.build_headers(nil))
      assert headers["X-ZTLP-Authenticated"] == "false"
      assert headers["X-ZTLP-Assurance"] == "unknown"
    end
  end

  describe "strip_ztlp_headers/1" do
    test "removes X-ZTLP-* headers" do
      request = make_http_request("GET", "/", [
        {"Host", "example.com"},
        {"X-ZTLP-Node-ID", "fake-id"},
        {"X-ZTLP-Assurance", "hardware"},
        {"Accept", "text/html"}
      ])

      stripped = HttpHeaderInjector.strip_ztlp_headers(request)
      refute String.contains?(stripped, "X-ZTLP-Node-ID")
      refute String.contains?(stripped, "X-ZTLP-Assurance")
      assert String.contains?(stripped, "Host: example.com")
      assert String.contains?(stripped, "Accept: text/html")
    end

    test "handles request with no ZTLP headers" do
      request = make_http_request("GET", "/", [{"Host", "example.com"}])
      stripped = HttpHeaderInjector.strip_ztlp_headers(request)
      assert String.contains?(stripped, "Host: example.com")
    end
  end

  describe "inject/3 with passthrough mode" do
    test "returns data unchanged" do
      request = make_http_request("GET", "/", [{"Host", "example.com"}])
      result = HttpHeaderInjector.inject(request, make_identity(), nil)
      assert result == request
    end
  end

  describe "inject/3 with identity mode" do
    setup do
      SniRouter.put_route("web.corp.ztlp", "127.0.0.1:8080", auth_mode: :identity)
      :ok
    end

    test "injects identity headers" do
      request = make_http_request("GET", "/", [{"Host", "web.corp.ztlp"}])
      result = HttpHeaderInjector.inject(request, make_identity(), "web.corp.ztlp")
      assert String.contains?(result, "X-ZTLP-Node-ID: abcdef1234567890")
      assert String.contains?(result, "X-ZTLP-Authenticated: true")
    end

    test "strips forged X-ZTLP headers from client" do
      request = make_http_request("GET", "/", [
        {"Host", "web.corp.ztlp"},
        {"X-ZTLP-Node-ID", "forged-id"},
        {"X-ZTLP-Assurance", "hardware"}
      ])
      result = HttpHeaderInjector.inject(request, make_identity(node_id: "real-id"), "web.corp.ztlp")
      # Should have the real ID, not the forged one
      assert String.contains?(result, "X-ZTLP-Node-ID: real-id")
      refute String.contains?(result, "forged-id")
    end
  end

  describe "inject/3 with enforce mode" do
    setup do
      SniRouter.put_route("secure.corp.ztlp", "127.0.0.1:9090",
        auth_mode: :enforce, min_assurance: :software)
      :ok
    end

    test "allows authenticated request" do
      request = make_http_request("GET", "/", [{"Host", "secure.corp.ztlp"}])
      result = HttpHeaderInjector.inject(request, make_identity(), "secure.corp.ztlp")
      assert String.contains?(result, "X-ZTLP-Authenticated: true")
    end

    test "rejects unauthenticated request with 401" do
      request = make_http_request("GET", "/", [{"Host", "secure.corp.ztlp"}])
      result = HttpHeaderInjector.inject(request, nil, "secure.corp.ztlp")
      assert String.contains?(result, "401 Unauthorized")
    end

    test "rejects low assurance with 403" do
      SniRouter.put_route("high-sec.corp.ztlp", "127.0.0.1:9091",
        auth_mode: :enforce, min_assurance: :hardware)
      request = make_http_request("GET", "/", [{"Host", "high-sec.corp.ztlp"}])
      identity = make_identity(assurance: :software)
      result = HttpHeaderInjector.inject(request, identity, "high-sec.corp.ztlp")
      assert String.contains?(result, "403 Forbidden")
    end

    test "accepts sufficient assurance" do
      SniRouter.put_route("med-sec.corp.ztlp", "127.0.0.1:9092",
        auth_mode: :enforce, min_assurance: :software)
      request = make_http_request("GET", "/", [{"Host", "med-sec.corp.ztlp"}])
      identity = make_identity(assurance: :hardware)
      result = HttpHeaderInjector.inject(request, identity, "med-sec.corp.ztlp")
      assert String.contains?(result, "X-ZTLP-Authenticated: true")
    end
  end
end
