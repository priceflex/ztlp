defmodule ZtlpGateway.CertCacheTest do
  use ExUnit.Case

  alias ZtlpGateway.CertCache

  setup do
    case GenServer.whereis(CertCache) do
      nil -> :ok
      pid ->
        GenServer.stop(pid, :normal, 5000)
        Process.sleep(50)
    end

    {:ok, pid} = CertCache.start_link()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal, 5000)
    end)

    :ok
  end

  describe "put/2 and get/1" do
    test "caches and retrieves a certificate" do
      :ok = CertCache.put("web.corp.ztlp", %{certfile: "/tmp/cert.pem", keyfile: "/tmp/key.pem"})
      {:ok, entry} = CertCache.get("web.corp.ztlp")
      assert entry.certfile == "/tmp/cert.pem"
      assert entry.keyfile == "/tmp/key.pem"
    end

    test "returns error for missing hostname" do
      assert {:error, :not_found} = CertCache.get("missing.ztlp")
    end

    test "tracks cached_at timestamp" do
      :ok = CertCache.put("web.corp.ztlp", %{certfile: "/tmp/cert.pem"})
      {:ok, entry} = CertCache.get("web.corp.ztlp")
      assert is_integer(entry.cached_at)
    end
  end

  describe "delete/1" do
    test "removes a cached certificate" do
      :ok = CertCache.put("web.corp.ztlp", %{certfile: "/tmp/cert.pem"})
      :ok = CertCache.delete("web.corp.ztlp")
      assert {:error, :not_found} = CertCache.get("web.corp.ztlp")
    end
  end

  describe "list/0" do
    test "lists all cached certificates" do
      :ok = CertCache.put("web.corp.ztlp", %{certfile: "/tmp/cert1.pem"})
      :ok = CertCache.put("api.corp.ztlp", %{certfile: "/tmp/cert2.pem"})
      entries = CertCache.list()
      assert length(entries) >= 2
    end
  end

  describe "clear/0" do
    test "removes all cached certificates" do
      :ok = CertCache.put("web.corp.ztlp", %{certfile: "/tmp/cert1.pem"})
      :ok = CertCache.put("api.corp.ztlp", %{certfile: "/tmp/cert2.pem"})
      :ok = CertCache.clear()
      assert CertCache.list() == []
    end
  end

  describe "expiry" do
    test "expired entries return error" do
      :ok = CertCache.put("web.corp.ztlp", %{
        certfile: "/tmp/cert.pem",
        expires_at: System.system_time(:second) - 100
      })
      assert {:error, :expired} = CertCache.get("web.corp.ztlp")
    end
  end
end
