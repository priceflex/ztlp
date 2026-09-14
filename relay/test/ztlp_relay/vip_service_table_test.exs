defmodule ZtlpRelay.VipServiceTableTest do
  # async: false — the module owns a global named ETS table
  # (:ztlp_vip_service_table) and reads process-global env vars.
  use ExUnit.Case, async: false

  alias ZtlpRelay.VipServiceTable

  @table :ztlp_vip_service_table

  # The Application only starts VipServiceTable when VIP mode is enabled,
  # which it is not in the test env. Start it per-test and make sure any
  # stale table from a previous test is gone first.
  defp start_table(context_env \\ []) do
    if :ets.whereis(@table) != :undefined do
      # Owner is a previous GenServer that has been stopped by
      # start_supervised cleanup; wait for the table to go away.
      wait_for_table_gone()
    end

    prev = System.get_env("ZTLP_RELAY_VIP_SERVICES")
    prev_app = Application.get_env(:ztlp_relay, :vip_services)

    case Keyword.fetch(context_env, :env) do
      {:ok, nil} -> System.delete_env("ZTLP_RELAY_VIP_SERVICES")
      {:ok, v} -> System.put_env("ZTLP_RELAY_VIP_SERVICES", v)
      :error -> System.delete_env("ZTLP_RELAY_VIP_SERVICES")
    end

    case Keyword.fetch(context_env, :app) do
      {:ok, v} -> Application.put_env(:ztlp_relay, :vip_services, v)
      :error -> Application.delete_env(:ztlp_relay, :vip_services)
    end

    on_exit(fn ->
      if prev, do: System.put_env("ZTLP_RELAY_VIP_SERVICES", prev), else: System.delete_env("ZTLP_RELAY_VIP_SERVICES")
      if prev_app, do: Application.put_env(:ztlp_relay, :vip_services, prev_app), else: Application.delete_env(:ztlp_relay, :vip_services)
    end)

    pid = start_supervised!(VipServiceTable)
    pid
  end

  defp wait_for_table_gone(attempts \\ 50) do
    cond do
      :ets.whereis(@table) == :undefined -> :ok
      attempts == 0 -> flunk("stale #{@table} never went away")
      true ->
        Process.sleep(10)
        wait_for_table_gone(attempts - 1)
    end
  end

  describe "when the table GenServer is not running" do
    setup do
      if :ets.whereis(@table) != :undefined, do: wait_for_table_gone()
      :ok
    end

    test "lookup/1 returns :error instead of raising" do
      assert VipServiceTable.lookup("web") == :error
    end

    test "vip_service?/1 returns false instead of raising" do
      refute VipServiceTable.vip_service?("web")
    end

    # Regression: `:ets.info(tab, :size)` returns `:undefined` for a missing
    # table (does not raise), so a rescue-only count/0 leaked :undefined.
    test "count/0 returns 0 (not :undefined) when the table is missing" do
      assert VipServiceTable.count() == 0
    end
  end

  describe "start_link/1 with no configuration" do
    test "starts empty and is registered under the module name" do
      pid = start_table()
      assert Process.whereis(VipServiceTable) == pid
      assert VipServiceTable.count() == 0
      assert VipServiceTable.list() == []
    end

    test "ETS table is public and named so callers bypass the GenServer" do
      start_table()
      info = :ets.info(@table)
      assert info[:named_table]
      assert info[:protection] == :public
      assert info[:type] == :set
    end
  end

  describe "register/2, lookup/1, vip_service?/1, unregister/1" do
    setup do
      start_table()
      :ok
    end

    test "register then lookup round-trips the backend address" do
      assert :ok = VipServiceTable.register("web", {{10, 0, 0, 5}, 8080})
      assert {:ok, {{10, 0, 0, 5}, 8080}} = VipServiceTable.lookup("web")
      assert VipServiceTable.vip_service?("web")
      assert VipServiceTable.count() == 1
    end

    test "lookup of an unknown service is :error and vip_service? is false" do
      assert VipServiceTable.lookup("nope") == :error
      refute VipServiceTable.vip_service?("nope")
    end

    test "register overwrites an existing mapping (set semantics)" do
      VipServiceTable.register("web", {{10, 0, 0, 5}, 8080})
      VipServiceTable.register("web", {{10, 0, 0, 6}, 9090})
      assert {:ok, {{10, 0, 0, 6}, 9090}} = VipServiceTable.lookup("web")
      assert VipServiceTable.count() == 1
    end

    test "service names are case-sensitive exact matches" do
      VipServiceTable.register("Web", {{10, 0, 0, 5}, 80})
      assert VipServiceTable.lookup("web") == :error
      assert {:ok, _} = VipServiceTable.lookup("Web")
    end

    test "unregister removes the mapping and is idempotent" do
      VipServiceTable.register("web", {{10, 0, 0, 5}, 8080})
      assert :ok = VipServiceTable.unregister("web")
      assert VipServiceTable.lookup("web") == :error
      assert :ok = VipServiceTable.unregister("web")
      assert VipServiceTable.count() == 0
    end

    test "empty service name is rejected by register and lookup guards" do
      assert_raise FunctionClauseError, fn -> VipServiceTable.register("", {{1, 1, 1, 1}, 1}) end
      assert_raise FunctionClauseError, fn -> VipServiceTable.lookup("") end
    end

    test "non-binary service names are rejected by guards" do
      assert_raise FunctionClauseError, fn -> VipServiceTable.lookup(:web) end
      assert_raise FunctionClauseError, fn -> VipServiceTable.vip_service?(123) end
      assert_raise FunctionClauseError, fn -> VipServiceTable.unregister(nil) end
    end

    test "list/0 returns every registered mapping" do
      VipServiceTable.register("a", {{1, 1, 1, 1}, 1})
      VipServiceTable.register("b", {{2, 2, 2, 2}, 2})
      assert Enum.sort(VipServiceTable.list()) == [{"a", {{1, 1, 1, 1}, 1}}, {"b", {{2, 2, 2, 2}, 2}}]
    end

    test "IPv6 backend addresses are stored as-is" do
      addr = {{0, 0, 0, 0, 0, 0, 0, 1}, 443}
      VipServiceTable.register("v6", addr)
      assert {:ok, ^addr} = VipServiceTable.lookup("v6")
    end
  end

  describe "load_from_string/1" do
    setup do
      start_table()
      :ok
    end

    test "parses a well-formed multi-service spec" do
      assert :ok = VipServiceTable.load_from_string("web=10.0.0.5:8080,db=10.0.0.6:5432")
      assert {:ok, {{10, 0, 0, 5}, 8080}} = VipServiceTable.lookup("web")
      assert {:ok, {{10, 0, 0, 6}, 5432}} = VipServiceTable.lookup("db")
      assert VipServiceTable.count() == 2
    end

    test "trims whitespace around entries, names and addresses" do
      assert :ok = VipServiceTable.load_from_string("  web = 10.0.0.5:8080 , db= 10.0.0.6:5432  ")
      assert {:ok, _} = VipServiceTable.lookup("web")
      assert {:ok, _} = VipServiceTable.lookup("db")
    end

    test "skips trailing/duplicate commas" do
      assert :ok = VipServiceTable.load_from_string("web=10.0.0.5:8080,,db=10.0.0.6:5432,")
      assert VipServiceTable.count() == 2
    end

    test "empty string is a no-op :ok" do
      assert :ok = VipServiceTable.load_from_string("")
      assert VipServiceTable.count() == 0
    end

    test "entries without '=' are skipped, valid siblings still load" do
      assert :ok = VipServiceTable.load_from_string("garbage,web=10.0.0.5:8080")
      assert VipServiceTable.count() == 1
      assert {:ok, _} = VipServiceTable.lookup("web")
      assert VipServiceTable.lookup("garbage") == :error
    end

    test "entries with a non-numeric port are skipped" do
      assert :ok = VipServiceTable.load_from_string("web=10.0.0.5:http,db=10.0.0.6:5432")
      assert VipServiceTable.lookup("web") == :error
      assert {:ok, _} = VipServiceTable.lookup("db")
    end

    test "entries with trailing junk after the port are skipped" do
      assert :ok = VipServiceTable.load_from_string("web=10.0.0.5:8080x")
      assert VipServiceTable.count() == 0
    end

    test "entries with a hostname instead of an IP literal are skipped" do
      # Routing must not depend on DNS at load time — only IP literals.
      assert :ok = VipServiceTable.load_from_string("web=backend.internal:8080")
      assert VipServiceTable.count() == 0
    end

    test "entries with no port are skipped" do
      assert :ok = VipServiceTable.load_from_string("web=10.0.0.5")
      assert VipServiceTable.count() == 0
    end

    test "a bare IPv6 literal with colons is not parseable as host:port and is skipped" do
      # Documented limitation: parse_host_port splits on ':' so IPv6 needs
      # a different syntax. Pin this so a future bracket-syntax addition is
      # deliberate and tested.
      assert :ok = VipServiceTable.load_from_string("v6=::1:443")
      assert VipServiceTable.count() == 0
    end

    test "'=' inside the address is kept (parts: 2)" do
      assert :ok = VipServiceTable.load_from_string("web=10.0.0.5:8080=extra")
      assert VipServiceTable.count() == 0
    end

    test "later duplicate names win over earlier ones" do
      # reduce prepends, Enum.each registers in reverse-then-forward order:
      # pin the observable outcome so refactors keep it deterministic.
      assert :ok = VipServiceTable.load_from_string("web=10.0.0.1:1,web=10.0.0.2:2")
      assert {:ok, {{10, 0, 0, 1}, 1}} = VipServiceTable.lookup("web")
      assert VipServiceTable.count() == 1
    end
  end

  describe "init/1 configuration sources" do
    test "ZTLP_RELAY_VIP_SERVICES env var populates the table at boot" do
      start_table(env: "web=10.1.1.1:80,api=10.1.1.2:8443")
      assert {:ok, {{10, 1, 1, 1}, 80}} = VipServiceTable.lookup("web")
      assert {:ok, {{10, 1, 1, 2}, 8443}} = VipServiceTable.lookup("api")
      assert VipServiceTable.count() == 2
    end

    test "env var takes precedence over application config" do
      start_table(env: "web=10.1.1.1:80", app: [{"other", {{9, 9, 9, 9}, 9}}])
      assert {:ok, _} = VipServiceTable.lookup("web")
      assert VipServiceTable.lookup("other") == :error
    end

    test "application config as a keyword-style list is loaded when env var is absent" do
      start_table(app: [{"cfg", {{172, 16, 0, 1}, 3000}}])
      assert {:ok, {{172, 16, 0, 1}, 3000}} = VipServiceTable.lookup("cfg")
      assert VipServiceTable.count() == 1
    end

    test "application config as a spec string is loaded when env var is absent" do
      start_table(app: "s1=10.2.2.2:1,s2=10.2.2.3:2")
      assert VipServiceTable.count() == 2
      assert {:ok, {{10, 2, 2, 3}, 2}} = VipServiceTable.lookup("s2")
    end

    test "empty application config yields an empty table" do
      start_table(app: [])
      assert VipServiceTable.count() == 0
    end

    test "an empty env var string yields an empty table (does not crash init)" do
      start_table(env: "")
      assert VipServiceTable.count() == 0
    end
  end
end
