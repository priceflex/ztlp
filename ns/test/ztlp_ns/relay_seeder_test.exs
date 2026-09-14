defmodule ZtlpNs.RelaySeederTest do
  # async: false — Store (Mnesia) + Application env + OS env are global.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ZtlpNs.{Record, RelaySeeder, Store}

  @env "ZTLP_NS_RELAY_RECORDS"

  setup do
    prev_env = System.get_env(@env)
    prev_key = Application.get_env(:ztlp_ns, :registration_private_key)
    Store.clear()

    on_exit(fn ->
      if prev_env, do: System.put_env(@env, prev_env), else: System.delete_env(@env)

      if prev_key,
        do: Application.put_env(:ztlp_ns, :registration_private_key, prev_key),
        else: Application.delete_env(:ztlp_ns, :registration_private_key)

      Store.clear()
    end)

    :ok
  end

  defp seed_with(spec) do
    System.put_env(@env, spec)
    capture_log(fn -> assert :ok = RelaySeeder.seed() end)
  end

  describe "seed/0 with nothing configured" do
    test "unset env var -> :ok, nothing inserted, no key generated" do
      System.delete_env(@env)
      Application.delete_env(:ztlp_ns, :registration_private_key)
      log = capture_log(fn -> assert :ok = RelaySeeder.seed() end)
      assert log =~ "No relay records to seed"
      assert Store.list() == []
      assert Application.get_env(:ztlp_ns, :registration_private_key) == nil
    end

    test "blank / whitespace env var is treated as unset" do
      System.put_env(@env, "   ")
      log = capture_log(fn -> assert :ok = RelaySeeder.seed() end)
      assert log =~ "No relay records to seed"
      assert Store.list() == []
    end
  end

  describe "seed/0 happy path" do
    test "one fully-specified relay is inserted as a signed rich RELAY record" do
      Application.delete_env(:ztlp_ns, :registration_private_key)

      log =
        seed_with(
          "name=relay1,address=34.219.64.205:23095,region=us-west-2,latency_ms=12,load_pct=35,active_connections=7,health=degraded,node_id=abcd"
        )

      assert log =~ "Generated new NS signing key for relay seeding"
      assert log =~ "Seeded relay: relay1 -> 34.219.64.205:23095 (us-west-2, degraded)"
      assert log =~ "Relay seeder: seeded 1 records, 0 errors"

      assert {:ok, %Record{type: :relay} = rec} = Store.lookup("relay1", :relay)
      assert Record.verify(rec), "record must be signed with the NS key"

      assert rec.data == %{
               "address" => "34.219.64.205:23095",
               "region" => "us-west-2",
               "latency_ms" => 12,
               "load_pct" => 35,
               "active_connections" => 7,
               "health" => "degraded",
               "endpoints" => ["34.219.64.205:23095"],
               "node_id" => "abcd"
             }

      # A signing key was created and persisted in app env for later use.
      priv = Application.get_env(:ztlp_ns, :registration_private_key)
      assert is_binary(priv)
      {pub, _} = :crypto.generate_key(:eddsa, :ed25519, priv)
      assert rec.signer_public_key == pub
    end

    test "uses an existing registration key instead of generating one" do
      {pub, priv} = ZtlpNs.Crypto.generate_keypair()
      Application.put_env(:ztlp_ns, :registration_private_key, priv)
      log = seed_with("name=r,address=1.2.3.4:1")
      refute log =~ "Generated new NS signing key"
      assert {:ok, rec} = Store.lookup("r", :relay)
      assert rec.signer_public_key == pub
      assert Application.get_env(:ztlp_ns, :registration_private_key) == priv
    end

    test "multiple relays separated by | are all inserted" do
      log =
        seed_with(
          "name=a,address=1.1.1.1:1,region=r1|name=b,address=2.2.2.2:2,region=r2|name=c,address=3.3.3.3:3"
        )

      assert log =~ "seeded 3 records, 0 errors"
      for {n, addr, region} <- [{"a", "1.1.1.1:1", "r1"}, {"b", "2.2.2.2:2", "r2"}, {"c", "3.3.3.3:3", "unknown"}] do
        assert {:ok, rec} = Store.lookup(n, :relay)
        assert rec.data["address"] == addr
        assert rec.data["region"] == region
      end
    end

    test "defaults: region unknown, health healthy, numeric fields 0, node_id empty" do
      seed_with("name=min,address=9.9.9.9:9")
      assert {:ok, rec} = Store.lookup("min", :relay)
      assert rec.data["region"] == "unknown"
      assert rec.data["health"] == "healthy"
      assert rec.data["latency_ms"] == 0
      assert rec.data["load_pct"] == 0
      assert rec.data["active_connections"] == 0
      assert rec.data["node_id"] == ""
      assert rec.data["endpoints"] == ["9.9.9.9:9"]
    end

    test "'addr' is accepted as an alias for 'address'" do
      seed_with("name=alias,addr=5.5.5.5:5")
      assert {:ok, rec} = Store.lookup("alias", :relay)
      assert rec.data["address"] == "5.5.5.5:5"
    end

    test "'address' wins over 'addr' when both present" do
      seed_with("name=both,addr=1.1.1.1:1,address=2.2.2.2:2")
      assert {:ok, rec} = Store.lookup("both", :relay)
      assert rec.data["address"] == "2.2.2.2:2"
    end

    test "whitespace around keys, values and separators is trimmed" do
      seed_with("  name = spaced , address = 7.7.7.7:7 , region = eu  |  ")
      assert {:ok, rec} = Store.lookup("spaced", :relay)
      assert rec.data["address"] == "7.7.7.7:7"
      assert rec.data["region"] == "eu"
    end

    test "values containing '=' keep everything after the first '='" do
      seed_with("name=eq,address=1.1.1.1:1,node_id=a=b=c")
      assert {:ok, rec} = Store.lookup("eq", :relay)
      assert rec.data["node_id"] == "a=b=c"
    end

    test "parts without '=' are ignored" do
      seed_with("name=junk,garbage,address=1.1.1.1:1,,")
      assert {:ok, _} = Store.lookup("junk", :relay)
    end

    test "non-numeric or suffixed integers fall back to 0" do
      seed_with("name=nums,address=1.1.1.1:1,latency_ms=12ms,load_pct=abc,active_connections=-3")
      assert {:ok, rec} = Store.lookup("nums", :relay)
      assert rec.data["latency_ms"] == 0
      assert rec.data["load_pct"] == 0
      assert rec.data["active_connections"] == -3, "negative integers parse cleanly"
    end

    test "re-seeding the same name is rejected as :stale_serial (seeder always uses serial 1)" do
      # Operational note: changing ZTLP_NS_RELAY_RECORDS values for an
      # existing relay name and restarting does NOT update the record while
      # the old one is still in the store — Store enforces monotonic serials
      # and the seeder never increments. Pinned so this is a known property.
      seed_with("name=dup,address=1.1.1.1:1,region=old")
      log = seed_with("name=dup,address=1.1.1.1:1,region=new")
      assert log =~ "Failed to seed relay dup: :stale_serial"
      assert log =~ "seeded 0 records, 1 errors"
      assert {:ok, rec} = Store.lookup("dup", :relay)
      assert rec.data["region"] == "old"
    end
  end

  describe "seed/0 error handling" do
    test "entry missing name is counted as an error, others still seeded" do
      log = seed_with("address=1.1.1.1:1,region=x|name=ok,address=2.2.2.2:2")
      assert log =~ "seeded 1 records, 1 errors"
      assert {:ok, _} = Store.lookup("ok", :relay)
      assert Store.list() |> length() == 1
    end

    test "entry with empty name is an error" do
      log = seed_with("name=,address=1.1.1.1:1")
      assert log =~ "seeded 0 records, 1 errors"
      assert Store.list() == []
    end

    test "entry missing address is an error" do
      log = seed_with("name=noaddr,region=x")
      assert log =~ "seeded 0 records, 1 errors"
      assert Store.lookup("noaddr", :relay) == :not_found
    end

    test "entry with empty address is an error" do
      log = seed_with("name=noaddr,address=")
      assert log =~ "seeded 0 records, 1 errors"
    end

    test "empty entries between separators are skipped, not counted" do
      log = seed_with("|name=a,address=1.1.1.1:1||   |")
      assert log =~ "seeded 1 records, 0 errors"
    end

    test "Store.insert rejection is logged and counted (record too large)" do
      huge = String.duplicate("x", ZtlpNs.Config.max_record_size() + 100)
      log = seed_with("name=big,address=1.1.1.1:1,region=#{huge}")
      assert log =~ "Failed to seed relay big: :record_too_large"
      assert log =~ "seeded 0 records, 1 errors"
      assert Store.lookup("big", :relay) == :not_found
    end

    test "the documented example string (with a bare address part) seeds names but drops the addresses" do
      # The moduledoc example uses `name=relay1,34.219.64.205:23095,...` — a
      # bare address part without `address=`. That part has no '=' and is
      # ignored, so the entry has no address and is an error. Pin this so
      # the doc/behaviour mismatch is visible.
      log =
        seed_with(
          "name=relay1,34.219.64.205:23095,region=us-west-2,latency_ms=12,load_pct=35,health=healthy|name=relay2,44.246.33.34:23096,region=us-east-1,latency_ms=45,load_pct=80,health=degraded"
        )

      assert log =~ "seeded 0 records, 2 errors"
      assert Store.list() == []
    end
  end
end
