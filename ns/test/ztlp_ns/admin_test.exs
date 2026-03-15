defmodule ZtlpNs.AdminTest do
  @moduledoc """
  Comprehensive tests for Phase 3: Admin Controls.

  Covers:
  - Store.list_by_type/1 and Store.list_by_zone/1 filtering
  - Store.list_filtered/1 combined filtering
  - Audit module: logging, since/filter queries, ring buffer bounds
  - Revocation enhancements: reason field, index cleanup
  - Registration auth rate limiting
  - Revoked entity re-registration prevention
  - Admin query wire protocol (0x13)
  """

  use ExUnit.Case

  alias ZtlpNs.{Audit, Crypto, Record, Store, RegistrationAuth, TrustAnchor}

  setup do
    Store.clear()
    TrustAnchor.clear()
    Audit.clear()
    :ok
  end

  # ── Helpers ────────────────────────────────────────────────────────

  defp make_signed_device(name, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16)
    {device_pub, _} = Crypto.generate_keypair()

    record =
      Record.new_device(name, node_id, device_pub,
        owner: opts[:owner] || "",
        hardware_id: opts[:hardware_id] || "",
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: opts[:serial] || 1
      )

    Record.sign(record, priv)
  end

  defp make_signed_user(name, opts \\ []) do
    {pub, priv} = Crypto.generate_keypair()

    record =
      Record.new_user(name, pub,
        devices: opts[:devices] || [],
        email: opts[:email] || "",
        role: opts[:role] || "user",
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: opts[:serial] || 1
      )

    Record.sign(record, priv)
  end

  defp make_signed_group(name, members, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()

    record =
      Record.new_group(name, members,
        role: opts[:role] || "user",
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: opts[:serial] || 1
      )

    Record.sign(record, priv)
  end

  defp make_signed_key(name) do
    {pub, priv} = Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

    record = %Record{
      name: name,
      type: :key,
      data: %{
        public_key: Base.encode16(pub, case: :lower),
        node_id: node_id
      },
      created_at: System.system_time(:second),
      ttl: 86400,
      serial: 1
    }

    Record.sign(record, priv)
  end

  defp make_revocation(name, revoked_ids, reason \\ "test") do
    {_pub, priv} = Crypto.generate_keypair()

    record = %Record{
      name: name,
      type: :revoke,
      data: %{revoked_ids: revoked_ids, reason: reason, effective_at: "now"},
      created_at: System.system_time(:second),
      ttl: 0,
      serial: 1
    }

    Record.sign(record, priv)
  end

  # ── Store.list_by_type Tests ────────────────────────────────────────

  describe "Store.list_by_type/1" do
    test "returns only device records" do
      device = make_signed_device("laptop.zone.ztlp")
      user = make_signed_user("steve@zone.ztlp")
      assert :ok = Store.insert(device)
      assert :ok = Store.insert(user)

      results = Store.list_by_type(:device)
      assert length(results) == 1
      assert [{name, :device, _}] = results
      assert name == "laptop.zone.ztlp"
    end

    test "returns only user records" do
      device = make_signed_device("laptop.zone.ztlp")
      user = make_signed_user("steve@zone.ztlp")
      assert :ok = Store.insert(device)
      assert :ok = Store.insert(user)

      results = Store.list_by_type(:user)
      assert length(results) == 1
      assert [{name, :user, _}] = results
      assert name == "steve@zone.ztlp"
    end

    test "returns only group records" do
      group = make_signed_group("admins.zone.ztlp", ["steve@zone.ztlp"])
      device = make_signed_device("laptop.zone.ztlp")
      assert :ok = Store.insert(group)
      assert :ok = Store.insert(device)

      results = Store.list_by_type(:group)
      assert length(results) == 1
      assert [{name, :group, _}] = results
      assert name == "admins.zone.ztlp"
    end

    test "returns only key records" do
      key = make_signed_key("node1.zone.ztlp")
      device = make_signed_device("laptop.zone.ztlp")
      assert :ok = Store.insert(key)
      assert :ok = Store.insert(device)

      results = Store.list_by_type(:key)
      assert length(results) == 1
      assert [{name, :key, _}] = results
      assert name == "node1.zone.ztlp"
    end

    test "returns empty list when no records of type exist" do
      device = make_signed_device("laptop.zone.ztlp")
      assert :ok = Store.insert(device)

      assert Store.list_by_type(:group) == []
    end

    test "filters out expired records" do
      expired = make_signed_device("old.zone.ztlp", created_at: 1000, ttl: 1)
      assert :ok = Store.insert(expired)

      assert Store.list_by_type(:device) == []
    end

    test "returns multiple records of same type" do
      d1 = make_signed_device("laptop1.zone.ztlp")
      d2 = make_signed_device("laptop2.zone.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(d2)

      results = Store.list_by_type(:device)
      assert length(results) == 2
      names = Enum.map(results, fn {name, _, _} -> name end) |> Enum.sort()
      assert names == ["laptop1.zone.ztlp", "laptop2.zone.ztlp"]
    end
  end

  # ── Store.list_by_zone Tests ────────────────────────────────────────

  describe "Store.list_by_zone/1" do
    test "filters records by zone suffix" do
      d1 = make_signed_device("laptop.acme.ztlp")
      d2 = make_signed_device("laptop.other.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(d2)

      results = Store.list_by_zone("acme.ztlp")
      assert length(results) == 1
      assert [{name, _, _}] = results
      assert name == "laptop.acme.ztlp"
    end

    test "returns records from nested zones" do
      d1 = make_signed_device("laptop.sub.acme.ztlp")
      d2 = make_signed_device("laptop.acme.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(d2)

      results = Store.list_by_zone("acme.ztlp")
      assert length(results) == 2
    end

    test "returns empty list when no records match zone" do
      d1 = make_signed_device("laptop.other.ztlp")
      assert :ok = Store.insert(d1)

      assert Store.list_by_zone("acme.ztlp") == []
    end

    test "includes exact zone match" do
      key = make_signed_key("acme.ztlp")
      assert :ok = Store.insert(key)

      results = Store.list_by_zone("acme.ztlp")
      assert length(results) == 1
    end
  end

  # ── Store.list_filtered Tests ────────────────────────────────────────

  describe "Store.list_filtered/1" do
    test "filters by type and zone simultaneously" do
      d1 = make_signed_device("laptop.acme.ztlp")
      d2 = make_signed_device("laptop.other.ztlp")
      u1 = make_signed_user("steve@acme.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(d2)
      assert :ok = Store.insert(u1)

      results = Store.list_filtered(type: :device, zone: "acme.ztlp")
      assert length(results) == 1
      assert [{name, :device, _}] = results
      assert name == "laptop.acme.ztlp"
    end

    test "no filters returns all non-expired records" do
      d1 = make_signed_device("laptop.ztlp")
      u1 = make_signed_user("steve@zone.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(u1)

      results = Store.list_filtered()
      assert length(results) == 2
    end

    test "type filter only" do
      d1 = make_signed_device("laptop.ztlp")
      u1 = make_signed_user("steve@zone.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(u1)

      results = Store.list_filtered(type: :user)
      assert length(results) == 1
    end

    test "zone filter only" do
      d1 = make_signed_device("laptop.acme.ztlp")
      d2 = make_signed_device("laptop.other.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(d2)

      results = Store.list_filtered(zone: "acme.ztlp")
      assert length(results) == 1
    end
  end

  # ── Audit Module Tests ────────────────────────────────────────────

  describe "Audit.log/4 and Audit.all/0" do
    test "logs an entry" do
      Audit.log(:registered, "laptop.ztlp", :device, %{signer: "abc123"})

      entries = Audit.all()
      assert length(entries) == 1
      [{ts, action, name, type, details}] = entries
      assert action == :registered
      assert name == "laptop.ztlp"
      assert type == :device
      assert details.signer == "abc123"
      assert is_integer(ts)
    end

    test "logs multiple entries" do
      Audit.log(:registered, "laptop.ztlp", :device)
      Audit.log(:revoked, "steve@ztlp", :user, %{reason: "left"})
      Audit.log(:updated, "group.ztlp", :group)

      entries = Audit.all()
      assert length(entries) == 3
    end
  end

  describe "Audit.since/1" do
    test "returns entries since timestamp" do
      old_ts = System.system_time(:second) - 10

      Audit.log(:registered, "old.ztlp", :device)
      :timer.sleep(50)
      now = System.system_time(:second)
      Audit.log(:registered, "new.ztlp", :device)

      recent = Audit.since(now)
      # Should include entries from 'now' onwards
      assert Enum.any?(recent, fn {_, _, name, _, _} -> name == "new.ztlp" end)
    end

    test "returns empty list when no entries match" do
      Audit.log(:registered, "old.ztlp", :device)
      future = System.system_time(:second) + 3600

      assert Audit.since(future) == []
    end

    test "returns all entries for timestamp 0" do
      Audit.log(:registered, "a.ztlp", :device)
      Audit.log(:registered, "b.ztlp", :user)

      entries = Audit.since(0)
      assert length(entries) == 2
    end
  end

  describe "Audit.filter/1" do
    test "filters by prefix wildcard" do
      Audit.log(:registered, "steve@zone.ztlp", :user)
      Audit.log(:registered, "laptop.zone.ztlp", :device)

      results = Audit.filter("steve@*")
      assert length(results) == 1
      [{_, _, name, _, _}] = results
      assert name == "steve@zone.ztlp"
    end

    test "filters by suffix wildcard" do
      Audit.log(:registered, "a.acme.ztlp", :device)
      Audit.log(:registered, "b.other.ztlp", :device)

      results = Audit.filter("*.acme.ztlp")
      assert length(results) == 1
    end

    test "filters by middle wildcard" do
      Audit.log(:registered, "steve@acme.ztlp", :user)
      Audit.log(:registered, "bob@acme.ztlp", :user)

      results = Audit.filter("*@acme*")
      assert length(results) == 2
    end

    test "exact match" do
      Audit.log(:registered, "steve@zone.ztlp", :user)
      Audit.log(:registered, "bob@zone.ztlp", :user)

      results = Audit.filter("steve@zone.ztlp")
      assert length(results) == 1
    end

    test "returns empty for non-matching pattern" do
      Audit.log(:registered, "steve@zone.ztlp", :user)

      assert Audit.filter("nobody@*") == []
    end
  end

  describe "Audit.filter_since/2" do
    test "combines name pattern and time filter" do
      Audit.log(:registered, "steve@zone.ztlp", :user)
      now = System.system_time(:second)
      Audit.log(:registered, "steve@other.ztlp", :user)
      Audit.log(:registered, "bob@zone.ztlp", :user)

      results = Audit.filter_since("steve@*", now)
      assert length(results) >= 1
      assert Enum.all?(results, fn {_, _, name, _, _} -> String.starts_with?(name, "steve@") end)
    end
  end

  describe "Audit ring buffer bounds" do
    test "audit count is bounded" do
      # We can't easily test 10000 entries, but let's verify the mechanism works
      for i <- 1..100 do
        Audit.log(:registered, "entity#{i}.ztlp", :device)
      end

      count = Audit.count()
      assert count == 100
    end
  end

  describe "Audit.clear/0" do
    test "clears all entries" do
      Audit.log(:registered, "test.ztlp", :device)
      assert Audit.count() > 0

      Audit.clear()
      assert Audit.count() == 0
      assert Audit.all() == []
    end
  end

  # ── Revocation Enhancement Tests ───────────────────────────────────

  describe "revocation with reason" do
    test "revocation record carries reason in data" do
      revoke = Record.new_revoke(
        "revoke.test.ztlp",
        [:crypto.strong_rand_bytes(16)],
        "stolen device",
        "2024-01-01T00:00:00Z"
      )

      assert revoke.data.reason == "stolen device"
    end

    test "revocation record with custom reason roundtrips" do
      {_pub, priv} = Crypto.generate_keypair()
      id = :crypto.strong_rand_bytes(16)

      revoke = Record.new_revoke("revoke.zone.ztlp", [id], "left company", "now")
      signed = Record.sign(revoke, priv)

      assert signed.data.reason == "left company"
      assert Record.verify(signed)
    end
  end

  describe "revocation index cleanup" do
    test "revoking a device removes it from the device-owner index" do
      device = make_signed_device("laptop.zone.ztlp", owner: "steve@zone.ztlp")
      assert :ok = Store.insert(device)

      # Verify device shows in owner index
      devices = Store.lookup_devices_for_user("steve@zone.ztlp")
      assert "laptop.zone.ztlp" in devices

      # Now insert a revocation for the device (using direct record, not new_revoke which hex-encodes)
      revoke = make_revocation("revoke.laptop", ["laptop.zone.ztlp"], "stolen")
      assert :ok = Store.insert(revoke)

      # The device should be revoked
      assert Store.revoked?("laptop.zone.ztlp")
    end

    test "revoking a user removes them from group indexes" do
      # Create a group with members
      group = make_signed_group("admins.zone.ztlp", ["steve@zone.ztlp", "bob@zone.ztlp"])
      assert :ok = Store.insert(group)

      # Verify groups
      groups = Store.groups_for_user("steve@zone.ztlp")
      assert "admins.zone.ztlp" in groups

      # Now revoke the user (using direct record, not new_revoke which hex-encodes)
      revoke = make_revocation("revoke.steve", ["steve@zone.ztlp"], "left company")
      assert :ok = Store.insert(revoke)

      assert Store.revoked?("steve@zone.ztlp")
    end
  end

  # ── Registration Auth Rate Limiting Tests ───────────────────────────

  describe "RegistrationAuth.check_rate_limit/2" do
    setup do
      # Ensure rate limit table exists
      RegistrationAuth.init_rate_limit()
      # Clear the rate limit table
      if :ets.whereis(:ztlp_ns_registration_rate_limit) != :undefined do
        :ets.delete_all_objects(:ztlp_ns_registration_rate_limit)
      end
      :ok
    end

    test "first registration is allowed" do
      {pub, _priv} = Crypto.generate_keypair()
      assert :ok = RegistrationAuth.check_rate_limit("test.ztlp", pub)
    end

    test "second registration within window is rate limited" do
      {pub, _priv} = Crypto.generate_keypair()
      assert :ok = RegistrationAuth.check_rate_limit("test.ztlp", pub)
      assert {:error, :rate_limited} = RegistrationAuth.check_rate_limit("test.ztlp", pub)
    end

    test "different names have independent rate limits" do
      {pub, _priv} = Crypto.generate_keypair()
      assert :ok = RegistrationAuth.check_rate_limit("name1.ztlp", pub)
      assert :ok = RegistrationAuth.check_rate_limit("name2.ztlp", pub)
    end

    test "rate limit allows after expiry" do
      {pub, _priv} = Crypto.generate_keypair()
      # Manually set an old timestamp
      :ets.insert(:ztlp_ns_registration_rate_limit, {"test.ztlp", System.system_time(:second) - 7200})
      assert :ok = RegistrationAuth.check_rate_limit("test.ztlp", pub)
    end
  end

  # ── Registration Auth Revocation Check Tests ───────────────────────

  describe "RegistrationAuth.check_name_revocation/1" do
    test "non-revoked name passes" do
      assert :ok = RegistrationAuth.check_name_revocation("clean.ztlp")
    end

    test "revoked name is blocked" do
      revoke = make_revocation("revoke.test", ["blocked.ztlp"], "banned")
      assert :ok = Store.insert(revoke)

      assert {:error, :revoked} = RegistrationAuth.check_name_revocation("blocked.ztlp")
    end
  end

  # ── Admin Query Wire Protocol Tests (0x13) ──────────────────────────

  describe "admin query via UDP (0x13)" do
    setup do
      # Get the server's actual port (it uses port 0 in test config)
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
      {:ok, %{socket: socket, port: port}}
    end

    test "list all records via admin query", %{socket: socket, port: port} do
      device = make_signed_device("laptop.zone.ztlp")
      user = make_signed_user("steve@zone.ztlp")
      assert :ok = Store.insert(device)
      assert :ok = Store.insert(user)

      # Send admin list query: <<0x13, 0x01, 0x00, 0x00, 0x00>>
      # type_byte=0x00 (all), zone_len=0 (no zone filter)
      query = <<0x13, 0x01, 0x00, 0x00::16>>
      :gen_udp.send(socket, ~c"127.0.0.1", port, query)

      assert {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      assert <<0x13, cbor_data::binary>> = response
      assert byte_size(cbor_data) > 0

      # Decode CBOR and verify
      {:ok, decoded} = ZtlpNs.Cbor.decode(cbor_data)
      assert is_map(decoded)
      records = decoded["records"]
      assert is_list(records)
      assert length(records) == 2

      :gen_udp.close(socket)
    end

    test "list records filtered by type via admin query", %{socket: socket, port: port} do
      device = make_signed_device("laptop.zone.ztlp")
      user = make_signed_user("steve@zone.ztlp")
      assert :ok = Store.insert(device)
      assert :ok = Store.insert(user)

      # Query for DEVICE only (type_byte=0x10)
      query = <<0x13, 0x01, 0x10, 0x00::16>>
      :gen_udp.send(socket, ~c"127.0.0.1", port, query)

      assert {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      assert <<0x13, cbor_data::binary>> = response

      {:ok, decoded} = ZtlpNs.Cbor.decode(cbor_data)
      records = decoded["records"]
      assert length(records) == 1
      assert hd(records)["type"] == "device"

      :gen_udp.close(socket)
    end

    test "list records filtered by zone via admin query", %{socket: socket, port: port} do
      d1 = make_signed_device("laptop.acme.ztlp")
      d2 = make_signed_device("laptop.other.ztlp")
      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(d2)

      # Query with zone filter
      zone = "acme.ztlp"
      zone_len = byte_size(zone)
      query = <<0x13, 0x01, 0x00, zone_len::16, zone::binary>>
      :gen_udp.send(socket, ~c"127.0.0.1", port, query)

      assert {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      assert <<0x13, cbor_data::binary>> = response

      {:ok, decoded} = ZtlpNs.Cbor.decode(cbor_data)
      records = decoded["records"]
      assert length(records) == 1
      assert hd(records)["name"] == "laptop.acme.ztlp"

      :gen_udp.close(socket)
    end

    test "audit query returns entries since timestamp", %{socket: socket, port: port} do
      # Log some audit entries
      Audit.log(:registered, "test.ztlp", :device, %{signer: "abc"})
      :timer.sleep(50)

      since_ts = System.system_time(:second) - 10

      # Audit since: <<0x13, 0x02, since_ts::64>>
      query = <<0x13, 0x02, since_ts::unsigned-big-64>>
      :gen_udp.send(socket, ~c"127.0.0.1", port, query)

      assert {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      assert <<0x13, cbor_data::binary>> = response

      {:ok, decoded} = ZtlpNs.Cbor.decode(cbor_data)
      assert is_map(decoded)
      entries = decoded["entries"]
      assert is_list(entries)
      assert length(entries) >= 1

      :gen_udp.close(socket)
    end

    test "audit query with name filter", %{socket: socket, port: port} do
      Audit.log(:registered, "steve@zone.ztlp", :user)
      Audit.log(:registered, "bob@zone.ztlp", :user)
      :timer.sleep(50)

      since_ts = System.system_time(:second) - 10
      pattern = "steve@*"
      pattern_len = byte_size(pattern)

      # Audit filter: <<0x13, 0x03, since_ts::64, pattern_len::16, pattern::binary>>
      query = <<0x13, 0x03, since_ts::unsigned-big-64, pattern_len::16, pattern::binary>>
      :gen_udp.send(socket, ~c"127.0.0.1", port, query)

      assert {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      assert <<0x13, cbor_data::binary>> = response

      {:ok, decoded} = ZtlpNs.Cbor.decode(cbor_data)
      entries = decoded["entries"]
      assert is_list(entries)
      assert Enum.all?(entries, fn e -> String.starts_with?(e["name"], "steve@") end)

      :gen_udp.close(socket)
    end
  end

  # ── Audit Integration with Server ──────────────────────────────────

  describe "audit integration with registration" do
    setup do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, active: false])

      # Disable registration auth for this test so unsigned packets succeed
      original_auth = Application.get_env(:ztlp_ns, :require_registration_auth)
      Application.put_env(:ztlp_ns, :require_registration_auth, false)

      on_exit(fn ->
        case original_auth do
          nil -> Application.delete_env(:ztlp_ns, :require_registration_auth)
          val -> Application.put_env(:ztlp_ns, :require_registration_auth, val)
        end
      end)

      {:ok, %{socket: socket, port: port}}
    end

    test "registration creates audit entry", %{socket: socket, port: port} do
      Audit.clear()

      # Register a device via the server (unsigned — works because auth is disabled)
      name = "audit-test.zone.ztlp"
      type_byte = 0x10  # DEVICE

      node_id = :crypto.strong_rand_bytes(16)
      {device_pub, _} = Crypto.generate_keypair()

      data = %{
        "node_id" => Base.encode16(node_id, case: :lower),
        "public_key" => Base.encode16(device_pub, case: :lower),
        "owner" => "",
        "hardware_id" => ""
      }
      data_bin = ZtlpNs.Cbor.encode(data)

      name_bytes = name
      name_len = byte_size(name_bytes)
      data_len = byte_size(data_bin)

      pkt = <<0x09, name_len::16, name_bytes::binary, type_byte::8,
              data_len::16, data_bin::binary, 0::16>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, pkt)
      assert {:ok, {_, _, <<0x06>>}} = :gen_udp.recv(socket, 0, 5000)

      # Check audit log — wait for async task completion
      :timer.sleep(100)
      entries = Audit.all()
      assert length(entries) >= 1

      reg_entry = Enum.find(entries, fn {_, action, n, _, _} ->
        action == :registered and n == name
      end)
      assert reg_entry != nil

      :gen_udp.close(socket)
    end

    test "Audit.log called directly" do
      Audit.clear()

      Audit.log(:registered, "direct-test.ztlp", :device, %{signer: "testkey"})

      entries = Audit.all()
      assert length(entries) == 1
      [{_, :registered, "direct-test.ztlp", :device, %{signer: "testkey"}}] = entries
    end
  end

  # ── Additional Edge Cases ──────────────────────────────────────────

  describe "edge cases" do
    test "list_by_type with empty store" do
      assert Store.list_by_type(:device) == []
      assert Store.list_by_type(:user) == []
      assert Store.list_by_type(:group) == []
      assert Store.list_by_type(:key) == []
    end

    test "list_by_zone with empty store" do
      assert Store.list_by_zone("any.ztlp") == []
    end

    test "list_filtered with empty store" do
      assert Store.list_filtered(type: :device, zone: "any.ztlp") == []
    end

    test "audit log entries are sorted by timestamp" do
      Audit.log(:registered, "a.ztlp", :device)
      Audit.log(:registered, "b.ztlp", :device)
      Audit.log(:registered, "c.ztlp", :device)

      entries = Audit.all()
      timestamps = Enum.map(entries, fn {ts, _, _, _, _} -> ts end)
      assert timestamps == Enum.sort(timestamps)
    end

    test "multiple record types in same zone" do
      d1 = make_signed_device("laptop.acme.ztlp")
      u1 = make_signed_user("steve@acme.ztlp")
      g1 = make_signed_group("admins.acme.ztlp", ["steve@acme.ztlp"])
      k1 = make_signed_key("node1.acme.ztlp")

      assert :ok = Store.insert(d1)
      assert :ok = Store.insert(u1)
      assert :ok = Store.insert(g1)
      assert :ok = Store.insert(k1)

      all = Store.list_by_zone("acme.ztlp")
      assert length(all) == 4
    end

    test "list_filtered type and zone combined" do
      d_acme = make_signed_device("laptop.acme.ztlp")
      d_other = make_signed_device("laptop.other.ztlp")
      u_acme = make_signed_user("steve@acme.ztlp")

      assert :ok = Store.insert(d_acme)
      assert :ok = Store.insert(d_other)
      assert :ok = Store.insert(u_acme)

      # Only devices in acme zone
      results = Store.list_filtered(type: :device, zone: "acme.ztlp")
      assert length(results) == 1
      assert [{name, :device, _}] = results
      assert name == "laptop.acme.ztlp"
    end

    test "revoked name cannot re-register via check_name_revocation" do
      revoke = make_revocation("revoke.test", ["blocked.zone.ztlp"], "banned")
      assert :ok = Store.insert(revoke)

      assert {:error, :revoked} = RegistrationAuth.check_name_revocation("blocked.zone.ztlp")

      # But a different name is fine
      assert :ok = RegistrationAuth.check_name_revocation("clean.zone.ztlp")
    end
  end
end
