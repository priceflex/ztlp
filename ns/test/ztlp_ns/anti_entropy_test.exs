defmodule ZtlpNs.AntiEntropyTest do
  use ExUnit.Case

  alias ZtlpNs.{AntiEntropy, Crypto, Record, Store}

  setup do
    Store.clear()
    :ok
  end

  # ── Helpers ──────────────────────────────────────────────────────────

  defp make_signed_key(name, opts \\ []) do
    {_pub, priv} = opts[:keypair] || Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16)
    {node_pub, _} = Crypto.generate_keypair()
    serial = opts[:serial] || 1

    record =
      Record.new_key(name, node_id, node_pub,
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: serial
      )

    Record.sign(record, priv)
  end

  defp make_signed_revoke(name, revoked_ids, opts \\ []) do
    {_pub, priv} = opts[:keypair] || Crypto.generate_keypair()

    revoke =
      Record.new_revoke(name, [], "compromised", "2026-03-10T00:00:00Z",
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 0,
        serial: opts[:serial] || 1
      )

    revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, revoked_ids)}
    Record.sign(revoke, priv)
  end

  # ── compute_root_hash/0 ─────────────────────────────────────────────

  describe "compute_root_hash/0" do
    test "returns consistent hash for same data" do
      rec = make_signed_key("node1.ztlp")
      Store.insert(rec, replicated: true)

      hash1 = AntiEntropy.compute_root_hash()
      hash2 = AntiEntropy.compute_root_hash()

      assert hash1 == hash2
      assert byte_size(hash1) == 32
    end

    test "changes when records change" do
      rec1 = make_signed_key("node1.ztlp")
      Store.insert(rec1, replicated: true)
      hash1 = AntiEntropy.compute_root_hash()

      rec2 = make_signed_key("node2.ztlp")
      Store.insert(rec2, replicated: true)
      hash2 = AntiEntropy.compute_root_hash()

      assert hash1 != hash2
    end

    test "returns same hash regardless of insertion order" do
      rec_a = make_signed_key("aaa.ztlp", serial: 1)
      rec_b = make_signed_key("bbb.ztlp", serial: 1)

      # Insert in order A, B
      Store.insert(rec_a, replicated: true)
      Store.insert(rec_b, replicated: true)
      hash_ab = AntiEntropy.compute_root_hash()

      # Clear and insert in order B, A
      Store.clear()
      Store.insert(rec_b, replicated: true)
      Store.insert(rec_a, replicated: true)
      hash_ba = AntiEntropy.compute_root_hash()

      assert hash_ab == hash_ba
    end
  end

  # ── merge_remote_records/1 ──────────────────────────────────────────

  describe "merge_remote_records/1" do
    test "accepts records with higher serial" do
      rec_v1 = make_signed_key("node1.ztlp", serial: 1)
      Store.insert(rec_v1, replicated: true)

      rec_v2 = make_signed_key("node1.ztlp", serial: 2)
      {:ok, stats} = AntiEntropy.merge_remote_records([rec_v2])

      assert stats.accepted == 1
      assert stats.rejected == 0
      assert stats.skipped == 0
    end

    test "rejects records with lower serial (stale)" do
      rec_v5 = make_signed_key("node1.ztlp", serial: 5)
      Store.insert(rec_v5, replicated: true)

      rec_v3 = make_signed_key("node1.ztlp", serial: 3)
      {:ok, stats} = AntiEntropy.merge_remote_records([rec_v3])

      assert stats.accepted == 0
      assert stats.skipped == 1
    end

    test "rejects records with invalid signatures" do
      rec = make_signed_key("node1.ztlp")
      tampered = %{rec | name: "hacked.ztlp"}

      {:ok, stats} = AntiEntropy.merge_remote_records([tampered])

      assert stats.rejected == 1
      assert stats.accepted == 0
    end

    test "propagates revocations" do
      revoke = make_signed_revoke("revoke.ztlp", ["bad-node-id"])
      {:ok, stats} = AntiEntropy.merge_remote_records([revoke])

      assert stats.accepted == 1
      assert Store.revoked?("bad-node-id")
    end

    test "skips expired records" do
      # Record created at epoch 0 with TTL 1 second — long expired
      rec = make_signed_key("old.ztlp", created_at: 0, ttl: 1, serial: 1)

      {:ok, stats} = AntiEntropy.merge_remote_records([rec])

      assert stats.skipped == 1
      assert stats.accepted == 0
    end

    test "returns merge stats (accepted, rejected, skipped counts)" do
      good_rec = make_signed_key("good.ztlp", serial: 1)
      expired_rec = make_signed_key("expired.ztlp", created_at: 0, ttl: 1, serial: 1)
      tampered_rec = %{make_signed_key("bad.ztlp") | name: "tampered.ztlp"}

      {:ok, stats} = AntiEntropy.merge_remote_records([good_rec, expired_rec, tampered_rec])

      assert stats.accepted == 1
      assert stats.skipped == 1
      assert stats.rejected == 1
    end
  end

  # ── compute_range_hash/2 ────────────────────────────────────────────

  describe "compute_range_hash/2" do
    test "computes hash over subset of records" do
      rec_a = make_signed_key("aaa.ztlp", serial: 1)
      rec_m = make_signed_key("mmm.ztlp", serial: 1)
      rec_z = make_signed_key("zzz.ztlp", serial: 1)

      Store.insert(rec_a, replicated: true)
      Store.insert(rec_m, replicated: true)
      Store.insert(rec_z, replicated: true)

      # Range covering only aaa-mmm (should exclude zzz)
      range_hash = AntiEntropy.compute_range_hash({"aaa.ztlp", :key}, {"mmm.ztlp", :key})
      full_hash = AntiEntropy.compute_root_hash()

      assert range_hash != full_hash
      assert byte_size(range_hash) == 32
    end
  end

  # ── diff_with_peer/1 ────────────────────────────────────────────────

  describe "diff_with_peer/1" do
    test "returns :in_sync when hashes match" do
      rec = make_signed_key("node1.ztlp")
      Store.insert(rec, replicated: true)

      local_hash = AntiEntropy.compute_root_hash()
      assert :in_sync = AntiEntropy.diff_with_peer(local_hash)
    end

    test "returns :needs_sync when hashes differ" do
      rec = make_signed_key("node1.ztlp")
      Store.insert(rec, replicated: true)

      fake_hash = :crypto.hash(:blake2s, "different")
      assert {:needs_sync, _local_hash} = AntiEntropy.diff_with_peer(fake_hash)
    end
  end
end
