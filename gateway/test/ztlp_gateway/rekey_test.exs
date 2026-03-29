defmodule ZtlpGateway.RekeyTest do
  @moduledoc """
  Tests for the FRAME_REKEY session key rotation protocol.

  Tests the pure-function helpers in `ZtlpGateway.Rekey` that handle
  key derivation, rekey state management, and the initiate/complete flow.
  """
  use ExUnit.Case, async: true

  alias ZtlpGateway.Rekey

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Build a minimal mock state with the fields Rekey functions need.
  defp mock_state(overrides \\ %{}) do
    base = %{
      i2r_key: :crypto.strong_rand_bytes(32),
      r2i_key: :crypto.strong_rand_bytes(32),
      rekey_packet_count: 0,
      rekey_interval_ms: Rekey.default_interval_ms(),
      rekey_packet_limit: Rekey.default_packet_limit(),
      rekey_pending: false,
      rekey_timer_ref: nil,
      pending_r2i_key: nil,
      pending_i2r_key: nil,
      rekey_count: 0
    }

    Map.merge(base, overrides)
  end

  # ---------------------------------------------------------------------------
  # derive_new_key/2
  # ---------------------------------------------------------------------------

  describe "derive_new_key/2" do
    test "produces a 32-byte key" do
      current = :crypto.strong_rand_bytes(32)
      material = :crypto.strong_rand_bytes(32)

      result = Rekey.derive_new_key(current, material)
      assert byte_size(result) == 32
    end

    test "is deterministic (same inputs produce same output)" do
      current = :crypto.strong_rand_bytes(32)
      material = :crypto.strong_rand_bytes(32)

      result1 = Rekey.derive_new_key(current, material)
      result2 = Rekey.derive_new_key(current, material)
      assert result1 == result2
    end

    test "produces a different key than the input" do
      current = :crypto.strong_rand_bytes(32)
      material = :crypto.strong_rand_bytes(32)

      result = Rekey.derive_new_key(current, material)
      assert result != current
    end

    test "different key material produces different keys" do
      current = :crypto.strong_rand_bytes(32)
      material1 = :crypto.strong_rand_bytes(32)
      material2 = :crypto.strong_rand_bytes(32)

      result1 = Rekey.derive_new_key(current, material1)
      result2 = Rekey.derive_new_key(current, material2)
      assert result1 != result2
    end

    test "different current keys produce different results" do
      current1 = :crypto.strong_rand_bytes(32)
      current2 = :crypto.strong_rand_bytes(32)
      material = :crypto.strong_rand_bytes(32)

      result1 = Rekey.derive_new_key(current1, material)
      result2 = Rekey.derive_new_key(current2, material)
      assert result1 != result2
    end
  end

  # ---------------------------------------------------------------------------
  # initial_state/1
  # ---------------------------------------------------------------------------

  describe "initial_state/1" do
    test "returns correct defaults" do
      state = Rekey.initial_state()

      assert state.rekey_packet_count == 0
      assert state.rekey_interval_ms == 86_400_000
      assert state.rekey_packet_limit == 4_294_967_296
      assert state.rekey_pending == false
      assert state.rekey_timer_ref == nil
      assert state.pending_r2i_key == nil
      assert state.pending_i2r_key == nil
      assert state.rekey_count == 0
    end

    test "accepts custom interval and packet limit" do
      state = Rekey.initial_state(%{
        rekey_interval_ms: 1_000,
        rekey_packet_limit: 100
      })

      assert state.rekey_interval_ms == 1_000
      assert state.rekey_packet_limit == 100
      # Other fields still default
      assert state.rekey_packet_count == 0
      assert state.rekey_pending == false
    end
  end

  # ---------------------------------------------------------------------------
  # should_rekey?/1
  # ---------------------------------------------------------------------------

  describe "should_rekey?/1" do
    test "returns :skip when below threshold" do
      state = mock_state(%{rekey_packet_count: 0, rekey_packet_limit: 100})
      assert {:skip, :below_threshold} = Rekey.should_rekey?(state)
    end

    test "returns :skip when just below threshold" do
      state = mock_state(%{rekey_packet_count: 99, rekey_packet_limit: 100})
      assert {:skip, :below_threshold} = Rekey.should_rekey?(state)
    end

    test "returns :initiate when at threshold" do
      state = mock_state(%{rekey_packet_count: 100, rekey_packet_limit: 100})
      assert :initiate = Rekey.should_rekey?(state)
    end

    test "returns :initiate when above threshold" do
      state = mock_state(%{rekey_packet_count: 200, rekey_packet_limit: 100})
      assert :initiate = Rekey.should_rekey?(state)
    end

    test "returns :skip when rekey already pending" do
      state = mock_state(%{rekey_pending: true, rekey_packet_count: 200, rekey_packet_limit: 100})
      assert {:skip, :already_pending} = Rekey.should_rekey?(state)
    end

    test "pending takes priority over threshold" do
      state = mock_state(%{rekey_pending: true, rekey_packet_count: 999_999, rekey_packet_limit: 1})
      assert {:skip, :already_pending} = Rekey.should_rekey?(state)
    end
  end

  # ---------------------------------------------------------------------------
  # initiate/2
  # ---------------------------------------------------------------------------

  describe "initiate/2" do
    test "sets rekey_pending and computes pending_r2i_key" do
      state = mock_state()
      key_material = :crypto.strong_rand_bytes(32)

      updates = Rekey.initiate(state, key_material)

      assert updates.rekey_pending == true
      assert byte_size(updates.pending_r2i_key) == 32
      # The pending key should be derived from the current r2i_key
      expected = Rekey.derive_new_key(state.r2i_key, key_material)
      assert updates.pending_r2i_key == expected
    end

    test "pending key differs from current key" do
      state = mock_state()
      key_material = :crypto.strong_rand_bytes(32)

      updates = Rekey.initiate(state, key_material)
      assert updates.pending_r2i_key != state.r2i_key
    end
  end

  # ---------------------------------------------------------------------------
  # complete/2
  # ---------------------------------------------------------------------------

  describe "complete/2" do
    test "returns :not_pending when no rekey in progress" do
      state = mock_state(%{rekey_pending: false})
      assert :not_pending = Rekey.complete(state, :crypto.strong_rand_bytes(32))
    end

    test "completes rekey and rotates keys" do
      state = mock_state()
      gw_key_material = :crypto.strong_rand_bytes(32)
      client_key_material = :crypto.strong_rand_bytes(32)

      # Simulate initiation: set pending state
      pending_r2i = Rekey.derive_new_key(state.r2i_key, gw_key_material)
      state = %{state |
        rekey_pending: true,
        pending_r2i_key: pending_r2i,
        rekey_packet_count: 5000,
        rekey_count: 2
      }

      {:ok, updates} = Rekey.complete(state, client_key_material)

      # New r2i_key is the pending one (derived from gateway's material)
      assert updates.r2i_key == pending_r2i
      # New i2r_key is derived from client's material
      expected_i2r = Rekey.derive_new_key(state.i2r_key, client_key_material)
      assert updates.i2r_key == expected_i2r
      # Flags reset
      assert updates.rekey_pending == false
      assert updates.pending_r2i_key == nil
      assert updates.pending_i2r_key == nil
      # Counter reset
      assert updates.rekey_packet_count == 0
      # Rekey count incremented
      assert updates.rekey_count == 3
    end

    test "new keys differ from old keys" do
      state = mock_state()
      gw_material = :crypto.strong_rand_bytes(32)
      client_material = :crypto.strong_rand_bytes(32)

      pending_r2i = Rekey.derive_new_key(state.r2i_key, gw_material)
      state = %{state | rekey_pending: true, pending_r2i_key: pending_r2i}

      {:ok, updates} = Rekey.complete(state, client_material)

      assert updates.r2i_key != state.r2i_key
      assert updates.i2r_key != state.i2r_key
    end

    test "rekey counter resets to 0 after completion" do
      state = mock_state(%{rekey_packet_count: 4_294_967_296})
      gw_material = :crypto.strong_rand_bytes(32)
      client_material = :crypto.strong_rand_bytes(32)

      pending_r2i = Rekey.derive_new_key(state.r2i_key, gw_material)
      state = %{state | rekey_pending: true, pending_r2i_key: pending_r2i}

      {:ok, updates} = Rekey.complete(state, client_material)
      assert updates.rekey_packet_count == 0
    end
  end

  # ---------------------------------------------------------------------------
  # Full rekey flow (integration of pure functions)
  # ---------------------------------------------------------------------------

  describe "full rekey flow" do
    test "end-to-end: initiate → complete produces valid rotated keys" do
      state = mock_state(%{rekey_packet_count: 100, rekey_packet_limit: 100})
      original_r2i = state.r2i_key
      original_i2r = state.i2r_key

      # Step 1: Check threshold
      assert :initiate = Rekey.should_rekey?(state)

      # Step 2: Initiate (gateway generates material)
      gw_material = :crypto.strong_rand_bytes(32)
      updates = Rekey.initiate(state, gw_material)
      state = Map.merge(state, updates)

      assert state.rekey_pending == true
      assert state.pending_r2i_key != nil

      # Step 3: While pending, should_rekey? returns skip
      assert {:skip, :already_pending} = Rekey.should_rekey?(state)

      # Step 4: Client sends ACK with their material
      client_material = :crypto.strong_rand_bytes(32)
      {:ok, final_updates} = Rekey.complete(state, client_material)
      state = Map.merge(state, final_updates)

      # Verify: keys have rotated
      assert state.r2i_key != original_r2i
      assert state.i2r_key != original_i2r
      assert state.rekey_pending == false
      assert state.rekey_packet_count == 0
      assert state.rekey_count == 1

      # Step 5: After reset, should_rekey? returns skip (counter is 0)
      assert {:skip, :below_threshold} = Rekey.should_rekey?(state)
    end

    test "multiple consecutive rekeys produce unique keys each time" do
      state = mock_state(%{rekey_packet_limit: 10})
      keys_seen = MapSet.new()

      {final_state, final_keys} =
        Enum.reduce(1..5, {state, keys_seen}, fn _i, {s, ks} ->
          s = %{s | rekey_packet_count: 10}
          gw_mat = :crypto.strong_rand_bytes(32)
          updates = Rekey.initiate(s, gw_mat)
          s = Map.merge(s, updates)

          client_mat = :crypto.strong_rand_bytes(32)
          {:ok, final} = Rekey.complete(s, client_mat)
          s = Map.merge(s, final)

          ks = MapSet.put(ks, s.r2i_key)
          ks = MapSet.put(ks, s.i2r_key)
          {s, ks}
        end)

      # 5 rekeys × 2 keys = 10 unique keys (all different)
      assert MapSet.size(final_keys) == 10
      assert final_state.rekey_count == 5
    end
  end

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  describe "constants" do
    test "default interval is 24 hours in milliseconds" do
      assert Rekey.default_interval_ms() == 86_400_000
    end

    test "default packet limit is 2^32" do
      assert Rekey.default_packet_limit() == 4_294_967_296
    end
  end
end
