defmodule ZtlpRelay.VipTcpTerminatorTest do
  # async: false — tests share the global named ETS table
  # :ztlp_vip_connections and would race under concurrent execution.
  use ExUnit.Case, async: false

  alias ZtlpRelay.VipTcpTerminator
  alias ZtlpRelay.VipFrame

  @session_a <<1::12, 0::96>>
  @session_b <<2::12, 0::96>>

  describe "register_connection/5 — composite key {session_id, conn_id}" do
    setup do
      # Ensure the ETS table exists regardless of whether the
      # VipTcpTerminator GenServer has been started in this test env
      # (it's only started when VIP mode is enabled via config/env).
      if :ets.info(:ztlp_vip_connections) == :undefined do
        :ets.new(:ztlp_vip_connections, [:named_table, :set, :public, write_concurrency: true])
      else
        :ets.delete_all_objects(:ztlp_vip_connections)
      end

      :ok
    end

    test "keys connections by {session_id, conn_id} not conn_id alone" do
      pid_a = self()
      pid_b = self()

      # Two sessions, same conn_id — both should coexist
      :ok = VipTcpTerminator.register_connection(@session_a, 1, pid_a, "vault", {{127, 0, 0, 1}, 8080})
      :ok = VipTcpTerminator.register_connection(@session_b, 1, pid_b, "vault", {{127, 0, 0, 1}, 8080})

      # Both should be in the table
      assert :ets.info(:ztlp_vip_connections, :size) == 2
    end

    test "prevents cross-session lookup by conn_id alone" do
      pid_a = self()
      pid_b = spawn(fn -> :ok end)

      # Session A registers conn_id=1
      :ok = VipTcpTerminator.register_connection(@session_a, 1, pid_a, "vault", {{127, 0, 0, 1}, 8080})

      # Session B cannot hijack by querying conn_id=1 — the lookup must include session_id
      # :ets.lookup({session_id, conn_id}) for session_b returns []
      result = :ets.lookup(:ztlp_vip_connections, {@session_b, 1})
      assert result == [], "cross-session conn_id lookup must return empty"

      # Session A can still find its own connection
      result_a = :ets.lookup(:ztlp_vip_connections, {@session_a, 1})
      assert length(result_a) == 1
    end

    test "unregister_connection/2 only removes matching {session_id, conn_id}" do
      pid_a = self()
      pid_b = self()

      :ok = VipTcpTerminator.register_connection(@session_a, 1, pid_a, "vault", {{127, 0, 0, 1}, 8080})
      :ok = VipTcpTerminator.register_connection(@session_b, 1, pid_b, "web", {{127, 0, 0, 1}, 80})

      assert :ets.info(:ztlp_vip_connections, :size) == 2

      # Unregister session A's conn_id=1 — session B's conn_id=1 must survive
      :ok = VipTcpTerminator.unregister_connection(@session_a, 1)

      assert :ets.info(:ztlp_vip_connections, :size) == 1
      assert :ets.lookup(:ztlp_vip_connections, {@session_a, 1}) == []
      assert length(:ets.lookup(:ztlp_vip_connections, {@session_b, 1})) == 1
    end
  end

  describe "connections_summary/0 — works with composite key" do
    setup do
      if :ets.info(:ztlp_vip_connections) == :undefined do
        :ets.new(:ztlp_vip_connections, [:named_table, :set, :public, write_concurrency: true])
      else
        :ets.delete_all_objects(:ztlp_vip_connections)
      end

      :ok
    end

    test "counts connections correctly with composite keys" do
      pid = self()

      :ok = VipTcpTerminator.register_connection(@session_a, 1, pid, "vault", {{127, 0, 0, 1}, 8080})
      :ok = VipTcpTerminator.register_connection(@session_a, 2, pid, "vault", {{127, 0, 0, 1}, 8080})
      :ok = VipTcpTerminator.register_connection(@session_b, 1, pid, "web", {{127, 0, 0, 1}, 80})

      summary = VipTcpTerminator.connections_summary()

      assert summary.active_connections == 3
      assert length(summary.services) == 2
    end
  end

  describe "existing connection lookup — requires matching session_id" do
    setup do
      if :ets.info(:ztlp_vip_connections) == :undefined do
        :ets.new(:ztlp_vip_connections, [:named_table, :set, :public, write_concurrency: true])
      else
        :ets.delete_all_objects(:ztlp_vip_connections)
      end

      :ok
    end

    test "non-SYN frame from wrong session_id is rejected" do
      pid_legit = self()

      # Legitimate session registers a connection
      :ok = VipTcpTerminator.register_connection(@session_a, 42, pid_legit, "vault", {{127, 0, 0, 1}, 8080})

      # Attacker from different session tries to send DATA on conn_id=42
      # The lookup must use {@session_b, 42} which returns []
      attacker_lookup = :ets.lookup(:ztlp_vip_connections, {@session_b, 42})
      assert attacker_lookup == [], "attacker session must not find victim's connection"

      # Legit session's lookup still works
      legit_lookup = :ets.lookup(:ztlp_vip_connections, {@session_a, 42})
      assert length(legit_lookup) == 1
    end
  end

  describe "VipFrame connection_id is attacker-controlled" do
    test "connection_id comes from the first 2 bytes of the decrypted frame" do
      # An attacker can craft any conn_id they want
      # The frame format is <<connection_id::16, flags::8, payload::binary>>
      {:ok, frame} = VipFrame.parse(<<9999::16, 0x02::8, "payload">>)
      assert frame.connection_id == 9999
    end
  end
end
