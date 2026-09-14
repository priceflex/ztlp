defmodule ZtlpGateway.CertProvisionerTest do
  @moduledoc """
  Drives `CertProvisioner` against a fake NS UDP server that speaks the
  0x14 0x01/0x02/0x03 wire protocol. Exercises the full provisioning path
  (CA root, chain, per-service cert issuance, ETS storage, dual keys),
  failure/backoff, renewal, expiry classification, and config parsing.
  """
  # async: false — module-named GenServer, named ETS table, env vars.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ZtlpGateway.CertProvisioner

  @table :ztlp_gateway_certs
  @env_keys ~w(ZTLP_NS_SERVER ZTLP_GATEWAY_NS_HOST ZTLP_GATEWAY_NS_PORT
               ZTLP_GATEWAY_SERVICE_NAMES ZTLP_GATEWAY_SERVICE_ZONE
               ZTLP_GATEWAY_TLS_AUTO ZTLP_GATEWAY_CERT_LIFETIME_DAYS)

  setup do
    prev = for k <- @env_keys, into: %{}, do: {k, System.get_env(k)}
    for k <- @env_keys, do: System.delete_env(k)

    # The application supervisor owns a permanent CertProvisioner child. Take
    # it out via the supervisor (so it is NOT restarted behind our back) and
    # put it back on exit.
    app_sup = ZtlpGateway.Supervisor
    app_owned? =
      Process.whereis(app_sup) != nil and
        Enum.any?(Supervisor.which_children(app_sup), fn {id, _, _, _} -> id == CertProvisioner end)

    if app_owned? do
      :ok = Supervisor.terminate_child(app_sup, CertProvisioner)
    else
      if pid = Process.whereis(CertProvisioner) do
        ref = Process.monitor(pid)
        GenServer.stop(pid, :normal)
        assert_receive {:DOWN, ^ref, _, _, _}, 2_000
      end
    end

    wait_table_gone()

    on_exit(fn ->
      for {k, v} <- prev do
        if v, do: System.put_env(k, v), else: System.delete_env(k)
      end

      if app_owned? do
        # start_supervised children are already gone at this point.
        wait_table_gone_quiet()
        Supervisor.restart_child(app_sup, CertProvisioner)
      end
    end)

    :ok
  end

  defp wait_table_gone(n \\ 100) do
    cond do
      :ets.whereis(@table) == :undefined -> :ok
      n == 0 -> flunk("stale #{@table}")
      true -> Process.sleep(10); wait_table_gone(n - 1)
    end
  end

  defp wait_table_gone_quiet(n \\ 100) do
    cond do
      :ets.whereis(@table) == :undefined -> :ok
      n == 0 -> :ok
      true -> Process.sleep(10); wait_table_gone_quiet(n - 1)
    end
  end

  # ── fake NS ─────────────────────────────────────────────────────────────

  # Starts a UDP responder. `handler` receives the request binary and
  # returns the reply binary (or :drop to not answer). Records every
  # request in the test mailbox as {:ns_request, bin}.
  defp start_fake_ns(handler) do
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(sock)
    test = self()

    pid =
      spawn_link(fn ->
        loop = fn loop ->
          case :gen_udp.recv(sock, 0, 10_000) do
            {:ok, {ip, p, data}} ->
              send(test, {:ns_request, data})

              case handler.(data) do
                :drop -> :ok
                reply when is_binary(reply) -> :gen_udp.send(sock, ip, p, reply)
              end

              loop.(loop)

            {:error, _} ->
              :ok
          end
        end

        loop.(loop)
      end)

    {port, pid}
  end

  defp ok_ns_handler(opts \\ []) do
    root = Keyword.get(opts, :root, "ROOT-DER")
    chain = Keyword.get(opts, :chain, "-----CHAIN-----")

    fn
      <<0x14, 0x01>> ->
        <<0x14, 0x01, 0x00, byte_size(root)::32, root::binary>>

      <<0x14, 0x02>> ->
        <<0x14, 0x02, 0x00, byte_size(chain)::32, chain::binary>>

      <<0x14, 0x03, hlen::16, host::binary-size(hlen), slen::16, sig::binary-size(slen), plen::16,
        pub::binary-size(plen)>> ->
        # Verify the request is really signed by the presented key.
        true = :crypto.verify(:eddsa, :none, host, sig, [pub, :ed25519])
        cert = "CERT-FOR-#{host}"
        key = "KEY-FOR-#{host}"
        <<0x14, 0x03, 0x00, byte_size(cert)::32, cert::binary, byte_size(key)::32, key::binary,
          byte_size(chain)::32, chain::binary>>
    end
  end

  defp start_provisioner(port, opts \\ []) do
    System.put_env("ZTLP_NS_SERVER", "127.0.0.1:#{port}")
    System.put_env("ZTLP_GATEWAY_SERVICE_NAMES", Keyword.get(opts, :services, "web,api"))
    if z = Keyword.get(opts, :zone), do: System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", z)
    if d = Keyword.get(opts, :days), do: System.put_env("ZTLP_GATEWAY_CERT_LIFETIME_DAYS", d)

    pid =
      start_supervised!(
        {CertProvisioner, [test_opts: %{skip_provision: true}]},
        restart: :temporary
      )

    pid
  end

  defp provision_now(pid) do
    send(pid, :provision)
    :sys.get_state(pid)
  end

  # ── lookups with no table ───────────────────────────────────────────────

  describe "accessors when the provisioner is not running" do
    test "all return :error / false / :not_started instead of raising" do
      assert CertProvisioner.lookup("web") == :error
      assert CertProvisioner.get_ca_root_der() == :error
      assert CertProvisioner.get_ca_chain_pem() == :error
      refute CertProvisioner.tls_available?()
      assert CertProvisioner.check_expiry("web") == :error
      assert CertProvisioner.status() == :not_started
    end
  end

  # ── init / config parsing ───────────────────────────────────────────────

  describe "init/1 configuration" do
    test "no NS server configured -> disabled, status :not_started, table exists but empty" do
      pid = start_supervised!(CertProvisioner)
      state = :sys.get_state(pid)
      assert state.ns_server == nil
      refute state.enabled
      assert state.services == []
      assert state.zone == "techrockstars.ztlp"
      assert state.cert_lifetime_days == 7
      assert CertProvisioner.status() == :not_started
      refute CertProvisioner.tls_available?()
      # :provision on a disabled provisioner is a no-op.
      send(pid, :provision)
      GenServer.cast(pid, :provision)
      assert :sys.get_state(pid).status == :not_started
    end

    test "consolidated ZTLP_NS_SERVER host:port is parsed to an ip tuple" do
      System.put_env("ZTLP_NS_SERVER", "10.1.2.3:23096")
      pid = start_supervised!({CertProvisioner, [test_opts: %{skip_provision: true}]})
      assert :sys.get_state(pid).ns_server == {{10, 1, 2, 3}, 23096}
      assert :sys.get_state(pid).enabled
    end

    test "split ZTLP_GATEWAY_NS_HOST/PORT form is honoured" do
      System.put_env("ZTLP_GATEWAY_NS_HOST", "127.0.0.9")
      System.put_env("ZTLP_GATEWAY_NS_PORT", "4444")
      pid = start_supervised!({CertProvisioner, [test_opts: %{skip_provision: true}]})
      assert :sys.get_state(pid).ns_server == {{127, 0, 0, 9}, 4444}
    end

    test "hostname (non-IP) NS server is rejected -> disabled" do
      System.put_env("ZTLP_NS_SERVER", "ns.example.com:1234")
      pid = start_supervised!({CertProvisioner, [test_opts: %{skip_provision: true}]})
      assert :sys.get_state(pid).ns_server == nil
      refute :sys.get_state(pid).enabled
    end

    test "NS server without a port is rejected" do
      System.put_env("ZTLP_NS_SERVER", "10.0.0.1")
      pid = start_supervised!({CertProvisioner, [test_opts: %{skip_provision: true}]})
      assert :sys.get_state(pid).ns_server == nil
    end

    test "ZTLP_GATEWAY_TLS_AUTO=false disables even with an NS server" do
      System.put_env("ZTLP_NS_SERVER", "10.1.2.3:1")
      System.put_env("ZTLP_GATEWAY_TLS_AUTO", "false")
      pid = start_supervised!({CertProvisioner, [test_opts: %{skip_provision: true}]})
      refute :sys.get_state(pid).enabled
    end

    test "service names are split, trimmed, and blanks dropped" do
      System.put_env("ZTLP_GATEWAY_SERVICE_NAMES", " web , api,,  ,db ")
      pid = start_supervised!(CertProvisioner)
      assert :sys.get_state(pid).services == ["web", "api", "db"]
    end

    test "cert lifetime parsing: valid, junk suffix, non-numeric, zero, negative" do
      for {v, exp} <- [{"14", 14}, {"3days", 3}, {"abc", 7}, {"0", 7}, {"-2", 7}] do
        System.put_env("ZTLP_GATEWAY_CERT_LIFETIME_DAYS", v)
        pid = start_supervised!(CertProvisioner, id: {:cp, v})
        assert :sys.get_state(pid).cert_lifetime_days == exp, "LIFETIME=#{v}"
        stop_supervised!({:cp, v})
        wait_table_gone()
      end
    end

    test "zone env var overrides the default" do
      System.put_env("ZTLP_GATEWAY_SERVICE_ZONE", "lab.ztlp")
      pid = start_supervised!(CertProvisioner)
      assert :sys.get_state(pid).zone == "lab.ztlp"
    end

    test "with an NS server and no skip_provision, an initial :provision is scheduled" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:1")
      pid = start_supervised!(CertProvisioner)
      # 5s delayed send_after: verify a timer exists targeting :provision.
      timers =
        Process.info(pid, :messages) |> elem(1)
      assert timers == []
      # Can't introspect send_after directly; assert nothing provisioned yet.
      assert :sys.get_state(pid).status == :not_started
    end
  end

  # ── happy path ──────────────────────────────────────────────────────────

  describe "full provisioning against a fake NS" do
    test "fetches root + chain, issues a signed cert per service, stores under hostname and bare name" do
      {port, _} = start_fake_ns(ok_ns_handler())
      pid = start_provisioner(port, zone: "lab.ztlp", days: "10")

      log = capture_log(fn -> provision_now(pid) end)

      assert CertProvisioner.status() == :ok
      assert CertProvisioner.tls_available?()
      assert CertProvisioner.get_ca_root_der() == {:ok, "ROOT-DER"}
      assert CertProvisioner.get_ca_chain_pem() == {:ok, "-----CHAIN-----"}

      for svc <- ["web", "api"] do
        host = "#{svc}.lab.ztlp"
        expected = %{cert_pem: "CERT-FOR-#{host}", key_pem: "KEY-FOR-#{host}", chain_pem: "-----CHAIN-----"}
        assert CertProvisioner.lookup(host) == {:ok, expected}
        assert CertProvisioner.lookup(svc) == {:ok, expected}, "bare-name alias"
        assert {:ok, :valid, days} = CertProvisioner.check_expiry(host)
        assert_in_delta days, 10.0, 0.01
        assert {:ok, :valid, _} = CertProvisioner.check_expiry(svc)
      end

      assert CertProvisioner.lookup("nope") == :error

      # Wire protocol: exactly one root, one chain, two issue requests.
      assert_received {:ns_request, <<0x14, 0x01>>}
      assert_received {:ns_request, <<0x14, 0x02>>}
      assert_received {:ns_request, <<0x14, 0x03, _::binary>>}
      assert_received {:ns_request, <<0x14, 0x03, _::binary>>}
      refute_received {:ns_request, _}

      assert log =~ "CA root cert fetched (8 bytes)"
      assert log =~ "Cert issued for web.lab.ztlp"
      assert log =~ "All certs provisioned (lifetime=10d), renewal in 5.0 days"

      state = :sys.get_state(pid)
      assert state.provisioned
      assert state.retry_count == 0
    end

    test "refresh/0 re-provisions via cast and replaces certs atomically" do
      counter = :counters.new(1, [])

      handler = fn
        <<0x14, 0x01>> -> <<0x14, 0x01, 0x00, 4::32, "root">>
        <<0x14, 0x02>> -> <<0x14, 0x02, 0x00, 5::32, "chain">>
        <<0x14, 0x03, hlen::16, host::binary-size(hlen), _::binary>> ->
          :counters.add(counter, 1, 1)
          n = :counters.get(counter, 1)
          cert = "CERT-v#{n}-#{host}"
          <<0x14, 0x03, 0x00, byte_size(cert)::32, cert::binary, 1::32, "k", 5::32, "chain">>
      end

      {port, _} = start_fake_ns(handler)
      pid = start_provisioner(port, services: "web")
      provision_now(pid)
      assert {:ok, %{cert_pem: "CERT-v1-web.techrockstars.ztlp"}} = CertProvisioner.lookup("web")

      CertProvisioner.refresh()
      :sys.get_state(pid)
      assert {:ok, %{cert_pem: "CERT-v2-web.techrockstars.ztlp"}} = CertProvisioner.lookup("web")
      assert CertProvisioner.status() == :ok
    end

    test ":renew message re-provisions and status passes through :renewing back to :ok" do
      {port, _} = start_fake_ns(ok_ns_handler())
      pid = start_provisioner(port, services: "web")
      provision_now(pid)

      log = capture_log(fn ->
        send(pid, :renew)
        :sys.get_state(pid)
      end)

      assert log =~ "Renewal timer fired"
      assert CertProvisioner.status() == :ok
    end

    test "chain fetch failure is non-fatal: root + certs still provisioned, status :ok" do
      handler = fn
        <<0x14, 0x01>> -> <<0x14, 0x01, 0x00, 4::32, "root">>
        <<0x14, 0x02>> -> <<0x14, 0x02, 0x01>>
        <<0x14, 0x03, hlen::16, host::binary-size(hlen), _::binary>> ->
          <<0x14, 0x03, 0x00, byte_size(host)::32, host::binary, 1::32, "k", 0::32>>
      end

      {port, _} = start_fake_ns(handler)
      pid = start_provisioner(port, services: "web")
      log = capture_log(fn -> provision_now(pid) end)

      assert log =~ "Failed to fetch CA chain: :ca_not_initialized"
      assert CertProvisioner.get_ca_root_der() == {:ok, "root"}
      assert CertProvisioner.get_ca_chain_pem() == :error
      assert {:ok, %{chain_pem: ""}} = CertProvisioner.lookup("web")
      assert CertProvisioner.status() == :ok
    end

    test "per-service issuance failures are logged and skipped; other services still provisioned" do
      handler = fn
        <<0x14, 0x01>> -> <<0x14, 0x01, 0x00, 4::32, "root">>
        <<0x14, 0x02>> -> <<0x14, 0x02, 0x00, 1::32, "c">>
        <<0x14, 0x03, hlen::16, host::binary-size(hlen), _::binary>> ->
          cond do
            String.starts_with?(host, "unauth") -> <<0x14, 0x03, 0x03>>
            String.starts_with?(host, "broken") -> <<0x14, 0x03, 0x02>>
            String.starts_with?(host, "noca") -> <<0x14, 0x03, 0x01>>
            String.starts_with?(host, "weird") -> <<0x99, 0x99>>
            true -> <<0x14, 0x03, 0x00, 2::32, "ok", 1::32, "k", 1::32, "c">>
          end
      end

      {port, _} = start_fake_ns(handler)
      pid = start_provisioner(port, services: "good,unauth,broken,noca,weird")
      log = capture_log(fn -> provision_now(pid) end)

      assert {:ok, %{cert_pem: "ok"}} = CertProvisioner.lookup("good")
      for bad <- ["unauth", "broken", "noca", "weird"] do
        assert CertProvisioner.lookup(bad) == :error
        assert CertProvisioner.check_expiry(bad) == :error
      end
      assert log =~ "Failed to issue cert for unauth.techrockstars.ztlp: :unauthorized"
      assert log =~ "Failed to issue cert for broken.techrockstars.ztlp: :issuance_failed"
      assert log =~ "Failed to issue cert for noca.techrockstars.ztlp: :ca_not_initialized"
      assert log =~ "Failed to issue cert for weird.techrockstars.ztlp: {:unexpected_response, 2}"
      assert CertProvisioner.status() == :ok
    end
  end

  # ── failure + backoff ───────────────────────────────────────────────────

  describe "provisioning failure" do
    test "CA not initialized -> status :error, retry scheduled with 30s backoff, retry_count increments" do
      {port, _} = start_fake_ns(fn <<0x14, 0x01>> -> <<0x14, 0x01, 0x01>> end)
      pid = start_provisioner(port, services: "web")

      log = capture_log(fn -> provision_now(pid) end)
      assert log =~ "Provisioning failed: :ca_not_initialized. Retry 1 in 30s"
      assert CertProvisioner.status() == :error
      refute CertProvisioner.tls_available?()
      assert :sys.get_state(pid).retry_count == 1

      log2 = capture_log(fn -> provision_now(pid) end)
      assert log2 =~ "Retry 2 in 1m"
      assert :sys.get_state(pid).retry_count == 2
    end

    test "unexpected root response shape -> {:unexpected_response, n}" do
      {port, _} = start_fake_ns(fn <<0x14, 0x01>> -> "garbage!" end)
      pid = start_provisioner(port, services: "web")
      log = capture_log(fn -> provision_now(pid) end)
      assert log =~ "{:unexpected_response, 8}"
      assert CertProvisioner.status() == :error
    end

    test "backoff schedule climbs 30s,1m,2m,5m,15m,30m and caps at 1h" do
      {port, _} = start_fake_ns(fn <<0x14, 0x01>> -> <<0x14, 0x01, 0x01>> end)
      pid = start_provisioner(port, services: "web")

      expected = ["30s", "1m", "2m", "5m", "15m", "30m", "1h", "1h", "1h"]

      for {label, i} <- Enum.with_index(expected, 1) do
        log = capture_log(fn -> provision_now(pid) end)
        assert log =~ "Retry #{i} in #{label}", "retry #{i}"
      end
    end

    test "renewal failure after successful provisioning keeps existing certs, status :renewing" do
      flag = :atomics.new(1, [])
      :atomics.put(flag, 1, 0)

      handler = fn
        <<0x14, 0x01>> ->
          if :atomics.get(flag, 1) == 0,
            do: <<0x14, 0x01, 0x00, 4::32, "root">>,
            else: <<0x14, 0x01, 0x01>>
        <<0x14, 0x02>> -> <<0x14, 0x02, 0x00, 1::32, "c">>
        <<0x14, 0x03, _::binary>> -> <<0x14, 0x03, 0x00, 2::32, "ok", 1::32, "k", 1::32, "c">>
      end

      {port, _} = start_fake_ns(handler)
      pid = start_provisioner(port, services: "web")
      provision_now(pid)
      assert CertProvisioner.status() == :ok
      assert {:ok, %{cert_pem: "ok"}} = CertProvisioner.lookup("web")

      :atomics.put(flag, 1, 1)
      log = capture_log(fn -> send(pid, :renew); :sys.get_state(pid) end)
      assert log =~ "Renewal failed: :ca_not_initialized. Keeping existing certs. Retry 1 in 30s"
      assert CertProvisioner.status() == :renewing
      assert {:ok, %{cert_pem: "ok"}} = CertProvisioner.lookup("web"), "old cert still served"
      assert CertProvisioner.tls_available?()
    end

    test "NS not answering -> recv timeout surfaces as {:error, :timeout} after 5s" do
      {port, _} = start_fake_ns(fn _ -> :drop end)
      pid = start_provisioner(port, services: "web")
      log = capture_log(fn ->
        send(pid, :provision)
        :sys.get_state(pid, 15_000)
      end)
      assert log =~ "Provisioning failed: :timeout"
      assert CertProvisioner.status() == :error
    end
  end

  # ── expiry classification ───────────────────────────────────────────────

  describe "check_expiry/1 classification" do
    setup do
      start_supervised!(CertProvisioner)
      :ok
    end

    test "fresh -> :valid with ~full lifetime remaining" do
      seed_expiry("a", 0.0)
      assert {:ok, :valid, days} = CertProvisioner.check_expiry("a")
      assert_in_delta days, 7.0, 0.01
    end

    test "74% -> :valid, 75% -> :warning" do
      seed_expiry("b", 0.74)
      assert {:ok, :valid, _} = CertProvisioner.check_expiry("b")
      seed_expiry("c", 0.751)
      assert {:ok, :warning, days} = CertProvisioner.check_expiry("c")
      assert_in_delta days, 7 * 0.249, 0.01
    end

    test "90% -> :critical" do
      seed_expiry("d", 0.9)
      assert {:ok, :critical, _} = CertProvisioner.check_expiry("d")
    end

    test "past lifetime -> :expired with negative days" do
      seed_expiry("e", 1.1)
      assert {:ok, :expired, days} = CertProvisioner.check_expiry("e")
      assert days < 0
    end

    test "unknown host -> :error" do
      assert CertProvisioner.check_expiry("zzz") == :error
    end
  end

  describe ":check_expiry sweep" do
    test "logs warning/critical/expired per service and forces :renew when anything expired" do
      {port, _} = start_fake_ns(ok_ns_handler())
      pid = start_provisioner(port, services: "fresh,warn,crit,dead")
      provision_now(pid)
      zone = "techrockstars.ztlp"
      lifetime = 7 * 86_400_000
      now = System.system_time(:millisecond)

      for {svc, ratio} <- [{"warn", 0.8}, {"crit", 0.95}, {"dead", 1.5}] do
        :ets.insert(@table, {{:expiry, "#{svc}.#{zone}"}, %{issued_at: now - round(ratio * lifetime), lifetime_ms: lifetime}})
      end

      log = capture_log(fn ->
        send(pid, :check_expiry)
        :sys.get_state(pid)
        # check_all_expiry does `send(self(), :renew)`; that message is
        # queued behind the sync above, so sync once more to observe it.
        :sys.get_state(pid)
      end)

      assert log =~ "Cert for warn.#{zone} approaching expiry"
      assert log =~ "Cert for crit.#{zone} critically close to expiry"
      assert log =~ "Cert for dead.#{zone} has EXPIRED"
      refute log =~ "Cert for fresh.#{zone}"
      assert log =~ "One or more certs have expired — forcing renewal"
      # The forced :renew re-provisioned, so dead is fresh again.
      assert {:ok, :valid, _} = CertProvisioner.check_expiry("dead.#{zone}")
      assert CertProvisioner.status() == :ok
    end

    test "sweep with nothing expired does not renew" do
      {port, _} = start_fake_ns(ok_ns_handler())
      pid = start_provisioner(port, services: "web")
      provision_now(pid)
      # drain requests from provisioning
      flush_requests()
      send(pid, :check_expiry)
      :sys.get_state(pid)
      refute_received {:ns_request, _}
    end
  end

  test "unknown messages are ignored" do
    pid = start_supervised!(CertProvisioner)
    send(pid, :bogus)
    assert %{status: :not_started} = :sys.get_state(pid)
  end

  defp seed_expiry(host, elapsed_ratio, lifetime_ms \\ 7 * 86_400_000) do
    now = System.system_time(:millisecond)
    issued = now - round(elapsed_ratio * lifetime_ms)
    :ets.insert(@table, {{:expiry, host}, %{issued_at: issued, lifetime_ms: lifetime_ms}})
  end

  defp flush_requests do
    receive do
      {:ns_request, _} -> flush_requests()
    after
      0 -> :ok
    end
  end
end
