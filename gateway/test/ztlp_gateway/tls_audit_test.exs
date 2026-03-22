defmodule ZtlpGateway.TlsAuditTest do
  use ExUnit.Case

  alias ZtlpGateway.AuditLog

  setup do
    # Ensure AuditLog is running
    case GenServer.whereis(AuditLog) do
      nil ->
        {:ok, _} = AuditLog.start_link()
      _pid ->
        :ok
    end

    AuditLog.clear()
    :ok
  end

  describe "tls_connection_established/3" do
    test "logs connection with identity" do
      identity = %{
        node_id: "abc123",
        node_name: "laptop.corp.ztlp",
        assurance: :hardware,
        authenticated: true
      }

      :ok = AuditLog.tls_connection_established("app.corp.ztlp", identity, {{127, 0, 0, 1}, 12345})

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_connection_established
      assert event.hostname == "app.corp.ztlp"
      assert event.node_id == "abc123"
      assert event.node_name == "laptop.corp.ztlp"
      assert event.assurance == :hardware
      assert event.authenticated == true
      assert event.source == {{127, 0, 0, 1}, 12345}
    end

    test "logs connection without identity" do
      :ok = AuditLog.tls_connection_established("app.corp.ztlp", nil)

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_connection_established
      assert event.authenticated == false
      assert event.node_id == nil
    end
  end

  describe "tls_auth_failed/3" do
    test "logs auth failure with reason" do
      :ok = AuditLog.tls_auth_failed("app.corp.ztlp", :policy_denied, {{10, 0, 0, 1}, 54321})

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_auth_failed
      assert event.hostname == "app.corp.ztlp"
      assert event.reason == :policy_denied
    end

    test "logs auth failure without source" do
      :ok = AuditLog.tls_auth_failed("app.corp.ztlp", :mtls_required)

      events = AuditLog.events(1)
      assert [event] = events
      assert event.source == nil
    end
  end

  describe "tls_mtls_identity/1" do
    test "logs identity details" do
      identity = %{
        node_id: "deadbeef",
        node_name: "phone.corp.ztlp",
        zone: "corp.ztlp",
        assurance: :software,
        key_source: "file"
      }

      :ok = AuditLog.tls_mtls_identity(identity)

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_mtls_identity
      assert event.node_id == "deadbeef"
      assert event.zone == "corp.ztlp"
      assert event.assurance == :software
      assert event.key_source == "file"
    end
  end

  describe "tls_policy_decision/4" do
    test "logs allow decision" do
      :ok = AuditLog.tls_policy_decision("steve@corp.ztlp", "webapp", :allow)

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_policy_decision
      assert event.identity == "steve@corp.ztlp"
      assert event.service == "webapp"
      assert event.decision == :allow
      assert event.reason == nil
    end

    test "logs deny decision with reason" do
      :ok = AuditLog.tls_policy_decision("alice@corp.ztlp", "admin", :deny, "not in admin group")

      events = AuditLog.events(1)
      assert [event] = events
      assert event.decision == :deny
      assert event.reason == "not in admin group"
    end
  end

  describe "tls_connection_closed/1" do
    test "logs connection closed with stats" do
      :ok =
        AuditLog.tls_connection_closed(%{
          sni: "app.corp.ztlp",
          service: "webapp",
          node_id: "abc123",
          reason: :client_close,
          duration_ms: 5000,
          bytes_in: 1024,
          bytes_out: 2048
        })

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_connection_closed
      assert event.duration_ms == 5000
      assert event.bytes_in == 1024
      assert event.bytes_out == 2048
      assert event.reason == :client_close
    end

    test "logs connection closed from keyword list" do
      :ok =
        AuditLog.tls_connection_closed(
          sni: "test.ztlp",
          reason: :timeout,
          duration_ms: 30000
        )

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_connection_closed
      assert event.reason == :timeout
    end
  end

  describe "tls_cert_issued/3" do
    test "logs cert issuance" do
      :ok = AuditLog.tls_cert_issued("webapp.corp.ztlp", "SERIAL001", "ZTLP Intermediate CA")

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_cert_issued
      assert event.hostname == "webapp.corp.ztlp"
      assert event.serial == "SERIAL001"
      assert event.issuer == "ZTLP Intermediate CA"
    end

    test "logs cert issuance without issuer" do
      :ok = AuditLog.tls_cert_issued("db.corp.ztlp", "SERIAL002")

      events = AuditLog.events(1)
      assert [event] = events
      assert event.issuer == nil
    end
  end

  describe "tls_cert_renewed/3" do
    test "logs cert renewal" do
      :ok = AuditLog.tls_cert_renewed("webapp.corp.ztlp", "OLD_SERIAL", "NEW_SERIAL")

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :tls_cert_renewed
      assert event.hostname == "webapp.corp.ztlp"
      assert event.old_serial == "OLD_SERIAL"
      assert event.new_serial == "NEW_SERIAL"
    end
  end

  describe "cert_revoked/2" do
    test "logs cert revocation" do
      :ok = AuditLog.cert_revoked("SHA256:abc123", "device stolen")

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :cert_revoked
      assert event.fingerprint == "SHA256:abc123"
      assert event.reason == "device stolen"
    end
  end

  describe "assurance_insufficient/4" do
    test "logs assurance mismatch" do
      :ok = AuditLog.assurance_insufficient("node123", :software, :hardware, "admin-panel")

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :assurance_insufficient
      assert event.node_id == "node123"
      assert event.actual_assurance == :software
      assert event.required_assurance == :hardware
      assert event.service == "admin-panel"
    end
  end

  describe "log_event/1" do
    test "logs arbitrary event map" do
      :ok = AuditLog.log_event(%{event: :custom_test, data: "hello"})

      events = AuditLog.events(1)
      assert [event] = events
      assert event.event == :custom_test
      assert event.data == "hello"
      assert event.wall_clock != nil
      assert event.timestamp != nil
    end
  end

  describe "event ordering" do
    test "events are returned newest first" do
      :ok = AuditLog.tls_cert_issued("first.ztlp", "001")
      Process.sleep(1)
      :ok = AuditLog.tls_cert_issued("second.ztlp", "002")
      Process.sleep(1)
      :ok = AuditLog.tls_cert_issued("third.ztlp", "003")

      events = AuditLog.events(3)
      hostnames = Enum.map(events, & &1.hostname)
      assert hostnames == ["third.ztlp", "second.ztlp", "first.ztlp"]
    end
  end
end
