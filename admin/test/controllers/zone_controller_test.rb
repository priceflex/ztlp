# frozen_string_literal: true

# Slice 5c: the /zone page (spec Slice 5, §2.1 routes).
#
# GET  /zone             zone#show      zone, authority status, secrets set/not set,
#                        last publish + reconcile, drift table (ns_drift_json),
#                        Publish now / Reconcile now buttons (write access only)
# POST /zone/publish     zone#publish   enqueue RepublishNsJob now
# POST /zone/reconcile   zone#reconcile enqueue ReconcileNsJob now
#
# Jobs are enqueued (not run inline) so a failed NS write cannot 500 the button;
# the recurring jobs + audit rows surface the outcome. read_only admins get 403.
require "test_helper"
require "json"

class ZoneControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary
  end

  # ---------------------------------------------------------------- show

  test "zone page shows name, ns addr and authority status" do
    get zone_path
    assert_response :success
    assert_includes response.body, @zone.name
    assert_includes response.body, @zone.ns_addr
    assert_includes response.body, "not imported"
  end

  test "zone page shows the imported authority pubkey" do
    seed, pub = Ztlp::Ed25519.generate
    @zone.authority_seed_ct = seed
    @zone.authority_pubkey_hex = pub
    @zone.save!(validate: false)
    get zone_path
    assert_response :success
    assert_includes response.body, pub
    refute_includes response.body, "not imported"
  end

  test "zone page shows each secret as set or not set" do
    get zone_path
    assert_response :success
    body = response.body
    assert_includes body, "Enrollment secret"
    assert_includes body, "Relay secret"
    assert_includes body, "NS admin API secret"
    assert body.scan(/Not set/).size >= 3, "unconfigured secrets must read Not set"
  end

  test "zone page shows set secrets after import" do
    @zone.enrollment_secret_ct = "a" * 64
    @zone.relay_secret_ct = "z" * 48
    @zone.ns_admin_api_secret_ct = "b" * 64
    @zone.save!
    get zone_path
    body = response.body
    assert_includes body, "Set"
    refute_includes body, "Not set"
  end

  test "zone page renders the drift table from ns_drift_json" do
    SystemSetting[(
      "ns_drift_json"
    )] = {
      "zone" => @zone.name, "checked_at" => 1, "status" => "ok",
      "user" => { "panel" => 1, "ns" => 0, "missing_in_ns" => [ "steve.users.test.ztlp" ], "extra_in_ns" => [] },
      "device" => { "panel" => 0, "ns" => 0, "missing_in_ns" => [], "extra_in_ns" => [] },
      "group" => { "panel" => 2, "ns" => 1, "missing_in_ns" => [ "admins.groups.test.ztlp" ], "extra_in_ns" => [] }
    }.to_json
    get zone_path
    assert_response :success
    assert_includes response.body, "steve.users.test.ztlp"
    assert_includes response.body, "admins.groups.test.ztlp"
  end

  test "zone page shows a failed reconcile status" do
    SystemSetting[(
      "ns_drift_json"
    )] = { "zone" => @zone.name, "checked_at" => 1, "status" => "failed", "error" => "0x0C timeout" }.to_json
    get zone_path
    assert_response :success
    assert_includes response.body, "failed"
    assert_includes response.body, "0x0C timeout"
  end

  test "zone page shows a not_configured reconcile status" do
    SystemSetting[(
      "ns_drift_json"
    )] = { "zone" => @zone.name, "checked_at" => 1, "status" => "not_configured" }.to_json
    get zone_path
    assert_response :success
    assert_includes response.body, "not_configured"
  end

  # ------------------------------------------------------------ mutations

  # The test adapter stores the job as a serialized hash under the "job"
  # key; `job_class` carries the deserializable class name.
  def enqueued_job_class
    ActiveJob::Base.queue_adapter.enqueued_jobs.last["job_class"]
  end

  test "publish now enqueues RepublishNsJob and redirects" do
    assert_difference "ActiveJob::Base.queue_adapter.enqueued_jobs.size", 1 do
      post zone_publish_path
    end
    assert_response :redirect
    assert response.location.end_with?("/zone"), "must redirect to the zone page, got #{response.location}"
    assert_equal "RepublishNsJob", enqueued_job_class
  end

  test "reconcile now enqueues ReconcileNsJob and redirects" do
    assert_difference "ActiveJob::Base.queue_adapter.enqueued_jobs.size", 1 do
      post zone_reconcile_path
    end
    assert_response :redirect
    assert_equal "ReconcileNsJob", enqueued_job_class
  end

  test "read_only admin gets 403 on both mutations" do
    ro_admin, ro_seed = make_admin(role: "read_only", username: "reader")
    sign_in_as(ro_admin, ro_seed)
    assert_no_difference "ActiveJob::Base.queue_adapter.enqueued_jobs.size" do
      post zone_publish_path
      assert_response :forbidden
      post zone_reconcile_path
      assert_response :forbidden
    end
  end

  test "write-access buttons are hidden for read_only admins" do
    ro_admin, ro_seed = make_admin(role: "read_only", username: "reader2")
    sign_in_as(ro_admin, ro_seed)
    get zone_path
    assert_response :success
    refute_includes response.body, "Publish now"
    refute_includes response.body, "Reconcile now"
  end

  # The zone page is part of the rail: /zone gets aria-current.
  test "rail marks the zone page current" do
    get zone_path
    assert_select ".rail .nav a[href=\"/zone\"][aria-current=page]", 1
  end

  # Publisher audits each USER/DEVICE/GROUP row as the target, so "last publish" must look
  # at every ns.publish row, and a user whose id equals the zone's id must not count as a
  # zone reconcile.
  test "last publish counts entity-targeted ns.publish rows; reconcile is zone-typed only" do
    user = @zone.users.create!(username: "pub1", role: "user", status: "active")
    AuditLog.record!("ns.publish", target: user, status: "ok", details: { name: user.ns_name, type: "user" })
    AuditLog.create!(action: "ns.reconcile", target_type: "User", target_id: @zone.id, status: "ok",
                     created_at: Time.utc(2030, 1, 1))
    get zone_path
    assert_select ".tally-item", text: /Last publish/ do
      assert_select ".tally-n", "Yes"
    end
    assert_select ".tally-item", text: /Last reconcile/ do
      assert_select ".tally-s", "never"
    end
  end
end
