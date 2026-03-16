require "test_helper"

class ApplicationHelperTest < ActionView::TestCase
  test "health_status_badge returns colored badge" do
    badge = health_status_badge("healthy")
    assert_includes badge, "green"
    assert_includes badge, "healthy"
  end

  test "health_status_badge handles degraded" do
    badge = health_status_badge("degraded")
    assert_includes badge, "yellow"
  end

  test "health_status_badge handles down" do
    badge = health_status_badge("down")
    assert_includes badge, "red"
  end

  test "health_status_badge handles unknown" do
    badge = health_status_badge("unknown")
    assert_includes badge, "gray"
  end

  test "health_status_badge handles nil" do
    badge = health_status_badge(nil)
    assert_includes badge, "unknown"
  end

  test "health_status_icon returns correct emoji" do
    assert_equal "🟢", health_status_icon("healthy")
    assert_equal "🟡", health_status_icon("degraded")
    assert_equal "🔴", health_status_icon("down")
    assert_equal "⚪", health_status_icon("unknown")
    assert_equal "⚪", health_status_icon(nil)
  end

  test "health_border_color returns correct class" do
    assert_equal "border-green-500", health_border_color("healthy")
    assert_equal "border-yellow-500", health_border_color("degraded")
    assert_equal "border-red-500", health_border_color("down")
    assert_equal "border-gray-300", health_border_color("unknown")
  end

  test "format_uptime handles seconds" do
    assert_equal "30s", format_uptime(30)
  end

  test "format_uptime handles minutes" do
    assert_equal "5m 30s", format_uptime(330)
  end

  test "format_uptime handles hours" do
    assert_equal "2h 5m", format_uptime(7500)
  end

  test "format_uptime handles days" do
    assert_equal "1d 2h", format_uptime(93600)
  end

  test "format_uptime handles nil" do
    assert_equal "N/A", format_uptime(nil)
  end

  test "alert_count_badge returns empty for zero" do
    Alert.stubs(:active_count).returns(0)
    assert_equal "", alert_count_badge
  end

  test "alert_count_badge returns badge for positive count" do
    Alert.stubs(:active_count).returns(5)
    badge = alert_count_badge
    assert_includes badge, "5"
    assert_includes badge, "red"
  end

  test "ztlp_tunnel_indicator shows green when reachable" do
    machine = machines(:ns1)
    machine.ztlp_tunnel_reachable = true
    machine.ztlp_tunnel_latency_ms = 42
    machine.ztlp_tunnel_checked_at = Time.current
    html = ztlp_tunnel_indicator(machine)
    assert_includes html, "bg-green-500"
    assert_includes html, "ZTLP"
  end

  test "ztlp_tunnel_indicator shows red when checked but unreachable" do
    machine = machines(:ns1)
    machine.ztlp_tunnel_reachable = false
    machine.ztlp_tunnel_error = "Handshake timeout"
    machine.ztlp_tunnel_checked_at = Time.current
    html = ztlp_tunnel_indicator(machine)
    assert_includes html, "bg-red-500"
    assert_includes html, "ZTLP"
  end

  test "ztlp_tunnel_indicator shows gray when not checked" do
    machine = machines(:ns1)
    machine.ztlp_tunnel_checked_at = nil
    html = ztlp_tunnel_indicator(machine)
    assert_includes html, "bg-gray-300"
    assert_includes html, "not checked"
  end
end
