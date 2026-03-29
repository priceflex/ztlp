use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

use ztlp_proto::metrics::{
    format_f64, format_labels, latency_buckets, size_buckets, MetricsRegistry, ZtlpMetrics,
};

// ── Counter tests ──────────────────────────────────────────────────

#[test]
fn counter_starts_at_zero() {
    let reg = MetricsRegistry::new("test");
    let c = reg.counter("ops", "operations");
    assert_eq!(c.get(), 0);
}

#[test]
fn counter_inc_increments_by_one() {
    let reg = MetricsRegistry::new("test");
    let c = reg.counter("ops", "operations");
    c.inc();
    assert_eq!(c.get(), 1);
}

#[test]
fn counter_inc_by_increments_by_n() {
    let reg = MetricsRegistry::new("test");
    let c = reg.counter("ops", "operations");
    c.inc_by(42);
    assert_eq!(c.get(), 42);
}

#[test]
fn counter_reset_sets_to_zero() {
    let reg = MetricsRegistry::new("test");
    let c = reg.counter("ops", "operations");
    c.inc_by(100);
    c.reset();
    assert_eq!(c.get(), 0);
}

#[test]
fn counter_is_thread_safe() {
    let reg = MetricsRegistry::new("test");
    let c = reg.counter("ops", "operations");
    let mut handles = Vec::new();
    for _ in 0..10 {
        let counter = Arc::clone(&c);
        handles.push(thread::spawn(move || {
            for _ in 0..1000 {
                counter.inc();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(c.get(), 10_000);
}

// ── Gauge tests ────────────────────────────────────────────────────

#[test]
fn gauge_starts_at_zero() {
    let reg = MetricsRegistry::new("test");
    let g = reg.gauge("temp", "temperature");
    assert!((g.get() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn gauge_set_sets_value() {
    let reg = MetricsRegistry::new("test");
    let g = reg.gauge("temp", "temperature");
    g.set(42.5);
    assert!((g.get() - 42.5).abs() < f64::EPSILON);
}

#[test]
fn gauge_inc_increments_by_one() {
    let reg = MetricsRegistry::new("test");
    let g = reg.gauge("temp", "temperature");
    g.inc();
    assert!((g.get() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn gauge_dec_decrements_by_one() {
    let reg = MetricsRegistry::new("test");
    let g = reg.gauge("temp", "temperature");
    g.set(5.0);
    g.dec();
    assert!((g.get() - 4.0).abs() < f64::EPSILON);
}

// ── Histogram tests ────────────────────────────────────────────────

#[test]
fn histogram_observe_increments_correct_buckets() {
    let reg = MetricsRegistry::new("test");
    let h = reg.histogram("dur", "duration", vec![0.1, 0.5, 1.0]);
    h.observe(0.3);
    // 0.3 <= 0.5, so bucket 0.5 and 1.0 and +Inf should be incremented
    // 0.3 > 0.1, so bucket 0.1 should NOT be incremented
    let output = reg.export();
    assert!(output.contains("test_dur_bucket{le=\"0.1\"} 0"));
    assert!(output.contains("test_dur_bucket{le=\"0.5\"} 1"));
    assert!(output.contains("test_dur_bucket{le=\"1\"} 1"));
}

#[test]
fn histogram_observe_increments_all_gte_buckets() {
    let reg = MetricsRegistry::new("test");
    let h = reg.histogram("dur", "duration", vec![0.1, 0.5, 1.0]);
    h.observe(0.05); // <= all buckets
    let output = reg.export();
    assert!(output.contains("test_dur_bucket{le=\"0.1\"} 1"));
    assert!(output.contains("test_dur_bucket{le=\"0.5\"} 1"));
    assert!(output.contains("test_dur_bucket{le=\"1\"} 1"));
    assert!(output.contains("test_dur_bucket{le=\"+Inf\"} 1"));
}

#[test]
fn histogram_sum_tracks_total() {
    let reg = MetricsRegistry::new("test");
    let h = reg.histogram("dur", "duration", vec![1.0]);
    h.observe(0.5);
    h.observe(1.5);
    assert!((h.get_sum() - 2.0).abs() < f64::EPSILON);
}

#[test]
fn histogram_count_tracks_observations() {
    let reg = MetricsRegistry::new("test");
    let h = reg.histogram("dur", "duration", vec![1.0]);
    h.observe(0.1);
    h.observe(0.2);
    h.observe(0.3);
    assert_eq!(h.get_count(), 3);
}

#[test]
fn histogram_inf_bucket_always_incremented() {
    let reg = MetricsRegistry::new("test");
    let h = reg.histogram("dur", "duration", vec![0.1]);
    h.observe(999.0); // way above all finite buckets
    let output = reg.export();
    assert!(output.contains("test_dur_bucket{le=\"+Inf\"} 1"));
    // finite bucket should NOT be incremented (999 > 0.1)
    assert!(output.contains("test_dur_bucket{le=\"0.1\"} 0"));
}

// ── Registry tests ─────────────────────────────────────────────────

#[test]
fn registry_counter_prefixes_name() {
    let reg = MetricsRegistry::new("myapp");
    let c = reg.counter("requests", "total requests");
    c.inc();
    let output = reg.export();
    assert!(output.contains("myapp_requests"));
}

#[test]
fn registry_gauge_prefixes_name() {
    let reg = MetricsRegistry::new("myapp");
    let g = reg.gauge("connections", "active connections");
    g.set(5.0);
    let output = reg.export();
    assert!(output.contains("myapp_connections"));
}

#[test]
fn registry_histogram_prefixes_name() {
    let reg = MetricsRegistry::new("myapp");
    let _h = reg.histogram("latency", "request latency", vec![0.1]);
    let output = reg.export();
    assert!(output.contains("myapp_latency"));
}

// ── Export tests ───────────────────────────────────────────────────

#[test]
fn export_produces_valid_prometheus_format() {
    let reg = MetricsRegistry::new("test");
    let c = reg.counter("requests", "total requests");
    c.inc_by(42);
    let output = reg.export();
    // Each metric block should have HELP, TYPE, and a value line
    assert!(output.contains("# HELP test_requests total requests\n"));
    assert!(output.contains("# TYPE test_requests counter\n"));
    assert!(output.contains("test_requests 42\n"));
}

#[test]
fn export_includes_help_and_type_lines() {
    let reg = MetricsRegistry::new("test");
    let _g = reg.gauge("temp", "temperature gauge");
    let output = reg.export();
    assert!(output.contains("# HELP test_temp temperature gauge\n"));
    assert!(output.contains("# TYPE test_temp gauge\n"));
}

#[test]
fn export_formats_counter_gauge_histogram_correctly() {
    let reg = MetricsRegistry::new("app");
    let c = reg.counter("reqs", "requests");
    c.inc_by(10);
    let g = reg.gauge("conns", "connections");
    g.set(3.0);
    let h = reg.histogram("dur", "duration", vec![0.5]);
    h.observe(0.1);

    let output = reg.export();

    // Counter
    assert!(output.contains("# TYPE app_reqs counter\n"));
    assert!(output.contains("app_reqs 10\n"));

    // Gauge
    assert!(output.contains("# TYPE app_conns gauge\n"));
    assert!(output.contains("app_conns 3\n"));

    // Histogram
    assert!(output.contains("# TYPE app_dur histogram\n"));
    assert!(output.contains("app_dur_bucket{le=\"0.5\"} 1\n"));
    assert!(output.contains("app_dur_sum 0.1\n"));
    assert!(output.contains("app_dur_count 1\n"));
}

#[test]
fn histogram_export_includes_bucket_sum_count() {
    let reg = MetricsRegistry::new("test");
    let h = reg.histogram("latency", "request latency", vec![0.01, 0.1, 1.0]);
    h.observe(0.05);
    h.observe(0.5);

    let output = reg.export();
    assert!(output.contains("test_latency_bucket{le="));
    assert!(output.contains("test_latency_sum"));
    assert!(output.contains("test_latency_count"));
}

#[test]
fn labels_format_correctly_in_export() {
    let reg = MetricsRegistry::new("test");
    let mut labels = BTreeMap::new();
    labels.insert("method".to_string(), "GET".to_string());
    let c = reg.counter_with_labels("requests", "http requests", labels);
    c.inc_by(42);
    let output = reg.export();
    assert!(output.contains("test_requests{method=\"GET\"} 42\n"));
}

// ── ZtlpMetrics tests ─────────────────────────────────────────────

#[test]
fn ztlp_metrics_new_creates_all_predefined_metrics() {
    let m = ZtlpMetrics::new();
    // Verify all 14 metrics exist by using them
    m.packets_sent.inc();
    m.packets_received.inc();
    m.bytes_sent.inc_by(1500);
    m.bytes_received.inc_by(1200);
    m.handshakes_total.inc();
    m.handshake_failures.inc();
    m.retransmits.inc();
    m.fec_recoveries.inc();
    m.active_streams.set(3.0);
    m.cwnd_packets.set(10.0);
    m.rtt_seconds.set(0.05);
    m.effective_mtu.set(1400.0);
    m.rtt_histogram.observe(0.05);
    m.packet_size_histogram.observe(512.0);

    assert_eq!(m.packets_sent.get(), 1);
    assert_eq!(m.bytes_sent.get(), 1500);
    assert!((m.active_streams.get() - 3.0).abs() < f64::EPSILON);
    assert_eq!(m.rtt_histogram.get_count(), 1);
}

#[test]
fn ztlp_metrics_export_includes_all_metrics() {
    let m = ZtlpMetrics::new();
    m.packets_sent.inc();
    m.rtt_seconds.set(0.025);
    m.rtt_histogram.observe(0.025);

    let output = m.export();

    // Check some representative metrics from each category
    assert!(output.contains("ztlp_packets_sent_total"));
    assert!(output.contains("ztlp_packets_received_total"));
    assert!(output.contains("ztlp_bytes_sent_total"));
    assert!(output.contains("ztlp_bytes_received_total"));
    assert!(output.contains("ztlp_handshakes_total"));
    assert!(output.contains("ztlp_handshake_failures_total"));
    assert!(output.contains("ztlp_retransmits_total"));
    assert!(output.contains("ztlp_fec_recoveries_total"));
    assert!(output.contains("ztlp_active_streams"));
    assert!(output.contains("ztlp_cwnd_packets"));
    assert!(output.contains("ztlp_rtt_seconds"));
    assert!(output.contains("ztlp_effective_mtu_bytes"));
    assert!(output.contains("ztlp_rtt_duration_seconds"));
    assert!(output.contains("ztlp_packet_size_bytes"));
}

// ── Bucket helper tests ────────────────────────────────────────────

#[test]
fn latency_buckets_returns_expected_values() {
    let b = latency_buckets();
    assert_eq!(
        b,
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    );
}

#[test]
fn size_buckets_returns_expected_values() {
    let b = size_buckets();
    assert_eq!(b, vec![64.0, 128.0, 256.0, 512.0, 1024.0, 1200.0, 1500.0]);
}

// ── format_f64 tests ───────────────────────────────────────────────

#[test]
fn format_f64_formats_integers_without_decimals() {
    assert_eq!(format_f64(42.0), "42");
    assert_eq!(format_f64(0.0), "0");
    assert_eq!(format_f64(1000.0), "1000");
}

#[test]
fn format_f64_formats_floats_correctly() {
    assert_eq!(format_f64(0.001), "0.001");
    assert_eq!(format_f64(3.14), "3.14");
    assert_eq!(format_f64(0.025), "0.025");
}
