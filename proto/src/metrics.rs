//! Client-side Prometheus metrics for ZTLP.
//!
//! Provides counters, gauges, and histograms with Prometheus text exposition format.
//! Zero external dependencies — all metric types are hand-implemented.
//!
//! # Usage
//!
//! ```
//! use ztlp_proto::metrics::{MetricsRegistry, latency_buckets};
//!
//! let registry = MetricsRegistry::new("ztlp");
//! let packets_sent = registry.counter("packets_sent_total", "Total packets sent");
//! packets_sent.inc();
//! packets_sent.inc_by(10);
//!
//! let rtt = registry.histogram("rtt_seconds", "Round-trip time", latency_buckets());
//! rtt.observe(0.05);
//!
//! // Export Prometheus format
//! let output = registry.export();
//! ```

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Default histogram buckets for latency (in seconds).
pub fn latency_buckets() -> Vec<f64> {
    vec![
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]
}

/// Default histogram buckets for packet sizes (in bytes).
pub fn size_buckets() -> Vec<f64> {
    vec![64.0, 128.0, 256.0, 512.0, 1024.0, 1200.0, 1500.0]
}

/// Atomic counter (monotonically increasing).
pub struct Counter {
    value: AtomicU64,
    name: String,
    help: String,
    labels: BTreeMap<String, String>,
}

impl Counter {
    fn new(name: &str, help: &str) -> Self {
        Self {
            value: AtomicU64::new(0),
            name: name.to_string(),
            help: help.to_string(),
            labels: BTreeMap::new(),
        }
    }

    fn with_labels(name: &str, help: &str, labels: BTreeMap<String, String>) -> Self {
        Self {
            value: AtomicU64::new(0),
            name: name.to_string(),
            help: help.to_string(),
            labels,
        }
    }

    /// Increment the counter by 1.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the counter by `n`.
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Get the current counter value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Reset the counter to 0.
    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

/// Atomic gauge (can go up or down).
pub struct Gauge {
    // Store as u64 bits, interpret as f64.
    value: AtomicU64,
    name: String,
    help: String,
    labels: BTreeMap<String, String>,
}

impl Gauge {
    fn new(name: &str, help: &str) -> Self {
        Self {
            value: AtomicU64::new(f64::to_bits(0.0)),
            name: name.to_string(),
            help: help.to_string(),
            labels: BTreeMap::new(),
        }
    }

    /// Set the gauge to the given value.
    pub fn set(&self, v: f64) {
        self.value.store(f64::to_bits(v), Ordering::Relaxed);
    }

    /// Get the current gauge value.
    pub fn get(&self) -> f64 {
        f64::from_bits(self.value.load(Ordering::Relaxed))
    }

    /// Increment the gauge by 1.0.
    pub fn inc(&self) {
        loop {
            let current = self.value.load(Ordering::Relaxed);
            let new = f64::to_bits(f64::from_bits(current) + 1.0);
            if self
                .value
                .compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Decrement the gauge by 1.0.
    pub fn dec(&self) {
        loop {
            let current = self.value.load(Ordering::Relaxed);
            let new = f64::to_bits(f64::from_bits(current) - 1.0);
            if self
                .value
                .compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
}

/// Histogram with configurable buckets.
pub struct Histogram {
    buckets: Vec<(f64, AtomicU64)>, // (upper_bound, count)
    sum: AtomicU64,                 // stored as f64 bits
    count: AtomicU64,
    name: String,
    help: String,
}

impl Histogram {
    fn new(name: &str, help: &str, bucket_bounds: Vec<f64>) -> Self {
        let mut buckets: Vec<(f64, AtomicU64)> = bucket_bounds
            .into_iter()
            .map(|b| (b, AtomicU64::new(0)))
            .collect();
        // +Inf bucket
        buckets.push((f64::INFINITY, AtomicU64::new(0)));

        Self {
            buckets,
            sum: AtomicU64::new(f64::to_bits(0.0)),
            count: AtomicU64::new(0),
            name: name.to_string(),
            help: help.to_string(),
        }
    }

    /// Record an observation in the histogram.
    pub fn observe(&self, value: f64) {
        // Increment matching buckets (cumulative)
        for (bound, count) in &self.buckets {
            if value <= *bound {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Update sum (CAS loop for atomic f64 add)
        loop {
            let current = self.sum.load(Ordering::Relaxed);
            let new = f64::to_bits(f64::from_bits(current) + value);
            if self
                .sum
                .compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of observations.
    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Get the sum of all observed values.
    pub fn get_sum(&self) -> f64 {
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }
}

/// Metrics registry that manages all metrics and handles export.
pub struct MetricsRegistry {
    prefix: String,
    counters: RwLock<Vec<Arc<Counter>>>,
    gauges: RwLock<Vec<Arc<Gauge>>>,
    histograms: RwLock<Vec<Arc<Histogram>>>,
}

impl MetricsRegistry {
    /// Create a new registry. All metric names will be prefixed with `prefix_`.
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            counters: RwLock::new(Vec::new()),
            gauges: RwLock::new(Vec::new()),
            histograms: RwLock::new(Vec::new()),
        }
    }

    /// Register and return a new counter.
    pub fn counter(&self, name: &str, help: &str) -> Arc<Counter> {
        let full_name = format!("{}_{}", self.prefix, name);
        let counter = Arc::new(Counter::new(&full_name, help));
        self.counters.write().unwrap().push(counter.clone());
        counter
    }

    /// Register and return a new counter with labels.
    pub fn counter_with_labels(
        &self,
        name: &str,
        help: &str,
        labels: BTreeMap<String, String>,
    ) -> Arc<Counter> {
        let full_name = format!("{}_{}", self.prefix, name);
        let counter = Arc::new(Counter::with_labels(&full_name, help, labels));
        self.counters.write().unwrap().push(counter.clone());
        counter
    }

    /// Register and return a new gauge.
    pub fn gauge(&self, name: &str, help: &str) -> Arc<Gauge> {
        let full_name = format!("{}_{}", self.prefix, name);
        let gauge = Arc::new(Gauge::new(&full_name, help));
        self.gauges.write().unwrap().push(gauge.clone());
        gauge
    }

    /// Register and return a new histogram with the given bucket boundaries.
    pub fn histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<Histogram> {
        let full_name = format!("{}_{}", self.prefix, name);
        let histogram = Arc::new(Histogram::new(&full_name, help, buckets));
        self.histograms.write().unwrap().push(histogram.clone());
        histogram
    }

    /// Export all metrics in Prometheus text exposition format.
    pub fn export(&self) -> String {
        let mut output = String::new();

        // Counters
        for counter in self.counters.read().unwrap().iter() {
            output.push_str(&format!("# HELP {} {}\n", counter.name, counter.help));
            output.push_str(&format!("# TYPE {} counter\n", counter.name));
            let labels = format_labels(&counter.labels);
            output.push_str(&format!("{}{} {}\n", counter.name, labels, counter.get()));
        }

        // Gauges
        for gauge in self.gauges.read().unwrap().iter() {
            output.push_str(&format!("# HELP {} {}\n", gauge.name, gauge.help));
            output.push_str(&format!("# TYPE {} gauge\n", gauge.name));
            let labels = format_labels(&gauge.labels);
            output.push_str(&format!(
                "{}{} {}\n",
                gauge.name,
                labels,
                format_f64(gauge.get())
            ));
        }

        // Histograms
        for histogram in self.histograms.read().unwrap().iter() {
            output.push_str(&format!("# HELP {} {}\n", histogram.name, histogram.help));
            output.push_str(&format!("# TYPE {} histogram\n", histogram.name));
            for (bound, count) in &histogram.buckets {
                let le = if bound.is_infinite() {
                    "+Inf".to_string()
                } else {
                    format_f64(*bound)
                };
                output.push_str(&format!(
                    "{}_bucket{{le=\"{}\"}} {}\n",
                    histogram.name,
                    le,
                    count.load(Ordering::Relaxed)
                ));
            }
            output.push_str(&format!(
                "{}_sum {}\n",
                histogram.name,
                format_f64(histogram.get_sum())
            ));
            output.push_str(&format!(
                "{}_count {}\n",
                histogram.name,
                histogram.get_count()
            ));
        }

        output
    }
}

/// Format label pairs as `{key="value",key2="value2"}`, or empty string if none.
pub fn format_labels(labels: &BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let pairs: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, v))
        .collect();
    format!("{{{}}}", pairs.join(","))
}

/// Format an f64 for Prometheus exposition: integers without decimal point.
pub fn format_f64(v: f64) -> String {
    if v == v.floor() && v.abs() < 1e15 {
        format!("{:.0}", v)
    } else {
        format!("{}", v)
    }
}

/// Pre-defined ZTLP client metrics.
pub struct ZtlpMetrics {
    /// Total ZTLP packets sent.
    pub packets_sent: Arc<Counter>,
    /// Total ZTLP packets received.
    pub packets_received: Arc<Counter>,
    /// Total bytes sent.
    pub bytes_sent: Arc<Counter>,
    /// Total bytes received.
    pub bytes_received: Arc<Counter>,
    /// Total Noise_XX handshakes initiated.
    pub handshakes_total: Arc<Counter>,
    /// Failed handshake attempts.
    pub handshake_failures: Arc<Counter>,
    /// Total packet retransmissions.
    pub retransmits: Arc<Counter>,
    /// Packets recovered via FEC.
    pub fec_recoveries: Arc<Counter>,
    /// Currently active mux streams.
    pub active_streams: Arc<Gauge>,
    /// Current congestion window in packets.
    pub cwnd_packets: Arc<Gauge>,
    /// Current smoothed RTT.
    pub rtt_seconds: Arc<Gauge>,
    /// Current PMTUD effective MTU.
    pub effective_mtu: Arc<Gauge>,
    /// RTT distribution histogram.
    pub rtt_histogram: Arc<Histogram>,
    /// Packet size distribution histogram.
    pub packet_size_histogram: Arc<Histogram>,
    /// The underlying registry (for custom metrics or export).
    pub registry: Arc<MetricsRegistry>,
}

impl ZtlpMetrics {
    /// Create a new set of pre-defined ZTLP client metrics.
    pub fn new() -> Self {
        let registry = Arc::new(MetricsRegistry::new("ztlp"));
        Self {
            packets_sent: registry.counter("packets_sent_total", "Total ZTLP packets sent"),
            packets_received: registry
                .counter("packets_received_total", "Total ZTLP packets received"),
            bytes_sent: registry.counter("bytes_sent_total", "Total bytes sent"),
            bytes_received: registry.counter("bytes_received_total", "Total bytes received"),
            handshakes_total: registry
                .counter("handshakes_total", "Total Noise_XX handshakes initiated"),
            handshake_failures: registry
                .counter("handshake_failures_total", "Failed handshake attempts"),
            retransmits: registry.counter("retransmits_total", "Total packet retransmissions"),
            fec_recoveries: registry.counter("fec_recoveries_total", "Packets recovered via FEC"),
            active_streams: registry.gauge("active_streams", "Currently active mux streams"),
            cwnd_packets: registry.gauge("cwnd_packets", "Current congestion window in packets"),
            rtt_seconds: registry.gauge("rtt_seconds", "Current smoothed RTT"),
            effective_mtu: registry.gauge("effective_mtu_bytes", "Current PMTUD effective MTU"),
            rtt_histogram: registry.histogram(
                "rtt_duration_seconds",
                "RTT distribution",
                latency_buckets(),
            ),
            packet_size_histogram: registry.histogram(
                "packet_size_bytes",
                "Packet size distribution",
                size_buckets(),
            ),
            registry,
        }
    }

    /// Export Prometheus text format.
    pub fn export(&self) -> String {
        self.registry.export()
    }
}

impl Default for ZtlpMetrics {
    fn default() -> Self {
        Self::new()
    }
}
