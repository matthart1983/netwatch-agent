//! OpenTelemetry (OTLP/HTTP) metrics exporter for the agent.
//!
//! Runs alongside the cloud sender: each collection tick is mapped to OTel
//! network/system semantic-convention metrics and a `PeriodicReader` pushes
//! them to an OTLP collector (HTTP/protobuf). Aggregate-only — no per-process
//! or per-connection attributes — so cardinality stays bounded.
//!
//! Endpoint/auth follow the OTel standard env vars
//! (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`,
//! `OTEL_EXPORTER_OTLP_HEADERS`); `--otlp-endpoint` overrides the endpoint.

use anyhow::{Context, Result};
use netwatch_sdk::types::Snapshot;
use opentelemetry::metrics::{Counter, Gauge, MeterProvider};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::{runtime, Resource};
use std::time::Duration;

const DIRECTION: &str = "network.io.direction";
const IFACE: &str = "network.interface.name";
const STATE: &str = "system.network.state";
const TARGET: &str = "netwatch.link.target";

pub struct OtelExporter {
    /// Held to keep the meter provider (and its background export thread) alive;
    /// dropping it would stop exporting. Also flushed by `shutdown()`.
    #[allow(dead_code)]
    provider: SdkMeterProvider,
    net_io: Counter<u64>,    // system.network.io (cumulative bytes, By)
    throughput: Gauge<f64>,  // system.network.throughput (By/s)
    connections: Gauge<u64>, // netwatch.connections.count
    tcp_state: Gauge<u64>,   // system.network.connections, by state
    link_rtt: Gauge<f64>,    // netwatch.link.rtt (s), by target
    link_loss: Gauge<f64>,   // netwatch.link.loss (ratio), by target
    cpu: Gauge<f64>,         // system.cpu.utilization (ratio)
    mem_used: Gauge<u64>,    // system.memory.usage (By)
    load1: Gauge<f64>,       // system.cpu.load_average.1m
}

impl OtelExporter {
    /// Build the OTLP exporter. `endpoint` overrides the OTel env-var endpoint
    /// when `Some`. `interval` is the metric export period.
    pub fn new(endpoint: Option<&str>, hostname: &str, interval: Duration) -> Result<Self> {
        let mut builder = opentelemetry_otlp::MetricExporter::builder().with_http();
        if let Some(ep) = endpoint {
            builder = builder.with_endpoint(ep);
        }
        let exporter = builder.build().context("build OTLP metric exporter")?;

        let reader = PeriodicReader::builder(exporter, runtime::Tokio)
            .with_interval(interval)
            .build();

        let resource = Resource::new(vec![
            KeyValue::new("service.name", "netwatch-agent"),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("host.name", hostname.to_string()),
        ]);

        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();
        let meter = provider.meter("netwatch-agent");

        Ok(Self {
            net_io: meter
                .u64_counter("system.network.io")
                .with_unit("By")
                .build(),
            throughput: meter
                .f64_gauge("system.network.throughput")
                .with_unit("By/s")
                .build(),
            connections: meter
                .u64_gauge("netwatch.connections.count")
                .with_unit("{connection}")
                .build(),
            tcp_state: meter
                .u64_gauge("system.network.connections")
                .with_unit("{connection}")
                .build(),
            link_rtt: meter.f64_gauge("netwatch.link.rtt").with_unit("s").build(),
            link_loss: meter.f64_gauge("netwatch.link.loss").with_unit("1").build(),
            cpu: meter
                .f64_gauge("system.cpu.utilization")
                .with_unit("1")
                .build(),
            mem_used: meter
                .u64_gauge("system.memory.usage")
                .with_unit("By")
                .build(),
            load1: meter
                .f64_gauge("system.cpu.load_average.1m")
                .with_unit("1")
                .build(),
            provider,
        })
    }

    /// Map one snapshot to OTel metrics. The byte counter takes per-tick deltas
    /// (the SDK already computes them) so the SDK accumulates a correct
    /// cumulative; gauges record the latest value.
    pub fn record(&self, s: &Snapshot) {
        for i in &s.interfaces {
            let rx = [
                KeyValue::new(DIRECTION, "receive"),
                KeyValue::new(IFACE, i.name.clone()),
            ];
            let tx = [
                KeyValue::new(DIRECTION, "transmit"),
                KeyValue::new(IFACE, i.name.clone()),
            ];
            self.net_io.add(i.rx_bytes_delta, &rx);
            self.net_io.add(i.tx_bytes_delta, &tx);
            if let Some(r) = i.rx_rate {
                self.throughput.record(r, &rx);
            }
            if let Some(t) = i.tx_rate {
                self.throughput.record(t, &tx);
            }
        }

        if let Some(c) = s.connection_count {
            self.connections.record(c as u64, &[]);
        }
        if let Some(tw) = s.tcp_time_wait {
            self.tcp_state
                .record(tw as u64, &[KeyValue::new(STATE, "time_wait")]);
        }
        if let Some(cw) = s.tcp_close_wait {
            self.tcp_state
                .record(cw as u64, &[KeyValue::new(STATE, "close_wait")]);
        }

        if let Some(h) = &s.health {
            if let Some(rtt) = h.gateway_rtt_ms {
                self.link_rtt
                    .record(rtt / 1000.0, &[KeyValue::new(TARGET, "gateway")]);
            }
            if let Some(loss) = h.gateway_loss_pct {
                self.link_loss
                    .record(loss / 100.0, &[KeyValue::new(TARGET, "gateway")]);
            }
            if let Some(rtt) = h.dns_rtt_ms {
                self.link_rtt
                    .record(rtt / 1000.0, &[KeyValue::new(TARGET, "dns")]);
            }
            if let Some(loss) = h.dns_loss_pct {
                self.link_loss
                    .record(loss / 100.0, &[KeyValue::new(TARGET, "dns")]);
            }
        }

        if let Some(sys) = &s.system {
            if let Some(cpu) = sys.cpu_usage_pct {
                self.cpu.record(cpu / 100.0, &[]);
            }
            if let Some(mu) = sys.memory_used_bytes {
                self.mem_used.record(mu, &[]);
            }
            if let Some(l) = sys.load_avg_1m {
                self.load1.record(l, &[]);
            }
        }
    }

    /// Flush + shut down the exporter. Not yet wired to a signal handler — the
    /// `PeriodicReader` exports on its interval, so at most one interval is lost
    /// on an abrupt kill; kept for when graceful shutdown lands.
    #[allow(dead_code)]
    pub fn shutdown(&self) {
        let _ = self.provider.force_flush();
        let _ = self.provider.shutdown();
    }
}
