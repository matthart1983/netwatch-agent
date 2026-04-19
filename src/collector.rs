use crate::config::AgentConfig;
use chrono::Utc;
use netwatch_sdk::collectors::network_intel::{InterfaceRateEvent, NetworkIntelCollector};
use netwatch_sdk::collectors::{
    config as net_config, connections, disk, health, process_bandwidth, system, traffic,
};
use netwatch_sdk::types::{HealthMetric, InterfaceMetric, Snapshot, SystemMetric};
use std::sync::{Arc, Mutex};

// v0.2.0 compatibility:
// Server validates timestamp is within ±24 hours of server time.
// We always use Utc::now() which is safe and recommended.

const MAX_CONNECTIONS_PER_SNAPSHOT: usize = 100;
const MAX_PROCESSES_PER_SNAPSHOT: usize = 25;

pub struct MetricsCollector {
    rate_tracker: traffic::InterfaceRateTracker,
    gateway_rtt_history: health::RttHistory,
    dns_rtt_history: health::RttHistory,
    intel: Arc<Mutex<NetworkIntelCollector>>,
    gateway: Option<String>,
    dns_server: Option<String>,
    filter_interfaces: Vec<String>,
}

impl MetricsCollector {
    pub fn new(cfg: &AgentConfig) -> Self {
        let gateway = cfg.gateway.clone().or_else(net_config::detect_gateway);
        let dns_server = cfg.dns_server.clone().or_else(net_config::detect_dns);

        if let Some(ref gw) = gateway {
            tracing::info!("gateway: {}", gw);
        } else {
            tracing::warn!("no gateway detected");
        }
        if let Some(ref dns) = dns_server {
            tracing::info!("dns: {}", dns);
        } else {
            tracing::warn!("no dns server detected");
        }

        let mut intel = NetworkIntelCollector::new();
        if let Some(threshold) = cfg.bandwidth_alert_bytes_per_sec {
            intel.set_bandwidth_threshold(threshold);
        }

        Self {
            rate_tracker: traffic::InterfaceRateTracker::new(),
            gateway_rtt_history: health::RttHistory::new(),
            dns_rtt_history: health::RttHistory::new(),
            intel: Arc::new(Mutex::new(intel)),
            gateway,
            dns_server,
            filter_interfaces: cfg.interfaces.clone(),
        }
    }

    /// Handle to the NetworkIntel collector — callers outside the main
    /// metrics cycle (e.g. the packet capture thread) use this to feed
    /// events.
    pub fn intel_handle(&self) -> Arc<Mutex<NetworkIntelCollector>> {
        Arc::clone(&self.intel)
    }

    pub fn collect(&mut self, include_health: bool) -> Snapshot {
        let interfaces = self.collect_interfaces();
        let health = if include_health {
            Some(self.collect_health())
        } else {
            None
        };

        let system_metric = {
            let cpu = system::measure_cpu_usage();
            let mem = system::read_memory();
            let load = system::read_load_avg();
            let swap = system::read_swap();
            Some(SystemMetric {
                cpu_usage_pct: cpu,
                memory_total_bytes: mem.as_ref().map(|m| m.total_bytes),
                memory_used_bytes: mem.as_ref().map(|m| m.used_bytes),
                memory_available_bytes: mem.as_ref().map(|m| m.available_bytes),
                load_avg_1m: load.as_ref().map(|l| l.one),
                load_avg_5m: load.as_ref().map(|l| l.five),
                load_avg_15m: load.as_ref().map(|l| l.fifteen),
                swap_total_bytes: swap.as_ref().map(|s| s.total_bytes),
                swap_used_bytes: swap.as_ref().map(|s| s.used_bytes),
                cpu_per_core: system::measure_cpu_per_core(),
            })
        };

        // Feed interface rates into the intel collector so the bandwidth
        // detector can fire. The packet capture thread (if enabled) feeds
        // the remaining detectors (port scan, beaconing, DNS tunnel) via
        // the same Arc<Mutex<...>> handle.
        {
            let mut intel = self.intel.lock().unwrap_or_else(|p| p.into_inner());
            for iface in &interfaces {
                if let (Some(rx), Some(tx)) = (iface.rx_rate, iface.tx_rate) {
                    intel.on_interface_rate(InterfaceRateEvent {
                        iface: iface.name.clone(),
                        rx_bps: rx as u64,
                        tx_bps: tx as u64,
                    });
                }
            }
            intel.tick();
        }

        let tcp_states = connections::collect_tcp_states();
        let disk_usage_data = disk::collect_disk_usage();
        let disk_io_data = disk::collect_disk_io();

        let raw_connections = connections::collect_connections();
        let connection_count = Some(
            raw_connections
                .iter()
                .filter(|c| c.state == "ESTABLISHED")
                .count() as u32,
        );
        let processes = {
            let ranked = process_bandwidth::attribute(
                &raw_connections,
                &interfaces,
                MAX_PROCESSES_PER_SNAPSHOT,
            );
            if ranked.is_empty() {
                None
            } else {
                Some(ranked)
            }
        };
        let top = connections::top_connections(raw_connections, MAX_CONNECTIONS_PER_SNAPSHOT);
        let connections_field = if top.is_empty() { None } else { Some(top) };

        let (active_alerts, dns) = {
            let intel = self.intel.lock().unwrap_or_else(|p| p.into_inner());
            (intel.active_alerts(), intel.dns_analytics())
        };
        let alerts_field = if active_alerts.is_empty() {
            None
        } else {
            Some(active_alerts)
        };
        let dns_analytics_field = if dns.is_empty() { None } else { Some(dns) };

        Snapshot {
            timestamp: Utc::now(),
            interfaces,
            health,
            connection_count,
            system: system_metric,
            disk_usage: if disk_usage_data.is_empty() {
                None
            } else {
                Some(disk_usage_data)
            },
            disk_io: disk_io_data,
            tcp_time_wait: Some(tcp_states.time_wait),
            tcp_close_wait: Some(tcp_states.close_wait),
            processes,
            connections: connections_field,
            alerts: alerts_field,
            dns_analytics: dns_analytics_field,
        }
    }

    fn collect_interfaces(&mut self) -> Vec<InterfaceMetric> {
        let mut metrics = match traffic::sample(&mut self.rate_tracker) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("failed to collect interface stats: {}", e);
                return Vec::new();
            }
        };

        if !self.filter_interfaces.is_empty() {
            metrics.retain(|m| self.filter_interfaces.iter().any(|f| f == &m.name));
        }

        metrics
    }

    fn collect_health(&mut self) -> HealthMetric {
        let (gateway_rtt, gateway_loss, gateway_ip) = if let Some(ref gw) = self.gateway {
            let result = health::run_ping(gw);
            (result.rtt_ms, Some(result.loss_pct), Some(gw.clone()))
        } else {
            (None, None, None)
        };

        let (dns_rtt, dns_loss, dns_ip) = if let Some(ref dns) = self.dns_server {
            let result = health::run_ping(dns);
            (result.rtt_ms, Some(result.loss_pct), Some(dns.clone()))
        } else {
            (None, None, None)
        };

        self.gateway_rtt_history.push(gateway_rtt);
        self.dns_rtt_history.push(dns_rtt);

        HealthMetric {
            gateway_ip,
            gateway_rtt_ms: gateway_rtt,
            gateway_loss_pct: gateway_loss,
            dns_ip,
            dns_rtt_ms: dns_rtt,
            dns_loss_pct: dns_loss,
            gateway_rtt_history: if self.gateway_rtt_history.is_empty() {
                None
            } else {
                Some(self.gateway_rtt_history.snapshot())
            },
            dns_rtt_history: if self.dns_rtt_history.is_empty() {
                None
            } else {
                Some(self.dns_rtt_history.snapshot())
            },
        }
    }
}
