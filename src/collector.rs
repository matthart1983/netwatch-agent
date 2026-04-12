use crate::config::AgentConfig;
use chrono::Utc;
use netwatch_core::collectors::{config as net_config, connections, disk, health, system};
use netwatch_core::platform;
use netwatch_core::types::{HealthMetric, InterfaceMetric, Snapshot, SystemMetric};
use std::collections::HashMap;

// v0.2.0 compatibility:
// Server validates timestamp is within ±24 hours of server time.
// We always use Utc::now() which is safe and recommended.

pub struct MetricsCollector {
    prev_bytes: HashMap<String, (u64, u64)>,
    gateway: Option<String>,
    dns_server: Option<String>,
    filter_interfaces: Vec<String>,
}

impl MetricsCollector {
    pub fn new(cfg: &AgentConfig) -> Self {
        let gateway = cfg.gateway.clone().or_else(|| net_config::detect_gateway());
        let dns_server = cfg.dns_server.clone().or_else(|| net_config::detect_dns());

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

        Self {
            prev_bytes: HashMap::new(),
            gateway,
            dns_server,
            filter_interfaces: cfg.interfaces.clone(),
        }
    }

    pub fn collect(&mut self, include_health: bool) -> Snapshot {
        let interfaces = self.collect_interfaces();
        let health = if include_health {
            Some(self.collect_health())
        } else {
            None
        };
        let connection_count = Some(connections::count_established_connections());

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

        let tcp_states = connections::collect_tcp_states();
        let disk_usage_data = disk::collect_disk_usage();
        let disk_io_data = disk::collect_disk_io();

        Snapshot {
            timestamp: Utc::now(),
            interfaces,
            health,
            connection_count,
            system: system_metric,
            disk_usage: if disk_usage_data.is_empty() { None } else { Some(disk_usage_data) },
            disk_io: disk_io_data,
            tcp_time_wait: Some(tcp_states.time_wait),
            tcp_close_wait: Some(tcp_states.close_wait),
        }
    }

    fn collect_interfaces(&mut self) -> Vec<InterfaceMetric> {
        let stats = match platform::collect_interface_stats() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to collect interface stats: {}", e);
                return Vec::new();
            }
        };

        let mut metrics = Vec::new();

        for (name, stat) in &stats {
            if !self.filter_interfaces.is_empty()
                && !self.filter_interfaces.iter().any(|f| f == name)
            {
                continue;
            }

            let (rx_delta, tx_delta) = if let Some(&(prev_rx, prev_tx)) = self.prev_bytes.get(name) {
                (
                    stat.rx_bytes.saturating_sub(prev_rx),
                    stat.tx_bytes.saturating_sub(prev_tx),
                )
            } else {
                (0, 0)
            };

            self.prev_bytes.insert(name.clone(), (stat.rx_bytes, stat.tx_bytes));

            metrics.push(InterfaceMetric {
                name: name.clone(),
                is_up: stat.is_up,
                rx_bytes: stat.rx_bytes,
                tx_bytes: stat.tx_bytes,
                rx_bytes_delta: rx_delta,
                tx_bytes_delta: tx_delta,
                rx_packets: stat.rx_packets,
                tx_packets: stat.tx_packets,
                rx_errors: stat.rx_errors,
                tx_errors: stat.tx_errors,
                rx_drops: stat.rx_drops,
                tx_drops: stat.tx_drops,
            });
        }

        metrics.sort_by(|a, b| a.name.cmp(&b.name));
        metrics
    }

    fn collect_health(&self) -> HealthMetric {
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

        HealthMetric {
            gateway_ip,
            gateway_rtt_ms: gateway_rtt,
            gateway_loss_pct: gateway_loss,
            dns_ip,
            dns_rtt_ms: dns_rtt,
            dns_loss_pct: dns_loss,
        }
    }
}
