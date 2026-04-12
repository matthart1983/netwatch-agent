use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::collectors::disk::{DiskIo, DiskUsage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRequest {
    pub agent_version: String,
    pub host: HostInfo,
    pub snapshots: Vec<Snapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub host_id: Uuid,
    pub hostname: String,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub uptime_secs: Option<u64>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub memory_total_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub interfaces: Vec<InterfaceMetric>,
    pub health: Option<HealthMetric>,
    pub connection_count: Option<u32>,
    pub system: Option<SystemMetric>,
    pub disk_usage: Option<Vec<DiskUsage>>,
    pub disk_io: Option<DiskIo>,
    pub tcp_time_wait: Option<u32>,
    pub tcp_close_wait: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceMetric {
    pub name: String,
    pub is_up: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_delta: u64,
    pub tx_bytes_delta: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetric {
    pub gateway_ip: Option<String>,
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: Option<f64>,
    pub dns_ip: Option<String>,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetric {
    pub cpu_usage_pct: Option<f64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub load_avg_1m: Option<f64>,
    pub load_avg_5m: Option<f64>,
    pub load_avg_15m: Option<f64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub cpu_per_core: Option<Vec<f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub accepted: u32,
    pub rejected: u32,
    pub host_id: Uuid,
    pub results: Vec<SnapshotResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResult {
    pub index: usize,
    pub status: u16,
    pub message: String,
}
