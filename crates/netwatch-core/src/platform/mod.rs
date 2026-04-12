#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use anyhow::Result;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
    pub is_up: bool,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::collect_interface_stats;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::collect_interface_stats;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    Ok(HashMap::new())
}
