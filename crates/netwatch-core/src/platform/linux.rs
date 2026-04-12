use super::InterfaceStats;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let mut stats = HashMap::new();
    let net_dir = Path::new("/sys/class/net");

    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        if name == "lo" {
            continue;
        }

        let base = net_dir.join(&name);
        let stat_dir = base.join("statistics");

        let read_stat = |file: &str| -> u64 {
            fs::read_to_string(stat_dir.join(file))
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or(0)
        };

        let is_up = fs::read_to_string(base.join("operstate"))
            .unwrap_or_default()
            .trim()
            == "up";

        stats.insert(
            name.clone(),
            InterfaceStats {
                name,
                rx_bytes: read_stat("rx_bytes"),
                tx_bytes: read_stat("tx_bytes"),
                rx_packets: read_stat("rx_packets"),
                tx_packets: read_stat("tx_packets"),
                rx_errors: read_stat("rx_errors"),
                tx_errors: read_stat("tx_errors"),
                rx_drops: read_stat("rx_dropped"),
                tx_drops: read_stat("tx_dropped"),
                is_up,
            },
        );
    }

    Ok(stats)
}
