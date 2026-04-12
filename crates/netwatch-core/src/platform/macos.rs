use super::InterfaceStats;
use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let mut stats = HashMap::new();

    // netstat -ibn gives: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll Drop
    let output = Command::new("netstat").args(["-ibn"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 11 {
            continue;
        }

        let name = cols[0].to_string();
        // Skip loopback and duplicates (netstat shows multiple rows per interface for different address families)
        if name == "lo0" {
            continue;
        }
        if stats.contains_key(&name) {
            continue;
        }

        // Only use lines with link-level addresses (contain <Link#N>)
        if !line.contains("<Link#") {
            continue;
        }

        let rx_packets: u64 = cols[4].parse().unwrap_or(0);
        let rx_errors: u64 = cols[5].parse().unwrap_or(0);
        let rx_bytes: u64 = cols[6].parse().unwrap_or(0);
        let tx_packets: u64 = cols[7].parse().unwrap_or(0);
        let tx_errors: u64 = cols[8].parse().unwrap_or(0);
        let tx_bytes: u64 = cols[9].parse().unwrap_or(0);
        let drops: u64 = if cols.len() > 11 {
            cols[11].parse().unwrap_or(0)
        } else {
            0
        };

        // Check if interface is up via ifconfig
        let is_up = Command::new("ifconfig")
            .arg(&name)
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).contains("status: active")
                    || String::from_utf8_lossy(&o.stdout).contains("RUNNING")
            })
            .unwrap_or(false);

        stats.insert(
            name.clone(),
            InterfaceStats {
                name,
                rx_bytes,
                tx_bytes,
                rx_packets,
                tx_packets,
                rx_errors,
                tx_errors,
                rx_drops: drops,
                tx_drops: 0,
                is_up,
            },
        );
    }

    Ok(stats)
}
