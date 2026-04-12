use std::fs;
use std::process::Command;

pub fn detect_gateway() -> Option<String> {
    // Linux: `ip route`
    if let Ok(output) = Command::new("ip").args(["route"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.starts_with("default via ") {
                return line.split_whitespace().nth(2).map(|s| s.to_string());
            }
        }
    }

    // macOS fallback: `netstat -rn`
    if let Ok(output) = Command::new("netstat").args(["-rn"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 2 && cols[0] == "default" {
                return Some(cols[1].to_string());
            }
        }
    }

    None
}

pub fn detect_dns() -> Option<String> {
    if let Ok(contents) = fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver ") {
                if let Some(addr) = trimmed.split_whitespace().nth(1) {
                    return Some(addr.to_string());
                }
            }
        }
    }
    None
}
