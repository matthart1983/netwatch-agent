use anyhow::Result;
use netwatch_core::collectors::system;
use netwatch_core::types::HostInfo;
use std::fs;
use std::path::Path;
use uuid::Uuid;

fn host_id_path() -> String {
    if cfg!(target_os = "macos") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/.config/netwatch-agent/host-id", home);
        }
    }
    "/var/lib/netwatch-agent/host-id".to_string()
}

pub fn get_or_create_host_id() -> Result<Uuid> {
    let id_path = host_id_path();
    let path = Path::new(&id_path);

    if let Ok(contents) = fs::read_to_string(path) {
        if let Ok(id) = contents.trim().parse::<Uuid>() {
            return Ok(id);
        }
    }

    let id = Uuid::new_v4();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    // Best-effort write — if it fails (e.g. no write permission), we still return the ID
    // but it won't persist across restarts
    if fs::write(path, id.to_string()).is_err() {
        tracing::warn!("could not persist host-id to {}, using ephemeral ID", id_path);
    }

    Ok(id)
}

pub fn collect_host_info(host_id: Uuid) -> HostInfo {
    // Env vars override auto-detection (useful when running in Docker)
    let hostname = std::env::var("NETWATCH_HOSTNAME").unwrap_or_else(|_| {
        // Try Linux paths first, then gethostname via uname
        fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| fs::read_to_string("/etc/hostname"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            })
    });

    let in_docker = Path::new("/.dockerenv").exists()
        || fs::read_to_string("/proc/1/cgroup")
            .map(|s| s.contains("docker") || s.contains("containerd"))
            .unwrap_or(false);

    let os = std::env::var("NETWATCH_OS").ok().or_else(|| {
        // Linux: /etc/os-release
        let detected = fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|contents| {
                contents
                    .lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            })
            .or_else(|| {
                // macOS: sw_vers
                let name = std::process::Command::new("sw_vers").arg("-productName").output().ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                let ver = std::process::Command::new("sw_vers").arg("-productVersion").output().ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                let arch = std::process::Command::new("uname").arg("-m").output().ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                match (name, ver, arch) {
                    (Some(n), Some(v), Some(a)) => Some(format!("{} {} ({})", n, v, a)),
                    (Some(n), Some(v), None) => Some(format!("{} {}", n, v)),
                    _ => None,
                }
            });
        match (detected, in_docker) {
            (Some(os), true) => Some(format!("{} (Docker)", os)),
            (Some(os), false) => Some(os),
            (None, true) => Some("Linux (Docker)".to_string()),
            (None, false) => None,
        }
    });

    let kernel = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let uptime_secs = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|v| v as u64)
        .or_else(|| {
            // macOS: sysctl kern.boottime
            let output = std::process::Command::new("sysctl").args(["-n", "kern.boottime"]).output().ok()?;
            let text = String::from_utf8_lossy(&output.stdout);
            // Format: "{ sec = 1711234567, usec = 0 } ..."
            let sec_str = text.split("sec = ").nth(1)?.split(',').next()?;
            let boot_time: u64 = sec_str.trim().parse().ok()?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            Some(now.saturating_sub(boot_time))
        });

    let cpu_info = system::detect_cpu_info();
    let memory_total = system::detect_memory_total();

    HostInfo {
        host_id,
        hostname,
        os,
        kernel,
        uptime_secs,
        cpu_model: cpu_info.model,
        cpu_cores: cpu_info.cores,
        memory_total_bytes: memory_total,
    }
}
