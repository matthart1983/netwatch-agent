#[derive(Debug)]
pub struct CpuInfo {
    pub model: Option<String>,
    pub cores: Option<u32>,
}

#[derive(Debug)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug)]
pub struct SwapInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    pub fn detect_cpu_info() -> CpuInfo {
        let contents = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        // x86: "model name : Intel Core i7-..."
        let model = contents
            .lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .or_else(|| {
                // ARM: try lscpu for model name and vendor
                let output = std::process::Command::new("lscpu")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string());
                let output = output.as_deref().unwrap_or("");
                let get = |prefix: &str| {
                    output.lines()
                        .find(|l| l.starts_with(prefix))
                        .and_then(|l| l.split(':').nth(1))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty() && s != "-")
                };
                let arch = get("Architecture:");
                let vendor = get("Vendor ID:");
                let model = get("Model name:");
                match (model, vendor, arch) {
                    (Some(m), _, _) => Some(m),
                    (None, Some(v), Some(a)) => Some(format!("{} ({})", v, a)),
                    (None, Some(v), None) => Some(v),
                    (None, None, Some(a)) => Some(a),
                    _ => None,
                }
            });
        let cores = contents
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count() as u32;
        CpuInfo {
            model,
            cores: if cores > 0 { Some(cores) } else { None },
        }
    }

    pub fn detect_memory_total() -> Option<u64> {
        let contents = fs::read_to_string("/proc/meminfo").ok()?;
        for line in contents.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    struct CpuSample {
        idle: u64,
        total: u64,
    }

    fn read_cpu_sample() -> Option<CpuSample> {
        let contents = fs::read_to_string("/proc/stat").ok()?;
        let line = contents.lines().next()?;
        if !line.starts_with("cpu ") {
            return None;
        }
        let vals: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|v| v.parse().ok())
            .collect();
        if vals.len() < 4 {
            return None;
        }
        let idle = vals[3];
        let total: u64 = vals.iter().sum();
        Some(CpuSample { idle, total })
    }

    pub fn measure_cpu_usage() -> Option<f64> {
        let s1 = read_cpu_sample()?;
        thread::sleep(Duration::from_millis(200));
        let s2 = read_cpu_sample()?;

        let total_diff = s2.total.saturating_sub(s1.total);
        let idle_diff = s2.idle.saturating_sub(s1.idle);
        if total_diff == 0 {
            return Some(0.0);
        }

        let usage = (total_diff - idle_diff) as f64 / total_diff as f64 * 100.0;
        Some((usage * 10.0).round() / 10.0)
    }

    fn read_per_core_samples() -> Option<Vec<CpuSample>> {
        let contents = fs::read_to_string("/proc/stat").ok()?;
        let mut cores = Vec::new();
        for line in contents.lines() {
            if line.starts_with("cpu") && !line.starts_with("cpu ") {
                let vals: Vec<u64> = line
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|v| v.parse().ok())
                    .collect();
                if vals.len() < 4 {
                    continue;
                }
                let idle = vals[3];
                let total: u64 = vals.iter().sum();
                cores.push(CpuSample { idle, total });
            }
        }
        if cores.is_empty() { None } else { Some(cores) }
    }

    pub fn measure_cpu_per_core() -> Option<Vec<f64>> {
        let s1 = read_per_core_samples()?;
        thread::sleep(Duration::from_millis(200));
        let s2 = read_per_core_samples()?;

        if s1.len() != s2.len() {
            return None;
        }

        let usages: Vec<f64> = s1.iter().zip(s2.iter()).map(|(a, b)| {
            let total_diff = b.total.saturating_sub(a.total);
            let idle_diff = b.idle.saturating_sub(a.idle);
            if total_diff == 0 {
                0.0
            } else {
                let usage = (total_diff - idle_diff) as f64 / total_diff as f64 * 100.0;
                (usage * 10.0).round() / 10.0
            }
        }).collect();

        Some(usages)
    }

    pub fn read_memory() -> Option<MemoryInfo> {
        let contents = fs::read_to_string("/proc/meminfo").ok()?;
        let mut total_kb = 0u64;
        let mut available_kb = 0u64;
        let mut free_kb = 0u64;
        let mut buffers_kb = 0u64;
        let mut cached_kb = 0u64;

        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "MemTotal:" => total_kb = parts[1].parse().unwrap_or(0),
                "MemAvailable:" => available_kb = parts[1].parse().unwrap_or(0),
                "MemFree:" => free_kb = parts[1].parse().unwrap_or(0),
                "Buffers:" => buffers_kb = parts[1].parse().unwrap_or(0),
                "Cached:" => cached_kb = parts[1].parse().unwrap_or(0),
                _ => {}
            }
        }

        if available_kb == 0 {
            available_kb = free_kb + buffers_kb + cached_kb;
        }

        let used_kb = total_kb.saturating_sub(available_kb);

        Some(MemoryInfo {
            total_bytes: total_kb * 1024,
            available_bytes: available_kb * 1024,
            used_bytes: used_kb * 1024,
        })
    }

    pub fn read_load_avg() -> Option<LoadAvg> {
        let contents = fs::read_to_string("/proc/loadavg").ok()?;
        let parts: Vec<&str> = contents.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }
        Some(LoadAvg {
            one: parts[0].parse().ok()?,
            five: parts[1].parse().ok()?,
            fifteen: parts[2].parse().ok()?,
        })
    }

    pub fn read_swap() -> Option<SwapInfo> {
        let contents = fs::read_to_string("/proc/meminfo").ok()?;
        let mut swap_total_kb = 0u64;
        let mut swap_free_kb = 0u64;

        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "SwapTotal:" => swap_total_kb = parts[1].parse().unwrap_or(0),
                "SwapFree:" => swap_free_kb = parts[1].parse().unwrap_or(0),
                _ => {}
            }
        }

        Some(SwapInfo {
            total_bytes: swap_total_kb * 1024,
            used_bytes: swap_total_kb.saturating_sub(swap_free_kb) * 1024,
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub fn detect_cpu_info() -> CpuInfo {
        let model = Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            });
        let cores = Command::new("sysctl")
            .args(["-n", "hw.ncpu"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok());
        CpuInfo { model, cores }
    }

    pub fn detect_memory_total() -> Option<u64> {
        let output = Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    }

    fn num_cpus() -> Option<u32> {
        Command::new("sysctl")
            .args(["-n", "hw.ncpu"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
    }

    pub fn measure_cpu_usage() -> Option<f64> {
        let output = Command::new("ps")
            .args(["-A", "-o", "%cpu"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let total: f64 = text
            .lines()
            .skip(1)
            .filter_map(|l| l.trim().parse::<f64>().ok())
            .sum();
        let cores = num_cpus().unwrap_or(1) as f64;
        let pct = (total / cores).min(100.0);
        Some((pct * 10.0).round() / 10.0)
    }

    pub fn read_memory() -> Option<MemoryInfo> {
        let total_bytes = detect_memory_total()?;
        let output = Command::new("vm_stat").output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);

        let page_size: u64 = text
            .lines()
            .next()
            .and_then(|l| l.split("page size of ").nth(1))
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(16384);

        let get_pages = |name: &str| -> u64 {
            text.lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|s| s.trim().trim_end_matches('.').parse().ok())
                .unwrap_or(0)
        };

        let free = get_pages("Pages free") * page_size;
        let inactive = get_pages("Pages inactive") * page_size;
        let speculative = get_pages("Pages speculative") * page_size;
        let available = free + inactive + speculative;
        let used = total_bytes.saturating_sub(available);

        Some(MemoryInfo {
            total_bytes,
            available_bytes: available,
            used_bytes: used,
        })
    }

    pub fn read_load_avg() -> Option<LoadAvg> {
        let mut loads: [f64; 3] = [0.0; 3];
        let ret = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
        if ret < 3 {
            return None;
        }
        Some(LoadAvg {
            one: loads[0],
            five: loads[1],
            fifteen: loads[2],
        })
    }

    pub fn read_swap() -> Option<SwapInfo> {
        let output = Command::new("sysctl")
            .args(["-n", "vm.swapusage"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let parse_mb = |prefix: &str| -> Option<u64> {
            text.split(prefix)
                .nth(1)?
                .trim()
                .split('M')
                .next()?
                .trim()
                .parse::<f64>()
                .ok()
                .map(|mb| (mb * 1024.0 * 1024.0) as u64)
        };
        let total = parse_mb("total =")?;
        let used = parse_mb("used =").unwrap_or(0);
        Some(SwapInfo {
            total_bytes: total,
            used_bytes: used,
        })
    }

    pub fn measure_cpu_per_core() -> Option<Vec<f64>> {
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod fallback {
    use super::*;

    pub fn detect_cpu_info() -> CpuInfo {
        CpuInfo { model: None, cores: None }
    }

    pub fn detect_memory_total() -> Option<u64> { None }
    pub fn measure_cpu_usage() -> Option<f64> { None }
    pub fn measure_cpu_per_core() -> Option<Vec<f64>> { None }
    pub fn read_memory() -> Option<MemoryInfo> { None }
    pub fn read_load_avg() -> Option<LoadAvg> { None }
    pub fn read_swap() -> Option<SwapInfo> { None }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use fallback::*;
