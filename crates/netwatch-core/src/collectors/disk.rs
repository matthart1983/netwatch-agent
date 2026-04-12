use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsage {
    pub mount_point: String,
    pub device: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIo {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::fs;

    const VIRTUAL_FS: &[&str] = &["proc", "sysfs", "devpts", "tmpfs", "devtmpfs", "cgroup", "cgroup2",
        "pstore", "securityfs", "debugfs", "configfs", "fusectl", "mqueue",
        "hugetlbfs", "autofs", "rpc_pipefs", "nfsd", "binfmt_misc", "tracefs",
        "squashfs", "overlay", "ramfs", "efivarfs"];

    pub fn collect_disk_usage() -> Vec<DiskUsage> {
        let Ok(contents) = fs::read_to_string("/proc/mounts") else {
            return Vec::new();
        };

        let mut results = Vec::new();

        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let device = parts[0];
            let mount_point = parts[1];
            let fs_type = parts[2];

            // Skip virtual filesystems; keep anything backed by a real device
            if !device.starts_with("/dev/") || VIRTUAL_FS.contains(&fs_type) {
                continue;
            }

            let Ok(c_path) = CString::new(mount_point) else {
                continue;
            };

            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
                    continue;
                }

                let block_size = stat.f_frsize as u64;
                let total_bytes = stat.f_blocks as u64 * block_size;
                let available_bytes = stat.f_bavail as u64 * block_size;
                let free_bytes = stat.f_bfree as u64 * block_size;
                let used_bytes = total_bytes.saturating_sub(free_bytes);

                let usage_pct = if total_bytes > 0 {
                    let pct = used_bytes as f64 / total_bytes as f64 * 100.0;
                    (pct * 10.0).round() / 10.0
                } else {
                    0.0
                };

                results.push(DiskUsage {
                    mount_point: mount_point.to_string(),
                    device: device.to_string(),
                    total_bytes,
                    used_bytes,
                    available_bytes,
                    usage_pct,
                });
            }
        }

        results
    }

    pub fn collect_disk_io() -> Option<DiskIo> {
        let contents = fs::read_to_string("/proc/diskstats").ok()?;
        let mut total_read_bytes = 0u64;
        let mut total_write_bytes = 0u64;
        let mut found = false;

        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue;
            }
            let name = parts[2];
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
                continue;
            }

            let read_sectors: u64 = parts[5].parse().unwrap_or(0);
            let write_sectors: u64 = parts[9].parse().unwrap_or(0);

            total_read_bytes += read_sectors * 512;
            total_write_bytes += write_sectors * 512;
            found = true;
        }

        if found {
            Some(DiskIo {
                read_bytes: total_read_bytes,
                write_bytes: total_write_bytes,
            })
        } else {
            None
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ffi::CString;

    pub fn collect_disk_usage() -> Vec<DiskUsage> {
        let Ok(output) = std::process::Command::new("mount").output() else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut results = Vec::new();

        for line in text.lines() {
            // Format: /dev/disk3s1s1 on / (apfs, ...)
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 { continue; }
            let device = parts[0];
            let mount_point = parts[2];

            // Only real disk devices
            if !device.starts_with("/dev/") { continue; }

            let Ok(c_path) = CString::new(mount_point) else { continue };

            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
                    continue;
                }

                let block_size = stat.f_frsize as u64;
                let total_bytes = stat.f_blocks as u64 * block_size;
                if total_bytes == 0 { continue; }
                let available_bytes = stat.f_bavail as u64 * block_size;
                let free_bytes = stat.f_bfree as u64 * block_size;
                let used_bytes = total_bytes.saturating_sub(free_bytes);
                let usage_pct = (used_bytes as f64 / total_bytes as f64 * 100.0 * 10.0).round() / 10.0;

                results.push(DiskUsage {
                    mount_point: mount_point.to_string(),
                    device: device.to_string(),
                    total_bytes,
                    used_bytes,
                    available_bytes,
                    usage_pct,
                });
            }
        }

        results
    }

    pub fn collect_disk_io() -> Option<DiskIo> {
        // macOS doesn't have /proc/diskstats; iostat is available but parsing is complex
        // Return None for now — disk I/O on macOS would need IOKit framework
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod fallback {
    use super::*;

    pub fn collect_disk_usage() -> Vec<DiskUsage> {
        Vec::new()
    }

    pub fn collect_disk_io() -> Option<DiskIo> {
        None
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use fallback::*;
