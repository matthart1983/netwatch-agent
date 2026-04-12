use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const REPO: &str = "matthart1983/netwatch-cloud";
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn self_update() -> Result<()> {
    if cfg!(target_os = "macos") {
        anyhow::bail!(
            "self-update is only supported for the Linux service install. For macOS dev use, rebuild locally with `cargo build --package netwatch-agent`."
        );
    }

    let arch = detect_arch()?;
    let artifact = format!("netwatch-agent-linux-{}", arch);

    println!("NetWatch Agent Updater");
    println!("  Current version: {}", VERSION);
    println!("  Architecture:    {}", arch);
    println!();

    // Download latest binary
    let url = format!(
        "https://github.com/{}/releases/latest/download/{}",
        REPO, artifact
    );
    println!("Downloading from {}...", url);

    let tmp_path = "/tmp/netwatch-agent-update";

    let status = Command::new("curl")
        .args(["-fsSL", "-o", tmp_path, &url])
        .status()
        .context("failed to run curl")?;

    if !status.success() {
        anyhow::bail!(
            "Download failed. Make sure a release exists at:\n  \
             https://github.com/{}/releases/latest\n\n  \
             Create one with: git tag v0.x.x && git push origin v0.x.x",
            REPO
        );
    }

    // Make executable
    fs::set_permissions(tmp_path, fs::Permissions::from_mode(0o755))?;

    // Check new version
    let new_version = Command::new(tmp_path)
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!("  New version: {}", new_version);

    if new_version.contains(VERSION) {
        println!("\n✅ Already on the latest version.");
        fs::remove_file(tmp_path).ok();
        return Ok(());
    }

    // Find current binary path
    let current_exe = std::env::current_exe().context("cannot determine binary path")?;
    let install_path = current_exe.to_str().unwrap_or("/usr/local/bin/netwatch-agent");

    println!("  Installing to: {}", install_path);

    // Replace binary
    fs::copy(tmp_path, install_path).context(
        "failed to replace binary — run with sudo:\n  sudo netwatch-agent update",
    )?;
    fs::remove_file(tmp_path).ok();

    println!();
    println!("✅ Updated! ({} → {})", VERSION, new_version);

    // Restart systemd service if running
    let is_active = Command::new("systemctl")
        .args(["is-active", "netwatch-agent"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);

    if is_active {
        println!("  Restarting service...");
        let _ = Command::new("systemctl")
            .args(["restart", "netwatch-agent"])
            .status();
        println!("  ✅ Service restarted");
    } else {
        println!("  Start with: sudo systemctl start netwatch-agent");
    }

    Ok(())
}

fn detect_arch() -> Result<String> {
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .context("failed to detect architecture")?;
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match arch.as_str() {
        "x86_64" => Ok("x86_64".to_string()),
        "aarch64" | "arm64" => Ok("aarch64".to_string()),
        other => anyhow::bail!("unsupported architecture: {}", other),
    }
}
