use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

// Releases live on this (public) repo — unauthenticated `curl` can't reach
// assets on the private netwatch-cloud repo, which silently broke self-update.
const REPO: &str = "matthart1983/netwatch-agent";
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

    let download = tempfile::tempdir().context("cannot create private download directory")?;
    let binary = download.path().join(&artifact);
    let tmp_path = binary.to_str().context("invalid download path")?;

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

    let sums = download.path().join("SHA256SUMS");
    let sums_url = format!("https://github.com/{REPO}/releases/latest/download/SHA256SUMS");
    anyhow::ensure!(
        Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&sums)
            .arg(sums_url)
            .status()?
            .success(),
        "failed to download release checksums"
    );
    let entries = fs::read_to_string(&sums)?;
    let entry = entries
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(artifact.as_str()))
        .context("release checksum missing for this architecture")?;
    fs::write(&sums, format!("{entry}\n"))?;
    anyhow::ensure!(
        Command::new("sha256sum")
            .args(["--check", "--status", "SHA256SUMS"])
            .current_dir(download.path())
            .status()?
            .success(),
        "release checksum mismatch; installed binary was not changed"
    );
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    let output = Command::new(&binary)
        .arg("--version")
        .output()
        .context("cannot run downloaded binary")?;
    anyhow::ensure!(
        output.status.success(),
        "downloaded binary failed its version check"
    );
    let new_version = String::from_utf8(output.stdout).context("invalid version response")?;
    let new_version = new_version.trim();
    anyhow::ensure!(
        new_version.starts_with("netwatch-agent "),
        "unexpected downloaded binary"
    );
    println!("  New version: {}", new_version);
    if new_version.split_whitespace().nth(1) == Some(VERSION) {
        println!("Already on the latest version.");
        return Ok(());
    }

    // Find current binary path
    let current_exe = std::env::current_exe().context("cannot determine binary path")?;
    let install_path = current_exe
        .to_str()
        .unwrap_or("/usr/local/bin/netwatch-agent");

    println!("  Installing to: {}", install_path);

    // Never open the running executable for writing (Linux ETXTBSY).
    atomic_replace(&binary, &current_exe).context(
        "cannot atomically install update; check write permissions on the installation directory",
    )?;
    for restorecon in ["/usr/sbin/restorecon", "/sbin/restorecon"] {
        if Path::new(restorecon).exists() {
            anyhow::ensure!(
                Command::new(restorecon)
                    .arg(&current_exe)
                    .status()?
                    .success(),
                "binary installed, but SELinux relabelling failed; service was not restarted"
            );
            break;
        }
    }

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
        anyhow::ensure!(
            Command::new("systemctl")
                .args(["restart", "netwatch-agent"])
                .status()?
                .success(),
            "binary installed, but service restart failed; inspect journalctl -u netwatch-agent"
        );
        anyhow::ensure!(
            Command::new("systemctl")
                .args(["is-active", "--quiet", "netwatch-agent"])
                .status()?
                .success(),
            "binary installed, but service is not active after restart"
        );
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

fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("installation directory missing")?;
    let mut staged =
        tempfile::NamedTempFile::new_in(parent).context("cannot stage update beside executable")?;
    let mut input = fs::File::open(source)?;
    std::io::copy(&mut input, staged.as_file_mut())?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    staged.as_file().sync_all()?;
    staged
        .persist(destination)
        .map_err(|e| e.error)
        .context("atomic rename failed")?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(target_os = "linux")]
    fn replaces_executable_while_it_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("agent");
        fs::copy("/bin/sleep", &exe).unwrap();
        let mut child = Command::new(&exe).arg("30").spawn().unwrap();
        let result = atomic_replace(Path::new("/bin/true"), &exe);
        let still_running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        result.unwrap();
        assert!(still_running);
        assert!(Command::new(&exe).status().unwrap().success());
        assert_eq!(fs::read(&exe).unwrap(), fs::read("/bin/true").unwrap());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[test]
    fn staging_failure_preserves_installed_binary_and_cleans_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("agent");
        fs::write(&exe, b"original").unwrap();
        assert!(atomic_replace(&dir.path().join("missing"), &exe).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
