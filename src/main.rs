use anyhow::Result;
use std::time::Duration;
use tracing::{info, warn};

mod collector;
mod config;
mod host;
mod sender;
mod update;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = env!("GIT_HASH");

// v0.2.0 compatibility:
// Exponential backoff configuration for retrying failed sends
const BASE_RETRY_DELAY: u64 = 5;  // 5 seconds
const MAX_RETRY_DELAY: u64 = 300; // 5 minutes

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str());

    match cmd {
        Some("--version" | "-V" | "version") => {
            println!("netwatch-agent {} ({})", VERSION, GIT_HASH);
            return Ok(());
        }
        Some("--help" | "-h" | "help") => {
            print_help();
            return Ok(());
        }
        Some("update") => {
            return update::self_update();
        }
        Some("status") => {
            return print_status();
        }
        Some("setup") => {
            return run_setup();
        }
        Some("launchd-install") => {
            return install_launchd_agent();
        }
        Some("launchd-remove") => {
            return remove_launchd_agent();
        }
        Some("config") => {
            return print_config();
        }
        Some(unknown) if unknown.starts_with('-') || !unknown.is_empty() => {
            // Unknown commands starting with letters are errors
            if !unknown.starts_with('-') {
                eprintln!("Unknown command: {}", unknown);
                eprintln!("Run 'netwatch-agent help' for usage");
                std::process::exit(1);
            }
        }
        _ => {}
    }

    // Default: run the agent daemon
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::AgentConfig::load()?;
    let host_id = host::get_or_create_host_id()?;
    let host_info = host::collect_host_info(host_id);

    info!("netwatch-agent started, version {} ({}), host_id={}", VERSION, GIT_HASH, host_id);
    info!("endpoint: {}", cfg.endpoint);
    info!("interval: {}s, health interval: {}s", cfg.interval_secs, cfg.health_interval_secs);

    let mut collector = collector::MetricsCollector::new(&cfg);
    let mut sender = sender::Sender::new(&cfg, host_info);

    let interval = Duration::from_secs(cfg.interval_secs);
    let health_interval = Duration::from_secs(cfg.health_interval_secs);
    let mut last_health = tokio::time::Instant::now() - health_interval;

    loop {
        let snapshot = collector.collect(last_health.elapsed() >= health_interval);

        if last_health.elapsed() >= health_interval {
            last_health = tokio::time::Instant::now();
        }

        // v0.2.0: Retry with exponential backoff on transient failures
        let mut retry_delay = BASE_RETRY_DELAY;
        let mut send_succeeded = false;
        
        while !send_succeeded {
            match sender.send(snapshot.clone()) {
                Ok(()) => {
                    info!("snapshot sent");
                    send_succeeded = true;
                }
                Err(e) if e.contains("402") || e.contains("Single") || e.contains("billing") => {
                    // 402: Account over limit / billing issue - don't retry
                    // 413 Single: Single snapshot too large - don't retry
                    warn!("Unrecoverable error: {}", e);
                    send_succeeded = true; // Exit retry loop
                }
                Err(e) => {
                    // Transient errors: network, 5xx, or 413 batch - retry with backoff
                    warn!("Send failed, retrying in {}s: {} (buffered: {} queued)", 
                          retry_delay, e, sender.buffer_len());
                    tokio::time::sleep(Duration::from_secs(retry_delay)).await;
                    retry_delay = (retry_delay * 2).min(MAX_RETRY_DELAY);
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

fn run_setup() -> Result<()> {
    use std::io::{self, BufRead, Write};

    let config_path = config::AgentConfig::config_path();
    let exists = std::path::Path::new(&config_path).exists();

    println!("netwatch-agent {} — setup", VERSION);
    println!();

    if exists {
        println!("Config already exists at {}", config_path);
        print!("Overwrite? [y/N] ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("Setup cancelled.");
            return Ok(());
        }
    }

    // API key
    print!("API Key: ");
    io::stdout().flush()?;
    let mut api_key = String::new();
    io::stdin().lock().read_line(&mut api_key)?;
    let api_key = api_key.trim().to_string();
    if api_key.is_empty() {
        anyhow::bail!("API key is required");
    }

    // Endpoint
    let default_endpoint = "https://netwatch-api-production.up.railway.app/api/v1/ingest";
    print!("Endpoint [{}]: ", default_endpoint);
    io::stdout().flush()?;
    let mut endpoint = String::new();
    io::stdin().lock().read_line(&mut endpoint)?;
    let endpoint = endpoint.trim();
    let endpoint = if endpoint.is_empty() { default_endpoint } else { endpoint };

    // Write config
    if let Some(parent) = std::path::Path::new(&config_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let config_content = format!(
        r#"# NetWatch Agent configuration
endpoint = "{}"
api_key = "{}"
interval_secs = 15
health_interval_secs = 30
"#,
        endpoint, api_key
    );

    std::fs::write(&config_path, &config_content)?;

    // Restrict permissions on the config file (contains API key)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    }

    println!();
    println!("✅ Config written to {}", config_path);
    println!();
    println!("Start the agent with:");
    println!("  netwatch-agent");
    println!();
    if cfg!(target_os = "macos") {
        println!("Optional macOS dev service:");
        println!("  netwatch-agent launchd-install");
    } else {
        println!("Or install as a service (Linux):");
        println!("  sudo cp $(which netwatch-agent || echo ./target/release/netwatch-agent) /usr/local/bin/");
        println!("  sudo systemctl enable --now netwatch-agent");
    }

    Ok(())
}

fn print_help() {
    println!("netwatch-agent {} — network metrics collector", VERSION);
    println!();
    println!("USAGE:");
    println!("  netwatch-agent             Run the agent daemon");
    println!("  netwatch-agent setup       Interactive first-run setup (writes config, starts agent)");
    println!("  netwatch-agent update      Download and install the latest version");
    println!("  netwatch-agent status      Show agent status");
    println!("  netwatch-agent config      Show current configuration");
    println!("  netwatch-agent launchd-install   Install a per-user macOS dev service");
    println!("  netwatch-agent launchd-remove    Remove the per-user macOS dev service");
    println!("  netwatch-agent version     Print version");
    println!("  netwatch-agent help        Show this help");
    println!();
    println!("CONFIGURATION:");
    println!("  Config file: {}", config::AgentConfig::config_path());
    println!("  Env vars:    NETWATCH_API_KEY, NETWATCH_ENDPOINT, NETWATCH_INTERVAL");
}

fn print_status() -> Result<()> {
    println!("netwatch-agent {}", VERSION);

    #[cfg(target_os = "macos")]
    {
        let label = launchd_label();
        let output = std::process::Command::new("launchctl")
            .args(["list", &label])
            .output();

        match output {
            Ok(o) if o.status.success() => println!("Status: ✅ launchd service loaded ({})", label),
            Ok(_) => println!("Status: launchd service not loaded ({})", label),
            Err(_) => println!("Status: launchctl not available (running outside launchd?)"),
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
    // Check if systemd service is running
        let output = std::process::Command::new("systemctl")
            .args(["is-active", "netwatch-agent"])
            .output();

        match output {
            Ok(o) => {
                let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if status == "active" {
                    println!("Status: ✅ running");
                } else {
                    println!("Status: ❌ {}", status);
                }
            }
            Err(_) => {
                println!("Status: systemctl not available (running outside systemd?)");
            }
        }
    }

    // Show host ID
    let host_id_path = if cfg!(target_os = "macos") {
        std::env::var("HOME").map(|h| format!("{}/.config/netwatch-agent/host-id", h)).unwrap_or_else(|_| "/var/lib/netwatch-agent/host-id".to_string())
    } else {
        "/var/lib/netwatch-agent/host-id".to_string()
    };
    if let Ok(id) = std::fs::read_to_string(&host_id_path) {
        println!("Host ID: {}", id.trim());
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn launchd_label() -> String {
    "com.netwatch.agent.dev".to_string()
}

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME")?;
    Ok(std::path::Path::new(&home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", launchd_label())))
}

#[cfg(target_os = "macos")]
fn install_launchd_agent() -> Result<()> {
    use std::fs;

    let exe = std::env::current_exe()?;
    let plist_path = launchd_plist_path()?;
    let log_dir = plist_path.parent().and_then(|p| p.parent()).map(|p| p.join("Logs")).expect("launch agents parent");
    fs::create_dir_all(plist_path.parent().expect("plist parent"))?;
    fs::create_dir_all(&log_dir)?;

    let stdout_path = log_dir.join("netwatch-agent.out.log");
    let stderr_path = log_dir.join("netwatch-agent.err.log");
    let config_path = config::AgentConfig::config_path();
    let label = launchd_label();

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NETWATCH_CONFIG</key>
    <string>{config_path}</string>
  </dict>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{stdout_path}</string>
  <key>StandardErrorPath</key>
  <string>{stderr_path}</string>
</dict>
</plist>
"#,
        label = label,
        exe = exe.display(),
        config_path = config_path,
        stdout_path = stdout_path.display(),
        stderr_path = stderr_path.display(),
    );

    fs::write(&plist_path, plist)?;

    let _ = std::process::Command::new("launchctl")
        .args(["unload", plist_path.to_str().unwrap()])
        .status();

    let status = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap()])
        .status()?;

    if !status.success() {
        anyhow::bail!("failed to load launchd agent from {}", plist_path.display());
    }

    println!("✅ launchd agent installed for macOS dev use");
    println!("  Label: {}", label);
    println!("  Plist: {}", plist_path.display());
    println!("  Logs:  {}", stdout_path.display());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn install_launchd_agent() -> Result<()> {
    anyhow::bail!("launchd-install is only available on macOS")
}

#[cfg(target_os = "macos")]
fn remove_launchd_agent() -> Result<()> {
    let plist_path = launchd_plist_path()?;
    let _ = std::process::Command::new("launchctl")
        .args(["unload", plist_path.to_str().unwrap()])
        .status();
    if plist_path.exists() {
        std::fs::remove_file(&plist_path)?;
    }
    println!("✅ launchd agent removed ({})", plist_path.display());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn remove_launchd_agent() -> Result<()> {
    anyhow::bail!("launchd-remove is only available on macOS")
}

fn print_config() -> Result<()> {
    let cfg = config::AgentConfig::load()?;
    println!("Endpoint:  {}", cfg.endpoint);
    println!("API Key:   {}...", &cfg.api_key[..std::cmp::min(14, cfg.api_key.len())]);
    println!("Interval:  {}s", cfg.interval_secs);
    println!("Health:    {}s", cfg.health_interval_secs);
    if !cfg.interfaces.is_empty() {
        println!("Interfaces: {}", cfg.interfaces.join(", "));
    }
    if let Some(ref gw) = cfg.gateway {
        println!("Gateway:   {}", gw);
    }
    if let Some(ref dns) = cfg.dns_server {
        println!("DNS:       {}", dns);
    }
    Ok(())
}
