use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

pub fn default_config_path() -> String {
    if cfg!(target_os = "macos") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/.config/netwatch-agent/config.toml", home);
        }
    }
    "/etc/netwatch-agent/config.toml".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub endpoint: String,
    pub api_key: String,
    pub interval_secs: u64,
    pub health_interval_secs: u64,
    pub interfaces: Vec<String>,
    pub gateway: Option<String>,
    pub dns_server: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://netwatch-api-production.up.railway.app/api/v1/ingest".to_string(),
            api_key: String::new(),
            interval_secs: 15,
            health_interval_secs: 30,
            interfaces: Vec::new(),
            gateway: None,
            dns_server: None,
        }
    }
}

impl AgentConfig {
    pub fn config_path() -> String {
        std::env::var("NETWATCH_CONFIG").unwrap_or_else(|_| default_config_path())
    }

    pub fn load() -> Result<Self> {
        // Environment variables take precedence
        let config_path = std::env::var("NETWATCH_CONFIG")
            .unwrap_or_else(|_| default_config_path());

        let mut cfg: AgentConfig = if let Ok(contents) = fs::read_to_string(&config_path) {
            toml::from_str(&contents)
                .with_context(|| format!("failed to parse config at {}", config_path))?
        } else {
            AgentConfig::default()
        };

        // Env var overrides
        if let Ok(v) = std::env::var("NETWATCH_ENDPOINT") {
            cfg.endpoint = v;
        }
        if let Ok(v) = std::env::var("NETWATCH_API_KEY") {
            cfg.api_key = v;
        }
        if let Ok(v) = std::env::var("NETWATCH_INTERVAL") {
            if let Ok(n) = v.parse() {
                cfg.interval_secs = n;
            }
        }

        // Validate
        if cfg.api_key.is_empty() {
            anyhow::bail!("api_key is required (set in config file or NETWATCH_API_KEY env var)");
        }
        if cfg.interval_secs < 10 {
            cfg.interval_secs = 10;
        }
        if cfg.health_interval_secs < 15 {
            cfg.health_interval_secs = 15;
        }

        Ok(cfg)
    }
}
