use crate::config::AgentConfig;
use netwatch_sdk::types::{HostInfo, IngestRequest, IngestResponse, Snapshot};
use std::collections::VecDeque;

const MAX_BUFFER: usize = 100;

/// Ingest envelope schema version. Matches netwatch's built-in `netwatch daemon`
/// (v0.25.6+) and the value netwatch-cloud Core records in the `hosts` table.
const SCHEMA_VERSION: u32 = 1;

// v0.2.0 compatibility:
// - Server returns 207 Multi-Status for partial success (some snapshots accepted, some rejected)
// - Server returns 402 Payment Required for billing limits (account over host limit or trial expired)
// - Server returns 413 Payload Too Large if batch > 5MB or > 100 snapshots
// - Server validates timestamp is within ±24h of server time
// - Server enforces host limits based on billing plan (reflected in 402)

/// Wire envelope POSTed to netwatch-cloud `/api/v1/ingest`: the `IngestRequest`
/// fields flattened at the top level, plus `schema_version` and `agent_health`,
/// so the standalone agent reports liveness/backlog the same way netwatch's
/// built-in daemon does (Core stores these on the `hosts` row).
#[derive(serde::Serialize)]
struct IngestEnvelope<'a> {
    schema_version: u32,
    #[serde(flatten)]
    request: &'a IngestRequest,
    agent_health: AgentHealth,
}

#[derive(serde::Serialize)]
struct AgentHealth {
    collectors_ok: bool,
    dropped_count: u64,
    queue_depth: u64,
}

pub struct Sender {
    endpoint: String,
    api_key: String,
    host_info: HostInfo,
    buffer: VecDeque<Snapshot>,
    consecutive_failures: u32,
    /// Snapshots discarded because the retry buffer overflowed `MAX_BUFFER`.
    /// Reported in `agent_health.dropped_count`.
    dropped_count: u64,
}

impl Sender {
    pub fn new(cfg: &AgentConfig, host_info: HostInfo) -> Self {
        Self {
            endpoint: cfg.endpoint.clone(),
            api_key: cfg.api_key.clone(),
            host_info,
            buffer: VecDeque::new(),
            consecutive_failures: 0,
            dropped_count: 0,
        }
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn send(&mut self, snapshot: Snapshot) -> Result<(), String> {
        self.buffer.push_back(snapshot);

        // Drain buffer into a single request
        let snapshots: Vec<Snapshot> = self.buffer.drain(..).collect();
        // Backlog being flushed in this batch (1 when healthy, higher once
        // sends have been failing and snapshots have queued up).
        let queue_depth = snapshots.len() as u64;

        let request = IngestRequest {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            host: self.host_info.clone(),
            snapshots: snapshots.clone(),
        };
        let envelope = IngestEnvelope {
            schema_version: SCHEMA_VERSION,
            request: &request,
            agent_health: AgentHealth {
                // The agent collects inline (no panicking collector threads like
                // the daemon), so it's healthy whenever it's alive to send.
                collectors_ok: true,
                dropped_count: self.dropped_count,
                queue_depth,
            },
        };

        let result = ureq::post(&self.endpoint)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(&envelope).map_err(|e| e.to_string())?);

        match result {
            Ok(response) => {
                match response.status() {
                    200 => {
                        // All snapshots accepted
                        self.consecutive_failures = 0;
                        Ok(())
                    }
                    207 => {
                        // Partial success - some snapshots accepted, some rejected
                        // Parse the IngestResponse to see details
                        match response.into_string() {
                            Ok(body) => {
                                match serde_json::from_str::<IngestResponse>(&body) {
                                    Ok(ingest_response) => {
                                        tracing::info!(
                                            "Ingest partial success: {}/{} snapshots accepted",
                                            ingest_response.accepted,
                                            ingest_response
                                                .rejected
                                                .saturating_add(ingest_response.accepted)
                                        );

                                        // Log any rejection details
                                        for result in ingest_response.results {
                                            if result.status != 200 {
                                                tracing::warn!(
                                                    "Snapshot {} rejected with status {}: {}",
                                                    result.index,
                                                    result.status,
                                                    result.message
                                                );
                                            }
                                        }

                                        // Treat partial success as OK (we got some data through)
                                        self.consecutive_failures = 0;
                                        Ok(())
                                    }
                                    Err(e) => {
                                        tracing::warn!("Failed to parse 207 response: {}", e);
                                        // Still count as partial success since we got 207
                                        self.consecutive_failures = 0;
                                        Ok(())
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to read 207 response body: {}", e);
                                // Still count as partial success
                                self.consecutive_failures = 0;
                                Ok(())
                            }
                        }
                    }
                    402 => {
                        // Payment required - account over host limit or trial expired
                        // Do NOT buffer - this is a billing/plan issue that won't resolve by retrying
                        tracing::error!(
                            "Account over host limit or billing issue (402 Payment Required). \
                             Check your subscription plan and billing status."
                        );
                        Err("Account over host limit or billing issue (402)".to_string())
                    }
                    413 => {
                        // Payload too large (> 5MB or > 100 snapshots in batch)
                        // Try to split the batch
                        let batch_size = snapshots.len();
                        if batch_size > 1 {
                            // Put snapshots back and let caller send them individually
                            for s in snapshots.into_iter().rev() {
                                self.buffer.push_front(s);
                            }
                            self.trim_buffer();
                            self.consecutive_failures += 1;
                            tracing::error!(
                                "Snapshot batch too large (413). Batch has {} snapshots. \
                                 Try reducing batch size or individual snapshot size.",
                                batch_size
                            );
                            Err("Snapshot batch too large (413)".to_string())
                        } else {
                            // Single snapshot is too large - don't buffer
                            tracing::error!(
                                "Single snapshot is too large (413). Snapshot size exceeds 5MB. \
                                 This snapshot will be dropped."
                            );
                            Err("Single snapshot too large (413)".to_string())
                        }
                    }
                    500..=599 => {
                        // Server error - retry with buffer
                        for s in snapshots.into_iter().rev() {
                            self.buffer.push_front(s);
                        }
                        self.trim_buffer();
                        self.consecutive_failures += 1;
                        tracing::warn!("Server error {} - will retry", response.status());
                        Err(format!("Server error {}", response.status()))
                    }
                    status => {
                        // Other client errors (4xx) - retry with buffer
                        for s in snapshots.into_iter().rev() {
                            self.buffer.push_front(s);
                        }
                        self.trim_buffer();
                        self.consecutive_failures += 1;
                        tracing::warn!("HTTP {} - will retry", status);
                        Err(format!("HTTP {}", status))
                    }
                }
            }
            Err(e) => {
                // Network error - put snapshots back in buffer
                for s in snapshots.into_iter().rev() {
                    self.buffer.push_front(s);
                }
                self.trim_buffer();
                self.consecutive_failures += 1;
                tracing::warn!("Network error - will retry: {}", e);
                Err(e.to_string())
            }
        }
    }

    fn trim_buffer(&mut self) {
        while self.buffer.len() > MAX_BUFFER {
            self.buffer.pop_front();
            self.dropped_count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netwatch_sdk::types::HostInfo;

    #[test]
    fn envelope_carries_schema_version_and_agent_health() {
        let request = IngestRequest {
            agent_version: "0.4.0".into(),
            host: HostInfo {
                host_id: uuid::Uuid::nil(),
                hostname: "edge-1".into(),
                os: None,
                kernel: None,
                uptime_secs: None,
                cpu_model: None,
                cpu_cores: None,
                memory_total_bytes: None,
            },
            snapshots: vec![],
        };
        let envelope = IngestEnvelope {
            schema_version: SCHEMA_VERSION,
            request: &request,
            agent_health: AgentHealth {
                collectors_ok: true,
                dropped_count: 3,
                queue_depth: 2,
            },
        };
        let v = serde_json::to_value(&envelope).unwrap();

        // schema_version + agent_health present; IngestRequest fields flattened
        // to the top level — exactly the shape Core's IngestEnvelope expects.
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["agent_version"], "0.4.0");
        assert!(v["host"].is_object(), "host flattened to top level");
        assert!(
            v["snapshots"].is_array(),
            "snapshots flattened to top level"
        );
        assert_eq!(v["agent_health"]["collectors_ok"], true);
        assert_eq!(v["agent_health"]["dropped_count"], 3);
        assert_eq!(v["agent_health"]["queue_depth"], 2);
    }
}
