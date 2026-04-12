use crate::config::AgentConfig;
use netwatch_core::types::{HostInfo, IngestRequest, IngestResponse, Snapshot};
use std::collections::VecDeque;

const MAX_BUFFER: usize = 100;

// v0.2.0 compatibility:
// - Server returns 207 Multi-Status for partial success (some snapshots accepted, some rejected)
// - Server returns 402 Payment Required for billing limits (account over host limit or trial expired)
// - Server returns 413 Payload Too Large if batch > 5MB or > 100 snapshots
// - Server validates timestamp is within ±24h of server time
// - Server enforces host limits based on billing plan (reflected in 402)

pub struct Sender {
    endpoint: String,
    api_key: String,
    host_info: HostInfo,
    buffer: VecDeque<Snapshot>,
    consecutive_failures: u32,
}

impl Sender {
    pub fn new(cfg: &AgentConfig, host_info: HostInfo) -> Self {
        Self {
            endpoint: cfg.endpoint.clone(),
            api_key: cfg.api_key.clone(),
            host_info,
            buffer: VecDeque::new(),
            consecutive_failures: 0,
        }
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn send(&mut self, snapshot: Snapshot) -> Result<(), String> {
        self.buffer.push_back(snapshot);

        // Drain buffer into a single request
        let snapshots: Vec<Snapshot> = self.buffer.drain(..).collect();

        let request = IngestRequest {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            host: self.host_info.clone(),
            snapshots: snapshots.clone(),
        };

        let result = ureq::post(&self.endpoint)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(&request).map_err(|e| e.to_string())?);

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
                                            ingest_response.rejected.saturating_add(ingest_response.accepted)
                                        );

                                        // Log any rejection details
                                        for result in ingest_response.results {
                                            if result.status != 200 {
                                                tracing::warn!(
                                                    "Snapshot {} rejected with status {}: {}",
                                                    result.index, result.status, result.message
                                                );
                                            }
                                        }

                                        // Treat partial success as OK (we got some data through)
                                        self.consecutive_failures = 0;
                                        Ok(())
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to parse 207 response: {}",
                                            e
                                        );
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
                        tracing::warn!(
                            "Server error {} - will retry",
                            response.status()
                        );
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
        }
    }
}
