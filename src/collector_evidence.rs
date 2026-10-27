//! Latest collector attempts, not historical metric quality or completeness.
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub status: &'static str,
    pub reason: &'static str,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CollectorReport {
    pub version: u32,
    pub collectors: BTreeMap<&'static str, Evidence>,
}
impl CollectorReport {
    pub fn record(&mut self, name: &'static str, status: &'static str, reason: &'static str) {
        self.version = 1;
        self.collectors.insert(
            name,
            Evidence {
                status,
                reason,
                observed_at: Utc::now(),
            },
        );
    }
    // Unknown SDK outcomes must never produce a global healthy assertion.
    pub fn collectors_ok(&self) -> Option<bool> {
        if self.collectors.values().any(|e| e.status == "unavailable") {
            Some(false)
        } else if self.collectors.is_empty()
            || self.collectors.values().any(|e| e.status == "unknown")
        {
            None
        } else {
            Some(true)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_is_not_healthy_and_failure_takes_priority() {
        let mut r = CollectorReport::default();
        assert_eq!(r.collectors_ok(), None);
        r.record("cpu", "observed", "sample_returned");
        r.record("connections", "unknown", "sdk_outcome_unavailable");
        assert_eq!(r.collectors_ok(), None);
        r.record("gateway_icmp", "unavailable", "execution_failed");
        assert_eq!(r.collectors_ok(), Some(false));
        let previous = r.collectors["gateway_icmp"].observed_at;
        r.record("cpu", "observed", "sample_returned");
        assert_eq!(r.collectors["gateway_icmp"].observed_at, previous);
    }
}
