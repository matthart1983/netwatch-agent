//! Counter-derived rates and evidence for the exact snapshot being sent.
use netwatch_sdk::{
    collectors::{connections::ConnectionDetail, process_bandwidth::ProcessBandwidth},
    types::{InterfaceMetric, Snapshot},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    time::Instant,
};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Direction {
    pub observed: u32,
    pub missing_baseline: u32,
    pub missing_counter: u32,
    pub counter_reset: u32,
}
impl Direction {
    fn delta(&mut self, current: Option<u64>, previous: Option<u64>, elapsed: f64) -> u64 {
        match (current, previous) {
            (None, _) => {
                self.missing_counter += 1;
                0
            }
            (Some(_), None) => {
                self.missing_baseline += 1;
                0
            }
            (Some(c), Some(p)) if c < p => {
                self.counter_reset += 1;
                0
            }
            (Some(c), Some(p)) if elapsed > 0.0 => {
                self.observed += 1;
                c - p
            }
            _ => {
                self.missing_baseline += 1;
                0
            }
        }
    }
    pub fn complete(&self) -> bool {
        self.observed > 0 && self.missing_baseline + self.missing_counter + self.counter_reset == 0
    }
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Coverage {
    pub rx: Direction,
    pub tx: Direction,
    pub disappeared: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProcessCoverage {
    pub process_name: String,
    pub pid: Option<u32>,
    #[serde(flatten)]
    pub coverage: Coverage,
}
#[derive(Clone, Debug, Serialize)]
pub struct RateReport {
    pub version: u32,
    pub interface_method: &'static str,
    pub process_method: &'static str,
    pub interface_interval_secs: Option<f64>,
    pub process_interval_secs: Option<f64>,
    pub interfaces: BTreeMap<String, Coverage>,
    pub disappeared_interfaces: u32,
    pub processes: Vec<ProcessCoverage>,
    pub disappeared_sockets: u32,
    pub processes_truncated: bool,
}
impl Default for RateReport {
    fn default() -> Self {
        Self {
            version: 1,
            interface_method: "interface_counter_delta",
            process_method: "observed_established_socket_delta",
            interface_interval_secs: None,
            process_interval_secs: None,
            interfaces: BTreeMap::new(),
            disappeared_interfaces: 0,
            processes: vec![],
            disappeared_sockets: 0,
            processes_truncated: false,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct RatedSnapshot {
    #[serde(flatten)]
    pub snapshot: Snapshot,
    pub rate_report: RateReport,
}

#[derive(Default)]
pub struct InterfaceRates {
    previous: HashMap<String, (u64, u64)>,
    at: Option<Instant>,
}
impl InterfaceRates {
    pub fn failed(&mut self) {
        *self = Self::default();
    }
    pub fn collect(
        &mut self,
        filters: &[String],
        report: &mut RateReport,
    ) -> anyhow::Result<Vec<InterfaceMetric>> {
        match netwatch_sdk::platform::collect_interface_stats() {
            Ok(mut stats) => {
                if !filters.is_empty() {
                    stats.retain(|name, _| filters.contains(name));
                }
                let metrics = stats
                    .into_values()
                    .map(|s| InterfaceMetric {
                        name: s.name,
                        is_up: s.is_up,
                        rx_bytes: s.rx_bytes,
                        tx_bytes: s.tx_bytes,
                        rx_bytes_delta: 0,
                        tx_bytes_delta: 0,
                        rx_packets: s.rx_packets,
                        tx_packets: s.tx_packets,
                        rx_errors: s.rx_errors,
                        tx_errors: s.tx_errors,
                        rx_drops: s.rx_drops,
                        tx_drops: s.tx_drops,
                        rx_rate: None,
                        tx_rate: None,
                        rx_history: None,
                        tx_history: None,
                    })
                    .collect();
                Ok(self.qualify(metrics, Instant::now(), report))
            }
            Err(e) => {
                self.failed();
                Err(e)
            }
        }
    }
    fn qualify(
        &mut self,
        mut metrics: Vec<InterfaceMetric>,
        now: Instant,
        report: &mut RateReport,
    ) -> Vec<InterfaceMetric> {
        let elapsed = self
            .at
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        let elapsed = if elapsed > 86400.0 {
            self.previous.clear();
            0.0
        } else {
            elapsed
        };
        report.interface_interval_secs = (elapsed > 0.0).then_some(elapsed);
        report.disappeared_interfaces = self
            .previous
            .keys()
            .filter(|n| !metrics.iter().any(|m| &m.name == *n))
            .count() as u32;
        let mut next = HashMap::new();
        for m in &mut metrics {
            let prev = self.previous.get(&m.name);
            let mut c = Coverage::default();
            let rx = c.rx.delta(Some(m.rx_bytes), prev.map(|p| p.0), elapsed);
            let tx = c.tx.delta(Some(m.tx_bytes), prev.map(|p| p.1), elapsed);
            m.rx_rate = c.rx.complete().then(|| rx as f64 / elapsed);
            m.tx_rate = c.tx.complete().then(|| tx as f64 / elapsed);
            m.rx_bytes_delta = rx;
            m.tx_bytes_delta = tx;
            // SDK histories cannot represent gaps; omit rather than retain invented zeros.
            m.rx_history = None;
            m.tx_history = None;
            next.insert(m.name.clone(), (m.rx_bytes, m.tx_bytes));
            report.interfaces.insert(m.name.clone(), c);
        }
        self.previous = next;
        self.at = Some(now);
        metrics.sort_by(|a, b| a.name.cmp(&b.name));
        metrics
    }
}

type ProcessKey = (String, Option<u32>);
type SocketKey = (String, String, String, ProcessKey);
#[derive(Default)]
pub struct ProcessRates {
    previous: HashMap<SocketKey, (Option<u64>, Option<u64>)>,
    at: Option<Instant>,
}
impl ProcessRates {
    pub fn sample(
        &mut self,
        connections: &[ConnectionDetail],
        max: usize,
        report: &mut RateReport,
    ) -> Vec<ProcessBandwidth> {
        self.sample_at(connections, max, report, Instant::now())
    }
    fn sample_at(
        &mut self,
        connections: &[ConnectionDetail],
        max: usize,
        report: &mut RateReport,
        now: Instant,
    ) -> Vec<ProcessBandwidth> {
        let elapsed = self
            .at
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        let elapsed = if elapsed > 86400.0 {
            self.previous.clear();
            0.0
        } else {
            elapsed
        };
        report.process_interval_secs = (elapsed > 0.0).then_some(elapsed);
        let mut next = HashMap::new();
        let mut rows: HashMap<ProcessKey, (ProcessBandwidth, Coverage)> = HashMap::new();
        for conn in connections.iter().filter(|c| c.state == "ESTABLISHED") {
            let name = conn
                .process_name
                .clone()
                .unwrap_or_else(|| format!("pid:{}", conn.pid.unwrap_or(0)));
            let process = (name.clone(), conn.pid);
            let key = (
                conn.protocol.clone(),
                conn.local_addr.clone(),
                conn.remote_addr.clone(),
                process.clone(),
            );
            if next.contains_key(&key) {
                continue;
            } // no double counting duplicated socket rows
            let previous = self.previous.get(&key);
            let (row, c) = rows.entry(process).or_insert_with(|| {
                (
                    ProcessBandwidth::network_only(name, conn.pid, 0, 0, 0.0, 0.0, 0),
                    Coverage::default(),
                )
            });
            row.connection_count += 1;
            row.rx_bytes = row.rx_bytes.saturating_add(c.rx.delta(
                conn.rx_bytes,
                previous.and_then(|p| p.0),
                elapsed,
            ));
            row.tx_bytes = row.tx_bytes.saturating_add(c.tx.delta(
                conn.tx_bytes,
                previous.and_then(|p| p.1),
                elapsed,
            ));
            next.insert(key, (conn.rx_bytes, conn.tx_bytes));
        }
        for key in self.previous.keys().filter(|k| !next.contains_key(*k)) {
            report.disappeared_sockets += 1;
            if let Some((_, c)) = rows.get_mut(&key.3) {
                c.disappeared += 1;
            }
        }
        self.previous = next;
        self.at = Some(now);
        let mut ranked: Vec<_> = rows.into_values().collect();
        for (p, _) in &mut ranked {
            if elapsed > 0.0 {
                p.rx_rate = p.rx_bytes as f64 / elapsed;
                p.tx_rate = p.tx_bytes as f64 / elapsed;
            }
        }
        ranked.sort_by(|(a, _), (b, _)| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.process_name.cmp(&b.process_name))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        report.processes_truncated = ranked.len() > max;
        ranked.truncate(max);
        report.processes = ranked
            .iter()
            .map(|(p, c)| ProcessCoverage {
                process_name: p.process_name.clone(),
                pid: p.pid,
                coverage: c.clone(),
            })
            .collect();
        ranked.into_iter().map(|(p, _)| p).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn iface(name: &str, rx: u64, tx: u64) -> InterfaceMetric {
        serde_json::from_value(serde_json::json!({"name":name,"is_up":true,"rx_bytes":rx,"tx_bytes":tx,"rx_bytes_delta":0,"tx_bytes_delta":0,"rx_packets":0,"tx_packets":0,"rx_errors":0,"tx_errors":0,"rx_drops":0,"tx_drops":0})).unwrap()
    }
    fn socket(port: u16, pid: u32, rx: Option<u64>, tx: Option<u64>) -> ConnectionDetail {
        ConnectionDetail {
            protocol: "TCP".into(),
            local_addr: format!("[::1]:{port}"),
            remote_addr: "[::1]:443".into(),
            state: "ESTABLISHED".into(),
            pid: Some(pid),
            process_name: Some(format!("p{pid}")),
            kernel_rtt_us: None,
            rx_bytes: rx,
            tx_bytes: tx,
        }
    }
    #[test]
    fn interface_baseline_zero_reset_disappearance_and_failure() {
        let mut t = InterfaceRates::default();
        let now = Instant::now();
        let mut r = RateReport::default();
        let m = t.qualify(vec![iface("eth0", 100, 200)], now, &mut r);
        assert_eq!(m[0].rx_rate, None);
        assert_eq!(r.interfaces["eth0"].rx.missing_baseline, 1);
        let mut r = RateReport::default();
        let m = t.qualify(
            vec![iface("eth0", 100, 400)],
            now + Duration::from_secs(2),
            &mut r,
        );
        assert_eq!(m[0].rx_rate, Some(0.0));
        assert_eq!(m[0].tx_rate, Some(100.0));
        let mut r = RateReport::default();
        let m = t.qualify(
            vec![iface("eth0", 1, 500), iface("eth1", 200, 200)],
            now + Duration::from_secs(4),
            &mut r,
        );
        assert_eq!(m[0].rx_rate, None);
        assert_eq!(m[0].tx_rate, Some(50.0));
        assert_eq!(r.interfaces["eth0"].rx.counter_reset, 1);
        assert_eq!(m[1].rx_rate, None);
        let mut r = RateReport::default();
        t.qualify(
            vec![iface("eth1", 200, 200)],
            now + Duration::from_secs(6),
            &mut r,
        );
        assert_eq!(r.disappeared_interfaces, 1);
        let mut r = RateReport::default();
        let m = t.qualify(
            vec![iface("eth0", 900, 900)],
            now + Duration::from_secs(8),
            &mut r,
        );
        assert_eq!(m[0].rx_rate, None); // reappearance does not bridge the absence
        t.failed();
        let mut r = RateReport::default();
        assert_eq!(
            t.qualify(
                vec![iface("eth0", 950, 950)],
                now + Duration::from_secs(10),
                &mut r
            )[0]
            .rx_rate,
            None
        );
    }
    #[test]
    fn socket_coverage_is_directional_and_tracks_churn() {
        let mut t = ProcessRates::default();
        let now = Instant::now();
        let mut r = RateReport::default();
        t.sample_at(
            &[
                socket(1, 1, Some(100), Some(200)),
                socket(2, 1, Some(0), None),
            ],
            25,
            &mut r,
            now,
        );
        assert_eq!(r.processes[0].coverage.rx.missing_baseline, 2);
        assert_eq!(r.processes[0].coverage.tx.missing_counter, 1);
        let mut r = RateReport::default();
        let p = t.sample_at(
            &[
                socket(1, 1, Some(100), Some(400)),
                socket(2, 1, Some(10), None),
            ],
            25,
            &mut r,
            now + Duration::from_secs(2),
        );
        assert_eq!(p[0].rx_rate, 5.0);
        assert!(r.processes[0].coverage.rx.complete());
        assert!(!r.processes[0].coverage.tx.complete());
        let mut r = RateReport::default();
        t.sample_at(
            &[socket(1, 1, Some(1), Some(400))],
            25,
            &mut r,
            now + Duration::from_secs(4),
        );
        assert_eq!(r.processes[0].coverage.rx.counter_reset, 1);
        assert_eq!(r.processes[0].coverage.disappeared, 1);
        let mut r = RateReport::default();
        t.sample_at(
            &[socket(1, 2, Some(999), Some(999))],
            25,
            &mut r,
            now + Duration::from_secs(6),
        );
        assert_eq!(r.processes[0].coverage.rx.missing_baseline, 1); // changed owner cannot borrow baseline
        assert_eq!(r.disappeared_sockets, 1);
    }
    #[test]
    fn unequal_traffic_zero_and_rank_limit_are_explicit() {
        let now = Instant::now();
        let mut t = ProcessRates::default();
        let mut r = RateReport::default();
        t.sample_at(
            &[
                socket(1, 1, Some(0), Some(0)),
                socket(2, 2, Some(0), Some(0)),
            ],
            1,
            &mut r,
            now,
        );
        assert!(r.processes_truncated);
        let mut r = RateReport::default();
        let p = t.sample_at(
            &[
                socket(1, 1, Some(1000), Some(0)),
                socket(2, 2, Some(10), Some(0)),
            ],
            2,
            &mut r,
            now + Duration::from_secs(10),
        );
        assert_eq!(p[0].rx_rate, 100.0);
        assert_eq!(p[1].rx_rate, 1.0);
        assert_eq!(p[0].tx_rate, 0.0);
        assert!(r.processes.iter().all(|c| c.coverage.tx.complete()));
        let mut r = RateReport::default();
        assert!(t
            .sample_at(&[], 2, &mut r, now + Duration::from_secs(20))
            .is_empty());
        assert_eq!(r.disappeared_sockets, 2);
    }
    #[test]
    fn buffered_snapshots_keep_their_own_evidence_and_legacy_wire_decodes() {
        let snapshot: Snapshot = serde_json::from_value(
            serde_json::json!({"timestamp":"2026-10-27T10:00:00Z","interfaces":[]}),
        )
        .unwrap();
        let mut report = RateReport::default();
        let first = RatedSnapshot {
            snapshot: snapshot.clone(),
            rate_report: report.clone(),
        };
        report.disappeared_sockets = 3;
        let second = RatedSnapshot {
            snapshot,
            rate_report: report,
        };
        let wire = serde_json::to_value(vec![first, second]).unwrap();
        assert_eq!(wire[0]["rate_report"]["disappeared_sockets"], 0);
        assert_eq!(wire[1]["rate_report"]["disappeared_sockets"], 3);
        serde_json::from_value::<Vec<Snapshot>>(wire).unwrap();
    }
}
