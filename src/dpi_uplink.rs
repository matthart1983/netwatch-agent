//! Outbound DPI metadata uplink.
//!
//! Agents are outbound-only, so the agent DIALS the cloud relay over WSS and
//! holds a control channel authenticated with its existing api key (the same
//! credential used for `/ingest`). The cloud — driven by an authorized,
//! fully-gated browser session — sends `start`/`stop`/`set_filter`; the agent
//! runs a libpcap capture, classifies each packet to METADATA ONLY via
//! `netwatch-dpi`, and streams `packets`/`stats` frames back up.
//!
//! Security posture (matches the cloud relay + the DPI security review):
//!   * LOCAL OPT-IN (#19): this task only runs when `dpi_remote_enabled = true`
//!     in the agent's own config (gated in `main`). The cloud cannot start a
//!     capture on a host that hasn't locally opted in — even a compromised
//!     control plane can't. This local flag is the load-bearing control.
//!   * METADATA ONLY: the classifier emits an addressing/identification
//!     allowlist (5-tuple, proto/app, TLS SNI, HTTP method + Host, DNS qname).
//!     It NEVER emits URL path/query, headers, cookies, bodies, or decrypted
//!     plaintext. A short snaplen means full payloads aren't even copied off
//!     the wire.
//!   * REDACTION BACKSTOP: every free-text field is passed through the
//!     `netwatch-dpi` Redactor before it leaves the host — defense in depth on
//!     top of the allowlist.
//!   * SESSION CAPS (#21): one capture at a time, a hard max duration, and
//!     snaplen/batch ceilings — enforced here regardless of what the cloud asks.
//!
//! FOLLOW-UP (security review #19): cloud→agent commands are authenticated by
//! TLS + the api key on the uplink and gated by the local opt-in, but are not
//! yet cryptographically signed per-command. Tracked for a later pass.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use netwatch_dpi::{classify_meta, AppProtocol, ClassifiedMeta, Redactor};
use pcap::{Capture, Linktype};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::capture;

const SNAPLEN_DPI: i32 = 2048; // enough for L7 id headers (SNI/Host); not full bodies
const READ_TIMEOUT_MS: i32 = 250;
const MAX_SESSION_SECS: u64 = 1800; // hard cap regardless of the cloud (#21)
const BATCH_INTERVAL: Duration = Duration::from_millis(700);
const MAX_BATCH: usize = 256;
const STATS_INTERVAL: Duration = Duration::from_secs(1);
const PING_INTERVAL: Duration = Duration::from_secs(25);
const BASE_RETRY: u64 = 5;
const MAX_RETRY: u64 = 300;

// ── wire types (mirror the cloud relay's vocabulary) ─────────────────────────

#[derive(Serialize, Clone)]
struct Packet {
    no: u64,
    t: f64,
    src: String,
    dst: String,
    proto: String,
    len: u32,
    flags: String,
    info: String,
    flow: String,
    app: String,
    anomaly: Option<String>,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct CaptureStats {
    packets: u64,
    captured_bytes: u64,
    pps: u32,
    tcp_pct: u32,
    tls_pct: u32,
    retrans_pct: f32,
    resets: u32,
    flows: u32,
    dropped: u64,
}

/// Agent → cloud frames.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UplinkMsg {
    Hello {
        agent_version: String,
    },
    Packets {
        packets: Vec<Packet>,
    },
    Stats {
        stats: CaptureStats,
    },
    Status {
        capturing: bool,
        message: String,
    },
    FilterResult {
        valid: bool,
        matches: u32,
        error: Option<String>,
    },
}

/// Cloud → agent control frames.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlMsg {
    Start {
        #[serde(default)]
        filter: Option<String>,
    },
    Stop,
    SetFilter {
        bpf: String,
    },
}

// ── connection lifecycle ─────────────────────────────────────────────────────

/// Dial the cloud uplink and serve it, reconnecting forever with backoff.
pub async fn run(
    uplink_url: String,
    api_key: String,
    host_id: Uuid,
    interface: String,
    agent_version: String,
) {
    let mut retry = BASE_RETRY;
    loop {
        match connect_and_serve(&uplink_url, &api_key, host_id, &interface, &agent_version).await {
            Ok(()) => {
                debug!("dpi uplink closed cleanly; reconnecting");
                retry = BASE_RETRY;
            }
            Err(e) => {
                warn!("dpi uplink error: {e}; reconnecting in {retry}s");
            }
        }
        tokio::time::sleep(Duration::from_secs(retry)).await;
        retry = (retry * 2).min(MAX_RETRY);
    }
}

async fn connect_and_serve(
    url: &str,
    api_key: &str,
    host_id: Uuid,
    interface: &str,
    agent_version: &str,
) -> anyhow::Result<()> {
    let full = format!("{url}?host_id={host_id}");
    let mut req = full.into_client_request()?;
    req.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {api_key}"))?,
    );
    let (ws, _resp) = tokio_tungstenite::connect_async(req).await?;
    info!("dpi uplink connected ({url})");
    let (mut ws_tx, mut ws_rx) = ws.split();

    send_msg(
        &mut ws_tx,
        &UplinkMsg::Hello {
            agent_version: agent_version.to_string(),
        },
    )
    .await?;

    // Capture thread → async forwarder. We hold `pkt_tx` for the whole
    // connection; each session clones it, so the receiver only sees data while a
    // capture runs and never closes mid-connection.
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<UplinkMsg>(512);
    let mut session: Option<CaptureSession> = None;
    let mut ping = tokio::time::interval(PING_INTERVAL);

    loop {
        tokio::select! {
            inbound = ws_rx.next() => {
                match inbound {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ControlMsg>(text.as_str()) {
                            Ok(ControlMsg::Start { filter }) => {
                                if session.is_none() {
                                    // The capture thread reports status/filter_result/data via pkt_tx.
                                    session = Some(CaptureSession::spawn(interface.to_string(), filter, pkt_tx.clone()));
                                }
                            }
                            Ok(ControlMsg::Stop) => {
                                session = None; // Drop sets the stop flag → thread exits
                                send_msg(&mut ws_tx, &UplinkMsg::Status { capturing: false, message: "stopped".into() }).await?;
                            }
                            Ok(ControlMsg::SetFilter { bpf }) => {
                                // Stop the old capture (drop → stop flag), then
                                // restart with the new filter; the new thread
                                // reports the authoritative compile result.
                                drop(session.take());
                                session = Some(CaptureSession::spawn(interface.to_string(), Some(bpf), pkt_tx.clone()));
                            }
                            Err(e) => debug!("dpi uplink: bad control frame: {e}"),
                        }
                    }
                    Some(Ok(Message::Ping(p))) => { ws_tx.send(Message::Pong(p)).await?; }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // binary ignored
                    Some(Err(e)) => return Err(e.into()),
                }
            }
            msg = pkt_rx.recv() => {
                if let Some(m) = msg {
                    send_msg(&mut ws_tx, &m).await?;
                }
            }
            _ = ping.tick() => {
                ws_tx.send(Message::Ping(Vec::new().into())).await?;
            }
        }
    }
    // `session` drops here → the capture thread is signalled to stop.
    Ok(())
}

async fn send_msg<S>(tx: &mut S, m: &UplinkMsg) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    tx.send(Message::Text(serde_json::to_string(m)?.into()))
        .await?;
    Ok(())
}

// ── capture session (blocking pcap thread) ───────────────────────────────────

/// Owns a running capture thread. Dropping it signals the thread to stop.
struct CaptureSession {
    stop: Arc<AtomicBool>,
}

impl CaptureSession {
    fn spawn(interface: String, filter: Option<String>, tx: mpsc::Sender<UplinkMsg>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        // pcap's Capture isn't Send-friendly to move across threads, so we open
        // it inside the thread (matches capture.rs). Spawn failures are logged.
        if let Err(e) = std::thread::Builder::new()
            .name("netwatch-dpi-capture".into())
            .spawn(move || run_capture(&interface, filter, tx, stop2))
        {
            warn!("dpi capture thread spawn failed: {e}");
        }
        Self { stop }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn run_capture(
    interface: &str,
    filter: Option<String>,
    tx: mpsc::Sender<UplinkMsg>,
    stop: Arc<AtomicBool>,
) {
    let device = match capture::resolve_interface(interface) {
        Ok(d) => d,
        Err(e) => {
            let _ = tx.blocking_send(UplinkMsg::Status {
                capturing: false,
                message: format!("interface error: {e}"),
            });
            return;
        }
    };
    let dev_name = device.name.clone();
    let mut cap = match Capture::from_device(device).and_then(|c| {
        c.snaplen(SNAPLEN_DPI)
            .timeout(READ_TIMEOUT_MS)
            .immediate_mode(true)
            .open()
    }) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.blocking_send(UplinkMsg::Status {
                capturing: false,
                message: format!("capture open failed on {dev_name} (needs CAP_NET_RAW/root): {e}"),
            });
            return;
        }
    };

    // Compile + install the BPF filter (the real libpcap validation, #16). A bad
    // filter is reported back and the session ends — reject-and-don't-capture.
    if let Some(f) = filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Err(e) = cap.filter(f, true) {
            let _ = tx.blocking_send(UplinkMsg::FilterResult {
                valid: false,
                matches: 0,
                error: Some(format!("{e}")),
            });
            let _ = tx.blocking_send(UplinkMsg::Status {
                capturing: false,
                message: "invalid filter".into(),
            });
            return;
        }
        let _ = tx.blocking_send(UplinkMsg::FilterResult {
            valid: true,
            matches: 0,
            error: None,
        });
    }

    let linktype = cap.get_datalink();
    let _ = tx.blocking_send(UplinkMsg::Status {
        capturing: true,
        message: "capturing".into(),
    });

    let redactor = Redactor::redacting();
    let start = Instant::now();
    let mut no: u64 = 0;
    let mut total_n: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut tcp_n: u64 = 0;
    let mut tls_n: u64 = 0;
    let mut resets: u64 = 0;
    let mut flows: HashMap<(String, String), u32> = HashMap::new();
    let mut batch: Vec<Packet> = Vec::with_capacity(MAX_BATCH);
    let mut last_flush = Instant::now();
    let mut last_stats = Instant::now();

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if start.elapsed() > Duration::from_secs(MAX_SESSION_SECS) {
            let _ = tx.blocking_send(UplinkMsg::Status {
                capturing: false,
                message: "max session duration reached".into(),
            });
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                let on_wire = packet.header.len;
                if let Some(p) = build_packet(
                    packet.data,
                    linktype,
                    on_wire,
                    &mut no,
                    &mut flows,
                    &redactor,
                    &start,
                ) {
                    total_n += 1;
                    total_bytes += on_wire as u64;
                    match p.proto.as_str() {
                        "TLS" => {
                            tcp_n += 1;
                            tls_n += 1;
                        }
                        "TCP" | "HTTP" => tcp_n += 1,
                        _ => {}
                    }
                    if p.flags.contains("RST") {
                        resets += 1;
                    }
                    batch.push(p);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                debug!("dpi capture read ended: {e}");
                break;
            }
        }

        if batch.len() >= MAX_BATCH || (!batch.is_empty() && last_flush.elapsed() >= BATCH_INTERVAL)
        {
            let drained = std::mem::take(&mut batch);
            if tx
                .blocking_send(UplinkMsg::Packets { packets: drained })
                .is_err()
            {
                break; // forwarder gone (connection closed)
            }
            last_flush = Instant::now();
        }

        if last_stats.elapsed() >= STATS_INTERVAL {
            let elapsed = start.elapsed().as_secs_f64().max(1.0);
            let stats = CaptureStats {
                packets: total_n,
                captured_bytes: total_bytes,
                pps: (total_n as f64 / elapsed) as u32,
                tcp_pct: pct(tcp_n, total_n),
                tls_pct: pct(tls_n, total_n),
                retrans_pct: 0.0,
                resets: resets as u32,
                flows: flows.len() as u32,
                dropped: 0,
            };
            if tx.blocking_send(UplinkMsg::Stats { stats }).is_err() {
                break;
            }
            last_stats = Instant::now();
        }
    }
    debug!("dpi capture thread exiting after {} packets", total_n);
}

/// Parse one frame down to METADATA ONLY and build a wire `Packet`. Returns
/// `None` for frames we don't surface (non-IP, non-TCP/UDP, malformed).
fn build_packet(
    frame: &[u8],
    linktype: Linktype,
    on_wire: u32,
    no: &mut u64,
    flows: &mut HashMap<(String, String), u32>,
    redactor: &Redactor,
    start: &Instant,
) -> Option<Packet> {
    let (src_ip, dst_ip, proto, l4) = match linktype {
        Linktype::ETHERNET => capture::parse_ethernet(frame)?,
        Linktype::NULL => capture::parse_bsd_loopback(frame, false)?,
        Linktype::LOOP => capture::parse_bsd_loopback(frame, true)?,
        _ => return None,
    };

    let (sport, dport, flags, payload, is_tcp) = match proto {
        6 => {
            let (sp, dp, fl, pl) = parse_tcp_meta(l4)?;
            (sp, dp, fl, pl, true)
        }
        17 => {
            let (sp, dp, pl) = parse_udp_meta(l4)?;
            (sp, dp, String::new(), pl, false)
        }
        _ => return None,
    };

    let src = format!("{src_ip}:{sport}");
    let dst = format!("{dst_ip}:{dport}");

    // Classify to metadata only (the classifier cannot return bodies/paths).
    let meta = classify_meta(payload, is_tcp, sport, dport);
    let (proto_label, app, info) = label(meta.as_ref(), is_tcp, &flags, on_wire, redactor);

    // Direction-independent flow id.
    let key = if src <= dst {
        (src.clone(), dst.clone())
    } else {
        (dst.clone(), src.clone())
    };
    let next = flows.len() as u32 + 1;
    let flow_id = *flows.entry(key).or_insert(next);

    *no += 1;
    let t = (start.elapsed().as_secs_f64() * 1_000_000.0).round() / 1_000_000.0;
    Some(Packet {
        no: *no,
        t,
        src,
        dst,
        proto: proto_label,
        len: on_wire,
        flags,
        info,
        flow: format!("F{flow_id}"),
        app,
        anomaly: None,
    })
}

/// Build (proto, app, info) labels — ALL metadata-only, redactor-backstopped.
fn label(
    meta: Option<&ClassifiedMeta>,
    is_tcp: bool,
    flags: &str,
    len: u32,
    r: &Redactor,
) -> (String, String, String) {
    let base = if is_tcp { "TCP" } else { "UDP" };
    let fallback = || {
        let info = if flags.is_empty() {
            format!("Len={len}")
        } else {
            format!("{flags} Len={len}")
        };
        (base.to_string(), base.to_string(), info)
    };
    let Some(m) = meta else { return fallback() };
    match &m.app {
        AppProtocol::Tls { sni, .. } => match sni {
            Some(h) if !h.is_empty() => {
                let h = r.redact_text(h);
                (
                    "TLS".into(),
                    format!("TLS · {h}"),
                    format!("Client Hello · {h}"),
                )
            }
            _ => ("TLS".into(), "TLS".into(), "TLS".into()),
        },
        // HTTP: method + Host only. NEVER the path/query (the classifier doesn't
        // even expose it), so `info` carries the method, app carries the Host.
        AppProtocol::Http {
            method,
            host,
            status,
        } => {
            let app = match host {
                Some(h) if !h.is_empty() => format!("HTTP · {}", r.redact_text(h)),
                _ => "HTTP".into(),
            };
            let info = match status {
                Some(s) => format!("HTTP {s}"),
                None => r.redact_text(method).to_string(),
            };
            ("HTTP".into(), app, info)
        }
        AppProtocol::Dns { qname, .. } => (
            "DNS".into(),
            "DNS".into(),
            format!("query {}", r.redact_text(qname)),
        ),
        AppProtocol::Ssh { version } => (
            "TCP".into(),
            format!("SSH · {}", r.redact_text(version)),
            "SSH".into(),
        ),
    }
}

fn parse_tcp_meta(buf: &[u8]) -> Option<(u16, u16, String, &[u8])> {
    if buf.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([buf[0], buf[1]]);
    let dport = u16::from_be_bytes([buf[2], buf[3]]);
    let data_off = ((buf[12] >> 4) as usize) * 4;
    if data_off < 20 || buf.len() < data_off {
        return None;
    }
    let f = buf[13];
    let mut parts: Vec<&str> = Vec::new();
    if f & 0x02 != 0 {
        parts.push("SYN");
    }
    if f & 0x10 != 0 {
        parts.push("ACK");
    }
    if f & 0x08 != 0 {
        parts.push("PSH");
    }
    if f & 0x01 != 0 {
        parts.push("FIN");
    }
    if f & 0x04 != 0 {
        parts.push("RST");
    }
    if f & 0x20 != 0 {
        parts.push("URG");
    }
    Some((sport, dport, parts.join(", "), &buf[data_off..]))
}

fn parse_udp_meta(buf: &[u8]) -> Option<(u16, u16, &[u8])> {
    if buf.len() < 8 {
        return None;
    }
    Some((
        u16::from_be_bytes([buf[0], buf[1]]),
        u16::from_be_bytes([buf[2], buf[3]]),
        &buf[8..],
    ))
}

fn pct(n: u64, total: u64) -> u32 {
    if total == 0 {
        0
    } else {
        ((n as f64 / total as f64) * 100.0) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flags_render_and_payload_offset() {
        // 20-byte TCP header, data offset = 5 (20 bytes), flags = PSH|ACK.
        let mut buf = vec![0u8; 24];
        buf[0..2].copy_from_slice(&443u16.to_be_bytes()); // sport
        buf[2..4].copy_from_slice(&50000u16.to_be_bytes()); // dport
        buf[12] = 0x50; // data offset 5
        buf[13] = 0x18; // PSH|ACK
        buf[20..24].copy_from_slice(b"data");
        let (sp, dp, flags, payload) = parse_tcp_meta(&buf).unwrap();
        assert_eq!(sp, 443);
        assert_eq!(dp, 50000);
        assert_eq!(flags, "ACK, PSH");
        assert_eq!(payload, b"data");
    }

    #[test]
    fn label_never_emits_http_path() {
        // Even if classification yields HTTP, only method + host can appear.
        let r = Redactor::redacting();
        let meta = ClassifiedMeta {
            app: AppProtocol::Http {
                method: "GET".into(),
                host: Some("github.com".into()),
                status: None,
            },
            sni: None,
            host: Some("github.com".into()),
            http_method: Some("GET".into()),
            dns_qname: None,
            alpn: None,
            ja4: None,
        };
        let (proto, app, info) = label(Some(&meta), true, "PSH, ACK", 200, &r);
        assert_eq!(proto, "HTTP");
        assert_eq!(app, "HTTP · github.com");
        assert_eq!(info, "GET");
        // No path/query ever — the classifier doesn't expose it and we don't add it.
        assert!(!app.contains('/'));
        assert!(!info.contains('/'));
    }

    #[test]
    fn pct_is_bounded() {
        assert_eq!(pct(0, 0), 0);
        assert_eq!(pct(1, 4), 25);
        assert_eq!(pct(4, 4), 100);
    }
}
