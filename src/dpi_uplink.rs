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
//!     plaintext. Snaplen bounds local packet copies; payload bytes may be
//!     inspected locally but are excluded from every emitted frame.
//!   * REDACTION BACKSTOP: every free-text field is passed through the
//!     `netwatch-dpi` Redactor before it leaves the host — defense in depth on
//!     top of the allowlist.
//!   * SESSION CAPS (#21): one capture at a time, a hard max duration, and
//!     snaplen/batch ceilings — enforced here regardless of what the cloud asks.
//!
//! FOLLOW-UP (security review #19): cloud→agent commands are authenticated by
//! TLS + the api key on the uplink and gated by the local opt-in, but are not
//! yet cryptographically signed per-command. Tracked for a later pass.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use netwatch_dpi::{
    classify_meta, dns_message, extract_dns_answers, AppProtocol, ClassifiedMeta, Redactor,
};
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
const MAX_BATCH: usize = 64;
const MAX_RELAY_FRAME: usize = 512 * 1024;
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
    /// Protocol-header decode tree (Frame/Eth/IP/TCP/UDP + L7 identification).
    /// Header fields only — NEVER application payload bodies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    decode: Vec<DecodeNode>,
    /// Header-region hex (L2–L4 bytes only, no payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    hex: Option<HexDump>,
}

/// A node in the protocol decode tree; mirrors the dashboard's `DecodeNode`.
/// `span` is the byte range of this field in the header hex (drives highlight).
#[derive(Serialize, Clone)]
struct DecodeNode {
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span: Option<[u32; 2]>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<DecodeNode>,
}

impl DecodeNode {
    fn leaf(label: &str, value: String) -> Self {
        Self {
            label: label.into(),
            value: Some(value),
            span: None,
            children: Vec::new(),
        }
    }
    fn leaf_span(label: &str, value: String, span: [u32; 2]) -> Self {
        Self {
            label: label.into(),
            value: Some(value),
            span: Some(span),
            children: Vec::new(),
        }
    }
    fn node(
        label: &str,
        value: Option<String>,
        span: Option<[u32; 2]>,
        children: Vec<DecodeNode>,
    ) -> Self {
        Self {
            label: label.into(),
            value,
            span,
            children,
        }
    }
}

#[derive(Serialize, Clone)]
struct HexDump {
    bytes: Vec<u8>,
    highlight: Option<[u32; 2]>,
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
    /// IP → hostname labels for the ledger/decode. `source` is "dns" (learned
    /// passively from observed DNS answers — authoritative) or "ptr" (reverse
    /// lookup for an address never seen in a query). Names are redacted at
    /// source like every other identifier.
    Names {
        source: String,
        names: HashMap<String, String>,
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
    let (_idle_tx, mut pkt_rx) = mpsc::channel::<UplinkMsg>(512);
    let mut pending_filter: Option<String> = None;
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
                                    let (tx, rx) = mpsc::channel(512);
                                    pkt_rx = rx;
                                    session = Some(CaptureSession::spawn(interface.to_string(), filter.or_else(|| pending_filter.clone()), tx));
                                }
                            }
                            Ok(ControlMsg::Stop) => {
                                session = None; // Drop sets the stop flag → thread exits
                                pkt_rx = mpsc::channel(1).1; // release blocked producers and queued frames
                                send_msg(&mut ws_tx, &UplinkMsg::Status { capturing: false, message: "stopped".into() }).await?;
                            }
                            Ok(ControlMsg::SetFilter { bpf }) => {
                                pending_filter = Some(bpf.clone());
                                // Editing a stopped session never starts capture.
                                if session.is_some() {
                                    drop(session.take());
                                    let (tx, rx) = mpsc::channel(512);
                                    pkt_rx = rx; // discard frames from the previous session
                                    session = Some(CaptureSession::spawn(interface.to_string(), Some(bpf), tx));
                                }

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
            msg = pkt_rx.recv(), if session.is_some() => {
                if let Some(m) = msg {
                    if matches!(m, UplinkMsg::Status { capturing: false, .. }) {
                        session = None; // allow retry after permission/filter/read failure
                        pkt_rx = mpsc::channel(1).1;
                    }
                    send_msg(&mut ws_tx, &m).await?;
                } else {
                    session = None;
                    send_msg(&mut ws_tx, &UplinkMsg::Status { capturing: false, message: "capture worker exited".into() }).await?;
                }
            }
            _ = ping.tick() => {
                ws_tx.send(Message::Ping(Vec::new())).await?;
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
    for text in encode_frames(m)? {
        tokio::time::timeout(Duration::from_secs(10), tx.send(Message::Text(text))).await??;
    }
    Ok(())
}

// Stay below the relay's 512 KiB limit even when a batch learns many DNS names.
fn encode_frames(m: &UplinkMsg) -> anyhow::Result<Vec<String>> {
    let frames = match m {
        UplinkMsg::Packets { packets } => packets
            .chunks(MAX_BATCH)
            .map(|chunk| {
                serde_json::to_string(&UplinkMsg::Packets {
                    packets: chunk.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        UplinkMsg::Names { source, names } => {
            let entries: Vec<_> = names.iter().collect();
            entries
                .chunks(64)
                .map(|chunk| {
                    serde_json::to_string(&UplinkMsg::Names {
                        source: source.clone(),
                        names: chunk
                            .iter()
                            .map(|(k, v)| ((*k).clone(), (*v).clone()))
                            .collect(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => vec![serde_json::to_string(m)?],
    };
    anyhow::ensure!(
        frames.iter().all(|f| f.len() <= MAX_RELAY_FRAME),
        "capture frame exceeds relay size limit"
    );
    Ok(frames)
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
        let error_tx = tx.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("netwatch-dpi-capture".into())
            .spawn(move || run_capture(&interface, filter, tx, stop2))
        {
            warn!("dpi capture thread spawn failed: {e}");
            let _ = error_tx.try_send(UplinkMsg::Status {
                capturing: false,
                message: "could not start capture worker".into(),
            });
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

    let mut cap = match cap.setnonblock() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.blocking_send(UplinkMsg::Status {
                capturing: false,
                message: format!("capture nonblocking mode failed: {e}"),
            });
            return;
        }
    };
    let linktype = cap.get_datalink();
    if !matches!(
        linktype,
        Linktype::ETHERNET | Linktype::NULL | Linktype::LOOP
    ) {
        let _ = tx.blocking_send(UplinkMsg::Status {
            capturing: false,
            message: format!(
                "unsupported capture link type {linktype:?}; select a physical interface"
            ),
        });
        return;
    }
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

    // Name resolution. `names` is the authoritative passive map (IP → looked-up
    // name, from observed DNS answers); `pending_names` buffers newly-learned
    // labels to flush with the next batch; `ptr_queued` dedupes what we've handed
    // to the reverse-DNS worker. The worker runs off this thread so a slow
    // resolver can't stall capture; the bounded channel drops on overflow.
    let mut names: HashMap<IpAddr, String> = HashMap::new();
    let mut pending_names: HashMap<String, String> = HashMap::new();
    let mut ptr_queued: HashSet<IpAddr> = HashSet::new();
    let (ptr_tx, ptr_rx) = std::sync::mpsc::sync_channel::<IpAddr>(1024);
    {
        let tx = tx.clone();
        let stop = stop.clone();
        if let Err(e) = std::thread::Builder::new()
            .name("netwatch-dpi-ptr".into())
            .spawn(move || ptr_resolver_loop(ptr_rx, tx, stop))
        {
            warn!("dpi ptr resolver spawn failed: {e}");
        }
    }

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
                if let Some(built) = build_packet(
                    packet.data,
                    linktype,
                    on_wire,
                    &mut no,
                    &mut flows,
                    &redactor,
                    &start,
                ) {
                    let Built {
                        packet: p,
                        src_ip,
                        dst_ip,
                        dns_answers,
                    } = built;
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

                    // Passive DNS wins: learn IP → looked-up name and stop any
                    // pending reverse lookup for that address.
                    for (name, ip) in dns_answers {
                        let label = redactor.redact_text(&name).to_string();
                        if names.len() < 4096 && names.get(&ip) != Some(&label) {
                            names.insert(ip, label.clone());
                            pending_names.insert(ip.to_string(), label);
                            ptr_queued.insert(ip);
                        }
                    }
                    // Reverse-DNS fallback for endpoints with no name yet.
                    for ip in [src_ip, dst_ip] {
                        if ptr_queued.len() < 4096
                            && ptr_eligible(&ip)
                            && !names.contains_key(&ip)
                            && ptr_queued.insert(ip)
                        {
                            let _ = ptr_tx.try_send(ip);
                        }
                    }

                    batch.push(p);
                }
            }
            Err(pcap::Error::TimeoutExpired) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                debug!("dpi capture read ended: {e}");
                let _ = tx.blocking_send(UplinkMsg::Status {
                    capturing: false,
                    message: format!("capture read failed: {e}"),
                });
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
            if !pending_names.is_empty() {
                let names = std::mem::take(&mut pending_names);
                if tx
                    .blocking_send(UplinkMsg::Names {
                        source: "dns".into(),
                        names,
                    })
                    .is_err()
                {
                    break;
                }
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
    stop.store(true, Ordering::Relaxed);
    debug!("dpi capture thread exiting after {} packets", total_n);
}

/// Reverse-DNS worker. Resolves endpoint IPs the passive map never named, off
/// the capture thread so a slow resolver can't stall capture. Dedupes, drops
/// non-results (a PTR that just echoes the address), redacts, and emits one
/// `Names` frame per resolved address. Exits when the capture thread drops the
/// sender or the session stops.
fn ptr_resolver_loop(
    rx: std::sync::mpsc::Receiver<IpAddr>,
    tx: mpsc::Sender<UplinkMsg>,
    stop: Arc<AtomicBool>,
) {
    let redactor = Redactor::redacting();
    let mut seen: HashSet<IpAddr> = HashSet::new();
    while let Ok(ip) = rx.recv() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if !seen.insert(ip) {
            continue;
        }
        let Ok(host) = dns_lookup::lookup_addr(&ip) else {
            continue;
        };
        let host = host.trim();
        if host.is_empty() || host == ip.to_string() {
            continue; // no useful PTR record
        }
        let mut names = HashMap::new();
        names.insert(ip.to_string(), redactor.redact_text(host).to_string());
        if tx
            .blocking_send(UplinkMsg::Names {
                source: "ptr".into(),
                names,
            })
            .is_err()
        {
            break; // uplink gone
        }
    }
}

/// Whether an address is worth a reverse lookup. Skips loopback, multicast, and
/// the unspecified address — never meaningful endpoints.
fn ptr_eligible(ip: &IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_multicast() || ip.is_unspecified())
}

/// Parse one frame down to METADATA ONLY and build a wire `Packet`. Returns
/// `None` for frames we don't surface (non-IP, non-TCP/UDP, malformed).
/// A built packet plus the side-channel the names layer needs: the endpoint
/// addresses (to queue for reverse DNS) and any A/AAAA answers carried by a DNS
/// response (to learn passively).
struct Built {
    packet: Packet,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dns_answers: Vec<(String, IpAddr)>,
}

fn build_packet(
    frame: &[u8],
    linktype: Linktype,
    on_wire: u32,
    no: &mut u64,
    flows: &mut HashMap<(String, String), u32>,
    redactor: &Redactor,
    start: &Instant,
) -> Option<Built> {
    // No IP reassembly: a noninitial fragment could masquerade as a transport
    // header and turn payload bytes into purported header hex.
    let ip_offset = match linktype {
        Linktype::ETHERNET => 14,
        Linktype::NULL | Linktype::LOOP => 4,
        _ => return None,
    };
    let ip = frame.get(ip_offset..)?;
    if ip.first().map(|b| b >> 4) == Some(4) {
        let frag = u16::from_be_bytes(ip.get(6..8)?.try_into().ok()?);
        if frag & 0x3fff != 0 {
            return None;
        }
    }
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

    // Passive DNS: a DNS *response* carries the address(es) the looked-up name
    // resolved to. Harvest them (empty for queries / non-DNS) so endpoint IPs
    // can be labelled with the name that was requested.
    let dns_answers = match meta.as_ref().map(|m| &m.app) {
        Some(AppProtocol::Dns { .. }) => dns_message(payload, is_tcp)
            .map(extract_dns_answers)
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    let (proto_label, app, info) = label(meta.as_ref(), is_tcp, &flags, on_wire, redactor);

    // Protocol-header decode tree (+ header-only hex). Header fields only.
    let (decode, hex) = build_decode(frame, linktype, meta.as_ref(), redactor);

    // Direction-independent flow id.
    let key = if src <= dst {
        (src.clone(), dst.clone())
    } else {
        (dst.clone(), src.clone())
    };
    if !flows.contains_key(&key) && flows.len() >= 4096 {
        return None;
    }
    let next = flows.len() as u32 + 1;
    let flow_id = *flows.entry(key).or_insert(next);

    *no += 1;
    let t = (start.elapsed().as_secs_f64() * 1_000_000.0).round() / 1_000_000.0;
    Some(Built {
        packet: Packet {
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
            decode,
            hex,
        },
        src_ip,
        dst_ip,
        dns_answers,
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

/// Build the protocol-HEADER decode tree (+ header-only hex) from the raw frame.
/// Emits only L2–L4 header fields (real, parsed from bytes) plus L7
/// *identification* values from the classifier (SNI/Host/method/qname — never
/// bodies/paths). The hex is the header region only (no application payload).
/// Bounds-checked: returns a partial tree if the frame is truncated.
fn build_decode(
    frame: &[u8],
    linktype: Linktype,
    meta: Option<&ClassifiedMeta>,
    r: &Redactor,
) -> (Vec<DecodeNode>, Option<HexDump>) {
    let mut tree = vec![DecodeNode::leaf(
        "Frame",
        format!("{} bytes on wire", frame.len()),
    )];

    // ── L2 ──
    let l2_len: usize = match linktype {
        Linktype::ETHERNET => {
            if frame.len() < 14 {
                return (tree, None);
            }
            let mac = |o: usize| {
                frame[o..o + 6]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            let etype = u16::from_be_bytes([frame[12], frame[13]]);
            tree.push(DecodeNode::node(
                "Ethernet II",
                None,
                Some([0, 14]),
                vec![
                    DecodeNode::leaf_span("Destination", mac(0), [0, 6]),
                    DecodeNode::leaf_span("Source", mac(6), [6, 12]),
                    DecodeNode::leaf_span("Type", format!("0x{etype:04x}"), [12, 14]),
                ],
            ));
            14
        }
        Linktype::NULL | Linktype::LOOP => {
            if frame.len() < 4 {
                return (tree, None);
            }
            let fam = u32::from_ne_bytes([frame[0], frame[1], frame[2], frame[3]]);
            tree.push(DecodeNode::node(
                "Loopback",
                None,
                Some([0, 4]),
                vec![DecodeNode::leaf_span(
                    "Address family",
                    format!("{fam}"),
                    [0, 4],
                )],
            ));
            4
        }
        _ => return (tree, None),
    };

    // ── L3 ──
    if frame.len() <= l2_len {
        return (tree, None);
    }
    let l2 = l2_len as u32;
    let (l4_proto, l4_off) = match frame[l2_len] >> 4 {
        4 => {
            if frame.len() < l2_len + 20 {
                return (tree, None);
            }
            let ihl = ((frame[l2_len] & 0x0f) as usize) * 4;
            if ihl < 20 || frame.len() < l2_len + ihl {
                return (tree, None);
            }
            let ttl = frame[l2_len + 8];
            let proto = frame[l2_len + 9];
            let cks = u16::from_be_bytes([frame[l2_len + 10], frame[l2_len + 11]]);
            let src = std::net::Ipv4Addr::new(
                frame[l2_len + 12],
                frame[l2_len + 13],
                frame[l2_len + 14],
                frame[l2_len + 15],
            );
            let dst = std::net::Ipv4Addr::new(
                frame[l2_len + 16],
                frame[l2_len + 17],
                frame[l2_len + 18],
                frame[l2_len + 19],
            );
            tree.push(DecodeNode::node(
                "Internet Protocol v4",
                Some(format!("{src} → {dst}")),
                Some([l2, l2 + ihl as u32]),
                vec![
                    DecodeNode::leaf_span(
                        "Version / IHL",
                        format!("4 / {ihl} bytes"),
                        [l2, l2 + 1],
                    ),
                    DecodeNode::leaf_span("TTL", format!("{ttl}"), [l2 + 8, l2 + 9]),
                    DecodeNode::leaf_span("Protocol", proto_name(proto), [l2 + 9, l2 + 10]),
                    DecodeNode::leaf_span(
                        "Header checksum",
                        format!("0x{cks:04x}"),
                        [l2 + 10, l2 + 12],
                    ),
                    DecodeNode::leaf_span("Source", src.to_string(), [l2 + 12, l2 + 16]),
                    DecodeNode::leaf_span("Destination", dst.to_string(), [l2 + 16, l2 + 20]),
                ],
            ));
            (proto, l2_len + ihl)
        }
        6 => {
            if frame.len() < l2_len + 40 {
                return (tree, None);
            }
            let nh = frame[l2_len + 6];
            let hop = frame[l2_len + 7];
            let src = ipv6_at(frame, l2_len + 8);
            let dst = ipv6_at(frame, l2_len + 24);
            tree.push(DecodeNode::node(
                "Internet Protocol v6",
                Some(format!("{src} → {dst}")),
                Some([l2, l2 + 40]),
                vec![
                    DecodeNode::leaf_span("Next header", proto_name(nh), [l2 + 6, l2 + 7]),
                    DecodeNode::leaf_span("Hop limit", format!("{hop}"), [l2 + 7, l2 + 8]),
                    DecodeNode::leaf_span("Source", src.to_string(), [l2 + 8, l2 + 24]),
                    DecodeNode::leaf_span("Destination", dst.to_string(), [l2 + 24, l2 + 40]),
                ],
            ));
            (nh, l2_len + 40)
        }
        _ => return (tree, None),
    };

    // ── L4 ──
    let o = l4_off as u32;
    let l7_off = if l4_proto == 6 && frame.len() >= l4_off + 20 {
        let sport = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]);
        let dport = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]);
        let seq = u32::from_be_bytes([
            frame[l4_off + 4],
            frame[l4_off + 5],
            frame[l4_off + 6],
            frame[l4_off + 7],
        ]);
        let ack = u32::from_be_bytes([
            frame[l4_off + 8],
            frame[l4_off + 9],
            frame[l4_off + 10],
            frame[l4_off + 11],
        ]);
        let doff = (((frame[l4_off + 12] >> 4) as usize) * 4).max(20);
        let fl = frame[l4_off + 13];
        let win = u16::from_be_bytes([frame[l4_off + 14], frame[l4_off + 15]]);
        tree.push(DecodeNode::node(
            "Transmission Control Protocol",
            Some(format!("{sport} → {dport}")),
            Some([o, o + doff as u32]),
            vec![
                DecodeNode::leaf_span("Source Port", format!("{sport}"), [o, o + 2]),
                DecodeNode::leaf_span("Destination Port", format!("{dport}"), [o + 2, o + 4]),
                DecodeNode::leaf_span("Sequence", format!("{seq}"), [o + 4, o + 8]),
                DecodeNode::leaf_span("Acknowledgment", format!("{ack}"), [o + 8, o + 12]),
                DecodeNode::node(
                    "Flags",
                    Some(format!("0x{fl:02x}")),
                    Some([o + 13, o + 14]),
                    vec![
                        DecodeNode::leaf("SYN", yn(fl & 0x02 != 0)),
                        DecodeNode::leaf("ACK", yn(fl & 0x10 != 0)),
                        DecodeNode::leaf("PSH", yn(fl & 0x08 != 0)),
                        DecodeNode::leaf("FIN", yn(fl & 0x01 != 0)),
                        DecodeNode::leaf("RST", yn(fl & 0x04 != 0)),
                    ],
                ),
                DecodeNode::leaf_span("Window", format!("{win}"), [o + 14, o + 16]),
            ],
        ));
        l4_off + doff
    } else if l4_proto == 17 && frame.len() >= l4_off + 8 {
        let sport = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]);
        let dport = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]);
        let ulen = u16::from_be_bytes([frame[l4_off + 4], frame[l4_off + 5]]);
        tree.push(DecodeNode::node(
            "User Datagram Protocol",
            Some(format!("{sport} → {dport}")),
            Some([o, o + 8]),
            vec![
                DecodeNode::leaf_span("Source Port", format!("{sport}"), [o, o + 2]),
                DecodeNode::leaf_span("Destination Port", format!("{dport}"), [o + 2, o + 4]),
                DecodeNode::leaf_span("Length", format!("{ulen}"), [o + 4, o + 6]),
            ],
        ));
        l4_off + 8
    } else {
        l4_off
    };

    // ── L7 identification (values only, redactor-backstopped; no bodies/paths) ──
    let rd = |s: &str| r.redact_text(s).into_owned();
    if let Some(m) = meta {
        match &m.app {
            AppProtocol::Tls { sni, alpn, ja4, .. } => {
                let mut ch = Vec::new();
                if let Some(s) = sni {
                    ch.push(DecodeNode::leaf("Server Name (SNI)", rd(s)));
                }
                if let Some(a) = alpn {
                    ch.push(DecodeNode::leaf("ALPN", rd(a)));
                }
                if let Some(j) = ja4 {
                    ch.push(DecodeNode::leaf("JA4", rd(j)));
                }
                tree.push(DecodeNode::node(
                    "Transport Layer Security",
                    Some("ClientHello".into()),
                    None,
                    ch,
                ));
            }
            AppProtocol::Http {
                method,
                host,
                status,
            } => {
                let mut ch = vec![DecodeNode::leaf("Method", rd(method))];
                if let Some(h) = host {
                    ch.push(DecodeNode::leaf("Host", rd(h)));
                }
                if let Some(s) = status {
                    ch.push(DecodeNode::leaf("Status", format!("{s}")));
                }
                tree.push(DecodeNode::node(
                    "Hypertext Transfer Protocol",
                    None,
                    None,
                    ch,
                ));
            }
            AppProtocol::Dns { qname, qtype } => {
                tree.push(DecodeNode::node(
                    "Domain Name System",
                    None,
                    None,
                    vec![
                        DecodeNode::leaf("Query Name", rd(qname)),
                        DecodeNode::leaf("Query Type", format!("{qtype}")),
                    ],
                ));
            }
            AppProtocol::Ssh { version } => {
                tree.push(DecodeNode::node("SSH", Some(rd(version)), None, Vec::new()));
            }
        }
    }

    // Header-only hex: L2–L4 bytes (NO application payload), capped at 128 bytes.
    let end = l7_off.min(frame.len()).min(128);
    let hex = HexDump {
        bytes: frame[..end].to_vec(),
        highlight: Some([(l4_off.min(end)) as u32, (l7_off.min(end)) as u32]),
    };
    (tree, Some(hex))
}

fn proto_name(p: u8) -> String {
    match p {
        1 => "ICMP (1)".into(),
        6 => "TCP (6)".into(),
        17 => "UDP (17)".into(),
        58 => "ICMPv6 (58)".into(),
        other => format!("{other}"),
    }
}

fn yn(b: bool) -> String {
    if b {
        "Set".into()
    } else {
        "·".into()
    }
}

fn ipv6_at(frame: &[u8], off: usize) -> std::net::Ipv6Addr {
    let mut b = [0u8; 16];
    b.copy_from_slice(&frame[off..off + 16]);
    std::net::Ipv6Addr::from(b)
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
    let len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if len < 8 {
        return None;
    }
    Some((
        u16::from_be_bytes([buf[0], buf[1]]),
        u16::from_be_bytes([buf[2], buf[3]]),
        &buf[8..len.min(buf.len())],
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

#[cfg(test)]
mod capture_integration_tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Write;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 54];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        f[23] = 6;
        f[26..30].copy_from_slice(&[192, 0, 2, 1]);
        f[30..34].copy_from_slice(&[192, 0, 2, 2]);
        f[34..36].copy_from_slice(&12345u16.to_be_bytes());
        f[36..38].copy_from_slice(&80u16.to_be_bytes());
        f[46] = 0x50;
        f[47] = 0x18;
        f.extend(payload);
        f
    }

    #[test]
    fn offline_pcap_to_wire_contains_metadata_but_no_payload() {
        let f=frame(b"POST /SECRET_PATH?token=SECRET_QUERY HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer SECRET_AUTH\r\nCookie: SECRET_COOKIE\r\n\r\nSECRET_BODY");
        let mut pcap = tempfile::NamedTempFile::new().unwrap();
        pcap.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ])
        .unwrap();
        for n in [0u32, 0, f.len() as u32, f.len() as u32] {
            pcap.write_all(&n.to_le_bytes()).unwrap();
        }
        pcap.write_all(&f).unwrap();
        pcap.flush().unwrap();
        let mut cap = Capture::from_file(pcap.path()).unwrap();
        let link = cap.get_datalink();
        let packet = cap.next_packet().unwrap();
        let built = build_packet(
            packet.data,
            link,
            packet.header.len,
            &mut 0,
            &mut HashMap::new(),
            &Redactor::redacting(),
            &Instant::now(),
        )
        .unwrap();
        assert_eq!(built.packet.proto, "HTTP");
        assert_eq!(built.packet.app, "HTTP · example.com");
        assert_eq!(built.packet.hex.as_ref().unwrap().bytes, f[..54]);
        let json = serde_json::to_string(&UplinkMsg::Packets {
            packets: vec![built.packet],
        })
        .unwrap();
        assert!(!json.contains("SECRET_"), "{json}");
        assert!(json.contains("example.com"));
    }

    async fn receive_status<S>(
        socket: &mut tokio_tungstenite::WebSocketStream<S>,
    ) -> serde_json::Value
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let m = socket.next().await.unwrap().unwrap();
                if let Message::Text(t) = m {
                    let value: serde_json::Value = serde_json::from_str(&t).unwrap();
                    if value["type"] == "status" {
                        return value;
                    }
                }
            }
        })
        .await
        .expect("status timeout")
    }

    #[tokio::test]
    async fn websocket_capture_failure_is_visible_and_retryable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            connect_and_serve(
                &format!("ws://{addr}/uplink"),
                "fixture",
                Uuid::nil(),
                "netwatch-interface-that-does-not-exist",
                "test",
            )
            .await
        });
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        // A failed worker must be cleared so each fresh start gets a result.
        for _ in 0..2 {
            ws.send(Message::Text(r#"{"type":"start"}"#.into()))
                .await
                .unwrap();
            let status = receive_status(&mut ws).await;
            assert_eq!(status["capturing"], false);
            assert!(status["message"]
                .as_str()
                .unwrap()
                .contains("interface error"));
        }
        ws.send(Message::Text(r#"{"type":"set_filter","bpf":"tcp"}"#.into()))
            .await
            .unwrap();
        ws.send(Message::Text(r#"{"type":"stop"}"#.into()))
            .await
            .unwrap();
        assert_eq!(receive_status(&mut ws).await["message"], "stopped");
        ws.send(Message::Close(None)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn malformed_frames_never_panic(f in prop::collection::vec(any::<u8>(),0..2048)) {
            for link in [Linktype::ETHERNET,Linktype::NULL,Linktype::LOOP] {
                let _=build_packet(&f,link,f.len() as u32,&mut 0,&mut HashMap::new(),&Redactor::redacting(),&Instant::now());
            }
        }
    }
}

#[cfg(test)]
mod wire_limit_tests {
    use super::*;
    #[test]
    fn dns_names_are_split_without_loss_before_relay_limit() {
        let names: HashMap<_, _> = (0..4096)
            .map(|i| (format!("2001:db8::{i:x}"), "x".repeat(256)))
            .collect();
        let frames = encode_frames(&UplinkMsg::Names {
            source: "dns".into(),
            names: names.clone(),
        })
        .unwrap();
        assert!(frames.len() > 1);
        let mut restored = HashMap::new();
        for frame in frames {
            assert!(frame.len() <= MAX_RELAY_FRAME);
            let json: serde_json::Value = serde_json::from_str(&frame).unwrap();
            for (ip, name) in json["names"].as_object().unwrap() {
                restored.insert(ip.clone(), name.as_str().unwrap().to_string());
            }
        }
        assert_eq!(restored, names);
    }
}
