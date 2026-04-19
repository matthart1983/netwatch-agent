//! Packet capture loop for feeding NetworkIntel's SYN/DNS detectors.
//!
//! This only parses what the detectors need — TCP SYN for connection attempts
//! and DNS queries/responses over UDP/53. No payload storage, no stream
//! reassembly, no packet-list buffer. Those are dashboard concerns the agent
//! doesn't own today.
//!
//! Requires elevated privileges: CAP_NET_RAW on Linux, admin/root on macOS.
//! If pcap can't open the interface, the capture thread logs a warning and
//! exits; the agent keeps running without it (bandwidth detector still fires
//! from interface rate samples).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::thread;

use netwatch_sdk::collectors::network_intel::{
    ConnAttemptEvent, DnsQueryEvent, DnsResponseEvent, NetworkIntelCollector,
};
use pcap::{Capture, Device, Linktype};

/// macOS sets AF_INET6 = 30 in the BSD loopback header. Other BSDs use
/// different numbers, but we only need macOS + Linux here.
const MACOS_AF_INET6: u32 = 30;

const SNAPLEN: i32 = 65535;
const READ_TIMEOUT_MS: i32 = 500;

/// Pick an interface to capture on. "auto" picks the pcap default device,
/// which is typically the primary uplink.
fn resolve_interface(name: &str) -> Result<Device, pcap::Error> {
    if name == "auto" {
        return Device::lookup()?.ok_or_else(|| {
            pcap::Error::PcapError("no default capture device available".into())
        });
    }
    let devices = Device::list()?;
    devices
        .into_iter()
        .find(|d| d.name == name)
        .ok_or_else(|| pcap::Error::PcapError(format!("interface {} not found", name)))
}

/// Spawn a background capture thread. Does not block. Returns immediately;
/// errors are surfaced via tracing rather than propagated.
pub fn spawn(interface: String, intel: Arc<Mutex<NetworkIntelCollector>>) {
    thread::Builder::new()
        .name("netwatch-capture".into())
        .spawn(move || run(&interface, intel))
        .expect("failed to spawn capture thread");
}

fn run(interface: &str, intel: Arc<Mutex<NetworkIntelCollector>>) {
    let device = match resolve_interface(interface) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("packet capture disabled — {}", e);
            return;
        }
    };

    tracing::info!("packet capture starting on {}", device.name);

    let mut cap = match Capture::from_device(device.clone())
        .and_then(|c| c.snaplen(SNAPLEN).timeout(READ_TIMEOUT_MS).open())
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "packet capture disabled — could not open {} ({}). \
                 Hint: run the agent with elevated privileges \
                 (sudo / CAP_NET_RAW).",
                device.name,
                e
            );
            return;
        }
    };

    // BPF filter: we only need TCP SYN packets and DNS (UDP/53) traffic.
    // Filtering in-kernel avoids a lot of userspace work on a busy host.
    let filter = "(tcp and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0) \
                  or (udp and port 53)";
    if let Err(e) = cap.filter(filter, true) {
        tracing::warn!("packet capture disabled — failed to install BPF filter: {}", e);
        return;
    }

    let linktype = cap.get_datalink();
    tracing::info!(
        "packet capture ready — filter: {}, linktype: {:?}",
        filter,
        linktype
    );

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(event) = parse_event(packet.data, linktype) {
                    let mut guard = match intel.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    match event {
                        Event::Conn(ev) => guard.on_conn_attempt(ev),
                        Event::DnsQ(ev) => guard.on_dns_query(ev),
                        Event::DnsR(ev) => guard.on_dns_response(ev),
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                tracing::error!("capture read error: {}", e);
                return;
            }
        }
    }
}

enum Event {
    Conn(ConnAttemptEvent),
    DnsQ(DnsQueryEvent),
    DnsR(DnsResponseEvent),
}

/// Parse a link-layer frame → IP → TCP/UDP → (optional) DNS and emit one of
/// our three event types, or None if the packet isn't relevant.
///
/// Supports three link types we actually encounter:
///   - Ethernet (DLT_EN10MB): normal NICs on both macOS and Linux,
///     and Linux's loopback too.
///   - BSD loopback null (DLT_NULL): macOS `lo0`. 4-byte header,
///     little-endian AF family number.
///   - OpenBSD loopback (DLT_LOOP): same shape, big-endian.
fn parse_event(frame: &[u8], linktype: Linktype) -> Option<Event> {
    let (src, dst, proto, l4) = match linktype {
        Linktype::ETHERNET => parse_ethernet(frame)?,
        Linktype::NULL => parse_bsd_loopback(frame, false)?,
        Linktype::LOOP => parse_bsd_loopback(frame, true)?,
        _ => return None,
    };

    match proto {
        6 => parse_tcp(src, dst, l4),
        17 => parse_udp(src, dst, l4),
        _ => None,
    }
}

fn parse_ethernet(frame: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => parse_ipv4(&frame[14..]),
        0x86DD => parse_ipv6(&frame[14..]),
        _ => None,
    }
}

/// BSD loopback: 4-byte family header, then the IP packet. DLT_NULL uses
/// host byte order; DLT_LOOP uses network byte order. We treat DLT_NULL as
/// little-endian because every OS where we'd actually see DLT_NULL
/// (macOS/Linux/FreeBSD) is little-endian.
fn parse_bsd_loopback(frame: &[u8], network_byte_order: bool) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    if frame.len() < 4 {
        return None;
    }
    let family = if network_byte_order {
        u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]])
    } else {
        u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]])
    };
    match family {
        2 => parse_ipv4(&frame[4..]),                 // AF_INET
        f if f == MACOS_AF_INET6 || f == 10 || f == 24 || f == 28 => parse_ipv6(&frame[4..]),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let proto = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some((IpAddr::V4(src), IpAddr::V4(dst), proto, &buf[ihl..]))
}

fn parse_ipv6(buf: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    if buf.len() < 40 {
        return None;
    }
    let next_header = buf[6];
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&buf[8..24]);
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&buf[24..40]);
    Some((
        IpAddr::V6(Ipv6Addr::from(src_bytes)),
        IpAddr::V6(Ipv6Addr::from(dst_bytes)),
        next_header,
        &buf[40..],
    ))
}

fn parse_tcp(src: IpAddr, dst: IpAddr, buf: &[u8]) -> Option<Event> {
    if buf.len() < 20 {
        return None;
    }
    let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
    let flags = buf[13];
    // BPF already filtered to SYN && !ACK, but double-check the invariant.
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    if !syn || ack {
        return None;
    }
    Some(Event::Conn(ConnAttemptEvent {
        src_ip: src.to_string(),
        dst_ip: dst.to_string(),
        dst_port,
    }))
}

fn parse_udp(src: IpAddr, dst: IpAddr, buf: &[u8]) -> Option<Event> {
    if buf.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([buf[0], buf[1]]);
    let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
    if src_port != 53 && dst_port != 53 {
        return None;
    }
    let payload = &buf[8..];
    parse_dns(src, dst, src_port, dst_port, payload)
}

fn parse_dns(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    buf: &[u8],
) -> Option<Event> {
    if buf.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([buf[0], buf[1]]);
    let flags_hi = buf[2];
    let flags_lo = buf[3];
    let is_response = flags_hi & 0x80 != 0;
    let rcode = flags_lo & 0x0f;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    // Clients send to port 53; servers reply from port 53.
    let (client_ip, server_ip) = if is_response {
        (dst.to_string(), src.to_string())
    } else {
        (src.to_string(), dst.to_string())
    };

    if is_response {
        return Some(Event::DnsR(DnsResponseEvent {
            txid,
            client_ip,
            server_ip,
            rcode,
        }));
    }

    // Parse the first question's QNAME.
    let qname = parse_qname(buf, 12)?;
    let _ = (src_port, dst_port);
    Some(Event::DnsQ(DnsQueryEvent {
        txid,
        client_ip,
        server_ip,
        qname,
    }))
}

/// Parse an RFC 1035 QNAME starting at `offset` into the DNS message. We don't
/// follow compression pointers (0xC0) — queries don't use them, and truncated
/// names are fine to drop.
fn parse_qname(buf: &[u8], offset: usize) -> Option<String> {
    let mut pos = offset;
    let mut out = String::new();
    let mut safety = 0;
    while pos < buf.len() && safety < 128 {
        let len = buf[pos] as usize;
        if len == 0 {
            break;
        }
        // Compression pointer — bail.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        for &b in &buf[pos..pos + len] {
            if b.is_ascii() {
                out.push(b as char);
            }
        }
        pos += len;
        safety += 1;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_syn() {
        // Minimal Eth(IPv4=TCP) with SYN flag only.
        let mut frame = vec![0u8; 14 + 20 + 20];
        // EtherType = 0x0800 (IPv4)
        frame[12] = 0x08;
        frame[13] = 0x00;
        // IPv4: version=4, IHL=5
        frame[14] = 0x45;
        frame[23] = 6; // proto = TCP
        // src = 10.0.0.1
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
        // dst = 10.0.0.2
        frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
        // TCP: dst port = 443 at IP+2..IP+4
        frame[14 + 20 + 2] = 0x01;
        frame[14 + 20 + 3] = 0xbb; // 443
        // Data offset = 5 (20 bytes) at IP+12 high nibble
        frame[14 + 20 + 12] = 0x50;
        // Flags: SYN only at IP+13
        frame[14 + 20 + 13] = 0x02;

        let event = parse_event(&frame, Linktype::ETHERNET).expect("should parse SYN");
        match event {
            Event::Conn(ev) => {
                assert_eq!(ev.src_ip, "10.0.0.1");
                assert_eq!(ev.dst_ip, "10.0.0.2");
                assert_eq!(ev.dst_port, 443);
            }
            _ => panic!("expected ConnAttemptEvent"),
        }
    }

    #[test]
    fn parses_dns_query() {
        // Eth(IPv4=UDP) with DNS query for "example.com"
        let mut frame = vec![0u8; 14 + 20 + 8];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 17; // UDP
        frame[26..30].copy_from_slice(&[192, 168, 1, 1]);
        frame[30..34].copy_from_slice(&[8, 8, 8, 8]);
        // UDP dst port 53
        frame[14 + 20 + 2] = 0x00;
        frame[14 + 20 + 3] = 0x35;

        // DNS: 12-byte header, txid=0x1234, flags=0 (query), qdcount=1
        let dns_header = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        frame.extend(dns_header);
        // QNAME: "example.com\0" in DNS wire format
        frame.extend_from_slice(&[7]);
        frame.extend_from_slice(b"example");
        frame.extend_from_slice(&[3]);
        frame.extend_from_slice(b"com");
        frame.extend_from_slice(&[0]);
        // QTYPE/QCLASS — not parsed
        frame.extend_from_slice(&[0, 1, 0, 1]);

        let event = parse_event(&frame, Linktype::ETHERNET).expect("should parse DNS query");
        match event {
            Event::DnsQ(ev) => {
                assert_eq!(ev.txid, 0x1234);
                assert_eq!(ev.qname, "example.com");
                assert_eq!(ev.client_ip, "192.168.1.1");
                assert_eq!(ev.server_ip, "8.8.8.8");
            }
            _ => panic!("expected DnsQueryEvent"),
        }
    }

    #[test]
    fn skips_non_ip_ethertypes() {
        let mut frame = vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP
        assert!(parse_event(&frame, Linktype::ETHERNET).is_none());
    }

    #[test]
    fn parses_bsd_loopback_ipv4_tcp_syn() {
        // macOS lo0 frame: 4-byte AF_INET header, then IPv4+TCP.
        let mut frame = vec![0u8; 4 + 20 + 20];
        // AF_INET = 2, little-endian
        frame[0] = 0x02;
        // IPv4: version=4, IHL=5
        frame[4] = 0x45;
        frame[4 + 9] = 6; // TCP
        frame[4 + 12..4 + 16].copy_from_slice(&[127, 0, 0, 1]);
        frame[4 + 16..4 + 20].copy_from_slice(&[127, 0, 0, 1]);
        // TCP dst port 3001
        frame[4 + 20 + 2] = 0x0b;
        frame[4 + 20 + 3] = 0xb9;
        frame[4 + 20 + 12] = 0x50; // data offset
        frame[4 + 20 + 13] = 0x02; // SYN

        let event = parse_event(&frame, Linktype::NULL).expect("should parse loopback SYN");
        match event {
            Event::Conn(ev) => {
                assert_eq!(ev.dst_ip, "127.0.0.1");
                assert_eq!(ev.dst_port, 3001);
            }
            _ => panic!("expected ConnAttemptEvent"),
        }
    }

    #[test]
    fn parses_dns_response_with_nxdomain() {
        let mut frame = vec![0u8; 14 + 20 + 8];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[8, 8, 8, 8]);
        frame[30..34].copy_from_slice(&[192, 168, 1, 1]);
        // UDP src port 53
        frame[14 + 20] = 0x00;
        frame[14 + 20 + 1] = 0x35;

        // DNS: response (QR=1), rcode=3 (NXDOMAIN), qdcount=1
        let dns = vec![0xaa, 0xbb, 0x81, 0x83, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        frame.extend(dns);
        let event = parse_event(&frame, Linktype::ETHERNET).expect("should parse DNS response");
        match event {
            Event::DnsR(ev) => {
                assert_eq!(ev.txid, 0xaabb);
                assert_eq!(ev.rcode, 3);
                assert_eq!(ev.client_ip, "192.168.1.1");
                assert_eq!(ev.server_ip, "8.8.8.8");
            }
            _ => panic!("expected DnsResponseEvent"),
        }
    }
}
