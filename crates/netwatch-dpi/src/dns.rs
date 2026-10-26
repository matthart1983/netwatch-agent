use crate::{sanitize, AppProtocol, MAX_INPUT};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
const MAX_RECORDS: usize = 64;
fn u16_at(p: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes(p.get(pos..pos + 2)?.try_into().ok()?))
}

// At most 128 steps; backwards-only compression pointers preclude cycles.
fn name(p: &[u8], pos: &mut usize) -> Option<String> {
    let mut cursor = *pos;
    let mut jumped = false;
    let mut result = String::new();
    for _ in 0..128 {
        let n = *p.get(cursor)? as usize;
        if n & 0xc0 == 0xc0 {
            let target = ((n & 0x3f) << 8) | (*p.get(cursor + 1)? as usize);
            if target < 12 || target >= cursor {
                return None;
            }
            if !jumped {
                *pos = cursor + 2;
                jumped = true;
            }
            cursor = target;
        } else if n == 0 {
            if !jumped {
                *pos = cursor + 1;
            }
            return Some(result);
        } else {
            if n > 63 {
                return None;
            }
            let label = p.get(cursor + 1..cursor + 1 + n)?;
            if !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(b))
            {
                return None;
            }
            if !result.is_empty() {
                result.push('.');
            }
            result.push_str(std::str::from_utf8(label).ok()?);
            if result.len() > 253 {
                return None;
            }
            cursor += n + 1;
        }
    }
    None
}
fn header(p: &[u8]) -> Option<(usize, usize)> {
    if p.len() < 12 || p.len() > MAX_INPUT || p[2] & 0x78 != 0 {
        return None;
    }
    let q = u16_at(p, 4)? as usize;
    let a = u16_at(p, 6)? as usize;
    (q <= MAX_RECORDS && a <= MAX_RECORDS).then_some((q, a))
}
pub fn classify(p: &[u8]) -> Option<AppProtocol> {
    let (q, _) = header(p)?;
    if q == 0 {
        return None;
    }
    let mut pos = 12;
    let qname = name(p, &mut pos)?;
    let qtype = u16_at(p, pos)?;
    if u16_at(p, pos + 2)? & 0x7fff != 1 {
        return None;
    }
    Some(AppProtocol::Dns {
        qname: sanitize(&qname),
        qtype,
    })
}
/// Extract address records from a complete raw DNS response (no TCP prefix).
/// Malformed answers invalidate the whole result; no partial poisoned mappings.
pub fn extract_dns_answers(p: &[u8]) -> Vec<(String, IpAddr)> {
    fn parse(p: &[u8]) -> Option<Vec<(String, IpAddr)>> {
        let (q, a) = header(p)?;
        if p[2] & 0x80 == 0 || p[2] & 0x02 != 0 || p[3] & 0x0f != 0 {
            return Some(Vec::new());
        }
        let mut pos = 12;
        for _ in 0..q {
            name(p, &mut pos)?;
            p.get(pos..pos + 4)?;
            pos += 4;
        }
        let mut out = Vec::new();
        for _ in 0..a {
            let owner = name(p, &mut pos)?;
            let kind = u16_at(p, pos)?;
            let class = u16_at(p, pos + 2)? & 0x7fff;
            let len = u16_at(p, pos + 8)? as usize;
            pos += 10;
            let data = p.get(pos..pos + len)?;
            if class == 1 {
                let ip = match kind {
                    1 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?))),
                    28 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
                    _ => None,
                };
                if let Some(ip) = ip {
                    out.push((sanitize(&owner), ip));
                }
            }
            pos += len;
        }
        Some(out)
    }
    parse(p).unwrap_or_default()
}
