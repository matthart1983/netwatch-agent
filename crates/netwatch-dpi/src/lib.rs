//! Metadata-only classification. No stream reassembly, payload export or decryption.
//! Incomplete/unsupported packets return `None`; callers retain transport metadata.
#![forbid(unsafe_code)]
mod dns;
mod http;
mod ja4;
mod redact;
mod tls;
pub use dns::extract_dns_answers;
pub use redact::Redactor;
use serde::Serialize;

pub const MAX_INPUT: usize = 16_384;
pub const MAX_TEXT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AppProtocol {
    Tls {
        sni: Option<String>,
        alpn: Option<String>,
        ja4: Option<String>,
        ech: bool,
    },
    Http {
        method: String,
        host: Option<String>,
        status: Option<u16>,
    },
    Dns {
        qname: String,
        qtype: u16,
    },
    Ssh {
        version: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassifiedMeta {
    pub app: AppProtocol,
    pub sni: Option<String>,
    pub host: Option<String>,
    pub http_method: Option<String>,
    pub dns_qname: Option<String>,
    pub alpn: Option<String>,
    pub ja4: Option<String>,
}

trait Classifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol>;
}

pub(crate) fn sanitize(s: &str) -> String {
    Redactor::redacting().redact_text(s).into_owned()
}

/// Classify one complete protocol message within a captured packet. TCP DNS
/// requires a complete two-byte-length-prefixed message; no guessing/reassembly.
pub fn classify_meta(
    payload: &[u8],
    is_tcp: bool,
    src_port: u16,
    dst_port: u16,
) -> Option<ClassifiedMeta> {
    let payload = &payload[..payload.len().min(MAX_INPUT)];
    let dns_port =
        src_port == 53 || dst_port == 53 || (!is_tcp && (src_port == 5353 || dst_port == 5353));
    let app = if dns_port {
        dns::classify(dns_message(payload, is_tcp)?)?
    } else if is_tcp {
        if payload.starts_with(b"SSH-") {
            // Retain only protocol + software identification, never banner comments.
            let end = payload.iter().position(|b| *b == b'\n')?;
            if end > 254 {
                return None;
            }
            let line = std::str::from_utf8(&payload[..end])
                .ok()?
                .trim_end_matches('\r');
            let version = line.split_whitespace().next()?;
            if !(version.starts_with("SSH-2.0-") || version.starts_with("SSH-1.99-"))
                || version.ends_with('-')
            {
                return None;
            }
            AppProtocol::Ssh {
                version: sanitize(version),
            }
        } else if let Some(http) = http::classify(payload) {
            http
        } else {
            tls::TlsClassifier.classify(payload, true)?
        }
    } else {
        return None;
    };
    let mut meta = ClassifiedMeta {
        app,
        sni: None,
        host: None,
        http_method: None,
        dns_qname: None,
        alpn: None,
        ja4: None,
    };
    match &meta.app {
        AppProtocol::Tls { sni, alpn, ja4, .. } => {
            meta.sni = sni.clone();
            meta.alpn = alpn.clone();
            meta.ja4 = ja4.clone();
        }
        AppProtocol::Http { method, host, .. } => {
            meta.http_method = Some(method.clone());
            meta.host = host.clone();
        }
        AppProtocol::Dns { qname, .. } => meta.dns_qname = Some(qname.clone()),
        AppProtocol::Ssh { .. } => {}
    }
    Some(meta)
}

/// Normalize DNS framing explicitly, shared with the agent's answer extraction.
pub fn dns_message(payload: &[u8], is_tcp: bool) -> Option<&[u8]> {
    if !is_tcp {
        return (payload.len() <= MAX_INPUT).then_some(payload);
    }
    let n = u16::from_be_bytes(payload.get(..2)?.try_into().ok()?) as usize;
    if n > MAX_INPUT {
        return None;
    }
    payload.get(2..2 + n)
}
