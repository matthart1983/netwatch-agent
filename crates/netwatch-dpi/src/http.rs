use crate::{sanitize, AppProtocol};

pub fn classify(payload: &[u8]) -> Option<AppProtocol> {
    let end = payload.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&payload[..end]).ok()?;
    let parts: Vec<_> = line.split(' ').collect();
    if matches!(parts.first(), Some(&"HTTP/1.0" | &"HTTP/1.1")) {
        let status = parts.get(1)?;
        if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let status: u16 = status.parse().ok()?;
        return (100..=599).contains(&status).then(|| AppProtocol::Http {
            method: "RESPONSE".into(),
            host: None,
            status: Some(status),
        });
    }
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") || parts[1].is_empty() {
        return None;
    }
    let method = parts[0];
    if ![
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
    ]
    .contains(&method)
    {
        return None;
    }
    let headers_end = payload.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&payload[end + 2..headers_end.max(end + 2)]).ok()?;
    let mut host = None;
    for line in headers.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                if host.is_some() {
                    return None;
                }
                let value = value.trim();
                // Authority only: no userinfo, paths, escapes or control bytes.
                if value.is_empty()
                    || value.len() > 253
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
                {
                    return None;
                }
                host = Some(sanitize(value));
            }
        }
    }
    Some(AppProtocol::Http {
        method: method.into(),
        host,
        status: None,
    })
}
