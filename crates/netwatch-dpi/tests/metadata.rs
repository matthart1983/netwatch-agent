use netwatch_dpi::{
    classify_meta, dns_message, extract_dns_answers, AppProtocol, Redactor, MAX_TEXT,
};
use proptest::prelude::*;

fn dns_response() -> Vec<u8> {
    let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
    p.extend_from_slice(b"\x07example\x03com\0\0\x01\0\x01");
    p.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
    p.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
    p.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    p
}

#[test]
fn http_allowlist_never_serializes_request_target_headers_or_body() {
    let p = b"POST /SECRET_PATH?token=SECRET_QUERY HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer SECRET_AUTH\r\nCookie: SECRET_COOKIE\r\n\r\nSECRET_BODY";
    let m = classify_meta(p, true, 12345, 80).unwrap();
    let json = serde_json::to_string(&m).unwrap();
    assert!(!json.contains("SECRET_"), "{json}");
    assert_eq!(m.host.as_deref(), Some("example.com"));
    assert_eq!(m.http_method.as_deref(), Some("POST"));
    assert!(matches!(
        classify_meta(b"HTTP/1.1 404 Not Found\r\n", true, 80, 12345)
            .unwrap()
            .app,
        AppProtocol::Http {
            status: Some(404),
            ..
        }
    ));
}
#[test]
fn http_requires_complete_headers_and_valid_authority() {
    for p in [
        b"GET / HTTP/1.1\r\nHost: partial".as_slice(),
        b"GET / HTTP/1.1\r\nHost: user:pass@example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
    ] {
        assert!(classify_meta(p, true, 12345, 80).is_none());
    }
    assert!(classify_meta(b"GET / HTTP/1.0\r\n\r\n", true, 12345, 80).is_some());
}
#[test]
fn dns_compressed_answers_and_tcp_framing() {
    let p = dns_response();
    let out = extract_dns_answers(&p);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].0, "example.com");
    assert_eq!(out[0].1.to_string(), "192.0.2.1");
    assert_eq!(out[1].1.to_string(), "2001:db8::1");
    let mut tcp = (p.len() as u16).to_be_bytes().to_vec();
    tcp.extend(&p);
    assert!(matches!(
        classify_meta(&tcp, true, 53, 12345).unwrap().app,
        AppProtocol::Dns { .. }
    ));
    assert_eq!(extract_dns_answers(dns_message(&tcp, true).unwrap()), out);
    tcp.pop();
    assert!(classify_meta(&tcp, true, 53, 12345).is_none());
    assert!(classify_meta(&p, false, 9000, 9001).is_none());
}
#[test]
fn dns_rejects_cycles_truncation_and_bad_lengths() {
    let p = dns_response();
    for len in 0..p.len() {
        assert!(extract_dns_answers(&p[..len]).is_empty());
    }
    let mut cycle = p.clone();
    cycle[12] = 0xc0;
    cycle[13] = 12;
    assert!(extract_dns_answers(&cycle).is_empty());
    assert!(classify_meta(&cycle, false, 53, 1).is_none());
    let mut forward = p.clone();
    forward[12] = 0xc0;
    forward[13] = 14;
    assert!(extract_dns_answers(&forward).is_empty());
    let mut bad = p.clone();
    bad[6] = 255;
    bad[7] = 255;
    assert!(extract_dns_answers(&bad).is_empty());
    let mut query = p.clone();
    query[2] = 0;
    assert!(extract_dns_answers(&query).is_empty());
}
#[test]
fn tls_fixture_and_every_truncation() {
    let p = include_bytes!("fixtures/client-hello.bin");
    let m = classify_meta(p, true, 45000, 443).unwrap();
    assert_eq!(m.sni.as_deref(), Some("example.com"));
    assert!(m.ja4.as_ref().is_some_and(|j| j.starts_with("t13")));
    for len in 0..p.len() {
        assert!(
            classify_meta(&p[..len], true, 45000, 443).is_none(),
            "length={len}"
        );
    }
    assert!(classify_meta(p, false, 45000, 443).is_none());
}
#[test]
fn ssh_drops_comments_and_requires_complete_identification() {
    let m = classify_meta(b"SSH-2.0-OpenSSH_9.0 SECRET_COMMENT\r\n", true, 22, 30000).unwrap();
    assert!(matches!(m.app,AppProtocol::Ssh { version } if version == "SSH-2.0-OpenSSH_9.0"));
    assert!(classify_meta(b"SSH-2.0-OpenSSH", true, 22, 30000).is_none());
}
#[test]
fn redaction_sanitizes_secrets_and_bounds_text() {
    let r = Redactor::redacting();
    for p in [
        "Authorization: Bearer SECRET_AUTH",
        "Cookie: SECRET_COOKIE",
        "password=SECRET_PASSWORD",
        "nw_ak_SECRET_KEY",
        "https://example.com/SECRET_PATH",
        "user@example.com",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
        "tok\u{200b}en=SECRET_TOKEN",
    ] {
        let out = r.redact_text(p);
        assert!(!out.contains("SECRET_"), "{out}");
        assert!(out.contains("[redacted]"), "{out}");
    }
    assert_eq!(r.redact_text("example.com"), "example.com");
    assert_eq!(r.redact_text("hello\u{202e}\nworld"), "helloworld");
    assert!(r.redact_text(&"é".repeat(1000)).len() <= MAX_TEXT);
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn arbitrary_packets_are_bounded(data in prop::collection::vec(any::<u8>(),0..4096), tcp in any::<bool>(), port in any::<u16>()) {
        let _=classify_meta(&data,tcp,port,53);
        let _=classify_meta(&data,tcp,port,443);
        let out=extract_dns_answers(&data);
        prop_assert!(out.len() <= 64);
        for (name,_) in out { prop_assert!(name.len() <= MAX_TEXT); }
    }
    #[test]
    fn arbitrary_unicode_redaction_is_bounded(s in ".{0,1024}") {
        let r=Redactor::redacting();
        let out=r.redact_text(&s);
        prop_assert!(out.len() <= MAX_TEXT);
        prop_assert!(!out.chars().any(char::is_control));
    }
}
