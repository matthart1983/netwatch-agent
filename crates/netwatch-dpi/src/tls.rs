// Adapted from netwatch; see NOTICE and LICENSE.
use super::ja4::{self, Ja4Input};
use super::{AppProtocol, Classifier};
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
};
fn has_ech(exts: &[TlsExtension]) -> bool {
    exts.iter()
        .any(|e| matches!(e, TlsExtension::Unknown(t, _) if t.0 == 0xfe0d))
}
pub struct TlsClassifier;

impl Classifier for TlsClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if !is_tcp {
            return None;
        }
        // Quick reject before invoking the parser: TLS records always
        // start with content_type = 0x16 (handshake) followed by major
        // protocol version 0x03.
        if payload.len() < 5 || payload[0] != 0x16 || payload[1] != 0x03 {
            return None;
        }

        let (_, record) = parse_tls_plaintext(payload).ok()?;
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                let mut sni: Option<String> = None;
                let mut alpn: Option<String> = None;
                let mut alpn_first_bytes: Option<&[u8]> = None;
                let mut ech = false;
                // Collected for JA4: extension type codes (in wire order),
                // signature algorithms (wire order), and the negotiated
                // TLS version (highest from supported_versions if present,
                // else falls back to the ClientHello legacy version).
                let mut ext_type_codes: Vec<u16> = Vec::new();
                let mut sig_algs: Vec<u16> = Vec::new();
                let mut tls_version: u16 = ch.version.0;
                if let Some(ext_data) = ch.ext {
                    ext_type_codes = ja4::extension_type_codes(ext_data);
                    if let Ok((_, exts)) = parse_tls_extensions(ext_data) {
                        ech = has_ech(&exts);
                        for ext in &exts {
                            match ext {
                                TlsExtension::SNI(entries) => {
                                    sni = entries
                                        .first()
                                        .and_then(|(_, host)| std::str::from_utf8(host).ok())
                                        .map(crate::sanitize);
                                }
                                TlsExtension::ALPN(protos) => {
                                    if let Some(first) = protos.first() {
                                        alpn_first_bytes = Some(*first);
                                        alpn = std::str::from_utf8(first).ok().map(crate::sanitize);
                                    }
                                }
                                TlsExtension::SignatureAlgorithms(algs) => {
                                    sig_algs = algs.clone();
                                }
                                TlsExtension::SupportedVersions(vers) => {
                                    // The TLS 1.3 ClientHello carries
                                    // legacy_version = 0x0303 and the real
                                    // version list in this extension. Pick
                                    // the highest non-GREASE entry.
                                    let highest = vers
                                        .iter()
                                        .map(|v| v.0)
                                        .filter(|v| !ja4::is_grease(*v))
                                        .max();
                                    if let Some(v) = highest {
                                        tls_version = v;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                let cipher_codes: Vec<u16> = ch.ciphers.iter().map(|c| c.0).collect();
                let ja4 = Some(ja4::compute_ja4(&Ja4Input {
                    is_quic: false,
                    tls_version,
                    sni_present: sni.is_some(),
                    alpn_first: alpn_first_bytes,
                    ciphers: &cipher_codes,
                    extensions: &ext_type_codes,
                    signature_algorithms: &sig_algs,
                }));
                return Some(AppProtocol::Tls {
                    sni,
                    alpn,
                    ech,
                    ja4,
                });
            }
        }
        None
    }
}
