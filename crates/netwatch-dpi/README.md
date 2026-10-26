# NetWatch DPI metadata library

An in-tree replacement for the unpublished `../netwatch-dpi` dependency used by
the capture agent. The agent builds from one checkout. This crate has no socket,
filesystem, capture-permission or decryption responsibilities.

## Contract

- `classify_meta(payload, is_tcp, source_port, destination_port)` returns the
  agent's `ClassifiedMeta`/`AppProtocol` contract, or `None` for unknown/incomplete
  messages. HTTP returns only method, Host and response status; TLS ClientHello
  returns SNI, ALPN, JA4 and ECH presence; DNS returns question name/type; SSH
  returns protocol/software identification without banner comments.
- `dns_message(payload, is_tcp)` explicitly removes a complete DNS-over-TCP
  length prefix. There is no TCP reassembly. The agent uses the normalized bytes
  both for classification and answer extraction.
- `extract_dns_answers(raw_dns)` extracts IN A/AAAA records from successful,
  non-truncated responses, with bounded compression decoding. Names are answer
  owners; CNAME aliases are not attributed to the original question. Malformed
  responses produce no mappings. These labels are observations, not DNSSEC proof.
- `Redactor::redacting().redact_text(text)` bounds and sanitizes Unicode text and
  masks recognized credentials, URLs, email addresses and long token-like strings.
  It has no raw mode. Redaction is defense in depth: hostnames and protocol
  identifiers still contain potentially sensitive metadata.

Output types cannot carry request paths, query strings, arbitrary headers,
application bodies, decrypted data or session keys. The agent serializes these
allowlisted fields plus transport headers. A short snaplen is a resource limit,
not a privacy boundary: payload bytes can exist in local capture memory.

## Limits and unsupported traffic

Input inspection is limited to 16 KiB; emitted free text to 256 UTF-8 bytes.
DNS names are limited to 253 bytes, record counts to 64, pointer walks to 128
steps. DNS classification is port-gated to 53 and UDP 5353. Incomplete DNS/TLS
messages are not reassembled. DNS labels outside ASCII letters/digits/hyphens/
underscores are rejected. HTTP requires a complete header block; SSH requires
a complete identification line. TLS application data, QUIC/HTTP3, DoH/DoT
contents and application stream reconstruction are not supported.

TLS SNI with ECH is the outer name; inner destinations are unavailable. The ECH
flag is present in the library contract, but the existing Cloud label UI does
not yet distinguish it. The agent supports Ethernet and BSD loopback frames;
Linux cooked (`any`), VLAN frames, IP reassembly and IPv6 extension-header
walking are not implemented. Select Fedora's physical uplink interface.

## Validation

Run `cargo test --workspace --locked` from the agent root. Tests include protocol
fixtures, all TLS fixture truncations, malformed DNS/compression, credential
exclusion and randomized byte/Unicode property tests. Agent integration tests
read a generated PCAP through libpcap and inspect outgoing JSON, and exercise
failed-worker retries over a real loopback WebSocket connection. These tests
require no elevated capture permissions or production credentials.

`NOTICE` pins the source of the adapted TLS/JA4 code and TLS fixture. `LICENSE`
retains the original MIT attribution.
