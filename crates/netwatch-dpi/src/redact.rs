use crate::{MAX_INPUT, MAX_TEXT};
use regex::Regex;
use std::{borrow::Cow, sync::OnceLock};

/// Defense in depth for metadata. This does not make hostnames non-sensitive.
/// No bypass/raw mode: callers cannot accidentally turn source redaction off.
pub struct Redactor;
impl Redactor {
    pub fn redacting() -> Self {
        Self
    }
    pub fn redact_text<'a>(&self, input: &'a str) -> Cow<'a, str> {
        static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
        let patterns = PATTERNS.get_or_init(|| [
            r"(?i)\b(?:https?|wss?)://[^\s]+",
            r"(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:[^\r\n]*",
            r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9+/_.=\-]+",
            r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?token)\s*[=:]\s*[^\s,;]+",
            r"\b(?:nw_ak_|sk-|sk_|ghp_|github_pat_)[A-Za-z0-9_\-]+",
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?",
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]+@[A-Za-z0-9.\-]+",
            r"\b[A-Za-z0-9_\-]{32,}\b",
        ].iter().map(|p| Regex::new(p).expect("constant regex")).collect());
        // Reject oversized input entirely; truncating a credential before
        // redaction could leave an unrecognizable prefix of a secret.
        if input.len() > MAX_INPUT {
            return Cow::Borrowed("[redacted: oversized]");
        }
        let mut text: Cow<'_, str> = Cow::Borrowed(input);
        for re in patterns {
            text = Cow::Owned(re.replace_all(&text, "[redacted]").into_owned());
        }
        let clean: String = text.chars().filter(|c| !c.is_control() && !matches!(*c,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'
        )).collect();
        // Re-run after removing invisible characters that can split a token.
        let mut clean = clean;
        for re in patterns {
            clean = re.replace_all(&clean, "[redacted]").into_owned();
        }
        let mut end = clean.len().min(MAX_TEXT);
        while !clean.is_char_boundary(end) {
            end -= 1;
        }
        clean.truncate(end);
        Cow::Owned(clean)
    }
}
