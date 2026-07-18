//! Non-HTTP protocol placeholders.
//!
//! LogosCyber's engine is HTTP-first. Official nuclei-templates may also contain
//! `dns`, `tcp`/`network`, `ssl`, `websocket`, `file`, `headless`, `code`,
//! `javascript`, and `whois` blocks. Those are intentionally not executed yet;
//! [`unsupported_protocol_keys`] surfaces them so the UI never silently reports Clean.

use serde_yaml::Value;

pub const PROTOCOL_KEYS: &[&str] = &[
    "dns",
    "tcp",
    "network",
    "ssl",
    "websocket",
    "file",
    "headless",
    "code",
    "javascript",
    "whois",
];

/// Return protocol keys present on the template root that this engine does not run.
pub fn unsupported_protocol_keys(root: &Value) -> Vec<String> {
    let mut found = Vec::new();
    for key in PROTOCOL_KEYS {
        if root.get(key).is_some() {
            found.push((*key).to_string());
        }
    }
    found
}

/// Future extension point: route a protocol block to a dedicated executor.
pub fn describe_future_support() -> &'static str {
    "Non-HTTP executors (DNS/TCP/SSL/…) will be separate modules after HTTP parity stabilizes."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_dns() {
        let v: Value = serde_yaml::from_str("dns:\n  - name: x\n").unwrap();
        assert_eq!(unsupported_protocol_keys(&v), vec!["dns".to_string()]);
    }
}
