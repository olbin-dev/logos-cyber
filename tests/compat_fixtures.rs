//! Integration-style parse/compat tests using official-style fixtures.

use logos_cyber::engine::{analyze_compatibility, parse_template, unsupported_protocol_keys};
use std::fs;
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

// Re-export helpers through a thin wrapper — binary crate tests need the lib.
// When only a binary exists, we compile these as unit tests in engine instead.
// This file is used once `lib.rs` exposes `engine`.

#[test]
fn fixture_git_config_parses_with_http_key() {
    let yaml = fixture("http_git_config.yaml");
    let parsed = parse_template(&yaml).expect("parse git config fixture");
    assert_eq!(parsed.id, "git-config-exposure");
    assert_eq!(parsed.http_requests.len(), 1);
    assert_eq!(parsed.http_requests[0].matchers_condition, "and");
    let report = analyze_compatibility(&parsed);
    assert!(report.score >= 80, "score={}", report.score);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

#[test]
fn fixture_dns_reports_unsupported() {
    let yaml = fixture("dns_only.yaml");
    let parsed = parse_template(&yaml).expect("parse");
    assert!(parsed.http_requests.is_empty());
    let keys = unsupported_protocol_keys(&parsed.raw_root);
    assert!(keys.contains(&"dns".to_string()));
    let report = analyze_compatibility(&parsed);
    assert!(report.warnings.iter().any(|w| w.contains("dns")));
}
