//! Nuclei-compatible HTTP template engine for authorized vulnerability assessment.
//!
//! Phased compatibility with official `nuclei-templates` (HTTP-first).
//! Non-HTTP protocols are detected and reported; see [`protocols`].

mod extractors;
mod http_exec;
mod matchers;
mod parse;
mod payloads;
pub mod protocols;
mod vars;

pub use parse::{analyze_compatibility, parse_template, CompatReport, ParsedTemplate};
pub use protocols::unsupported_protocol_keys;

use payloads::expand_payload_iterations;
use vars::BuiltinVars;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub template_id: String,
    pub target: String,
    pub matched: bool,
    /// Nuclei severity string from the template (`info.severity`).
    pub severity: String,
    pub details: String,
    pub extracted_data: Vec<String>,
    pub warnings: Vec<String>,
    pub compat: CompatReport,
}

/// Parse + scan a single Nuclei-compatible YAML template against `target`.
pub async fn run_scan(
    target: &str,
    template_yaml: &str,
    proxy_url: Option<String>,
) -> Result<ScanResult, String> {
    let parsed = parse_template(template_yaml)?;
    let compat = analyze_compatibility(&parsed);
    let mut warnings = compat.warnings.clone();

    if parsed.http_requests.is_empty() {
        let proto = unsupported_protocol_keys(&parsed.raw_root);
        if !proto.is_empty() {
            warnings.push(format!(
                "Unsupported protocol block(s): {}. HTTP-only engine — see engine::protocols.",
                proto.join(", ")
            ));
        }
        return Ok(ScanResult {
            template_id: parsed.id.clone(),
            target: target.to_string(),
            matched: false,
            severity: parsed.severity.clone(),
            details: if warnings.is_empty() {
                "No HTTP requests found in template.".to_string()
            } else {
                format!("Skipped. {}", warnings.join(" | "))
            },
            extracted_data: Vec::new(),
            warnings,
            compat,
        });
    }

    let builtins = BuiltinVars::from_target(target)?;
    let mut dynamic = parsed.variables.clone();
    let mut all_extracted = Vec::new();
    let mut last_match_details = String::new();
    let mut any_matched = false;

    let client = http_exec::build_client(proxy_url.as_deref(), true, 10)?;

    for req in &parsed.http_requests {
        let iterations = expand_payload_iterations(req)?;
        if iterations.len() > 1 {
            warnings.push(format!(
                "Expanded {} payload iteration(s) for request.",
                iterations.len()
            ));
        }

        for payload_vars in iterations {
            let mut scope = dynamic.clone();
            for (k, v) in &payload_vars {
                scope.insert(k.clone(), v.clone());
            }

            let responses = http_exec::execute_request(
                &client,
                req,
                &builtins,
                &scope,
            )
            .await?;

            for resp in &responses {
                let matched = matchers::evaluate_matchers(req, resp, &scope)?;
                let extracted = extractors::run_extractors(req, resp, &mut scope)?;

                for (name, value, internal) in &extracted {
                    if !internal {
                        all_extracted.push(format!("{name}: {value}"));
                    }
                    // Always store for chaining (internal and public names).
                    scope.insert(name.clone(), value.clone());
                    dynamic.insert(name.clone(), value.clone());
                }

                if matched {
                    any_matched = true;
                    last_match_details = format!(
                        "FINDING: {} on {} (status {})",
                        parsed.id, resp.final_url, resp.status
                    );
                    if !all_extracted.is_empty() {
                        last_match_details.push_str(&format!(
                            "\nExtracted:\n  - {}",
                            all_extracted.join("\n  - ")
                        ));
                    }
                    if req.stop_at_first_match || parsed.stop_at_first_match {
                        return Ok(ScanResult {
                            template_id: parsed.id.clone(),
                            target: target.to_string(),
                            matched: true,
                            severity: parsed.severity.clone(),
                            details: last_match_details,
                            extracted_data: all_extracted,
                            warnings,
                            compat,
                        });
                    }
                }
            }
        }
    }

    Ok(ScanResult {
        template_id: parsed.id.clone(),
        target: target.to_string(),
        matched: any_matched,
        severity: parsed.severity.clone(),
        details: if any_matched {
            last_match_details
        } else if !warnings.is_empty() {
            format!(
                "Clean (no match). Notes: {}",
                warnings.join(" | ")
            )
        } else {
            "Clean. No vulnerabilities matched.".to_string()
        },
        extracted_data: all_extracted,
        warnings,
        compat,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_detects_http_key() {
        let yaml = r#"
id: git-config
info:
  name: Git Config
  author: pdteam
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "[core]"
      - type: status
        status:
          - 200
"#;
        let parsed = parse_template(yaml).expect("parse");
        assert_eq!(parsed.http_requests.len(), 1);
        let report = analyze_compatibility(&parsed);
        assert!(report.score >= 70);
    }

    #[test]
    fn legacy_requests_still_parse() {
        let yaml = r#"
id: bak
info:
  name: Bak
  author: user
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/wp-config.php.bak"
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
"#;
        let parsed = parse_template(yaml).expect("parse");
        assert_eq!(parsed.http_requests.len(), 1);
    }

    #[test]
    fn author_as_list_ok() {
        let yaml = r#"
id: multi-author
info:
  name: Multi
  author:
    - a
    - b
  severity: low
  tags:
    - exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
"#;
        parse_template(yaml).expect("parse with author list");
    }

    #[test]
    fn unsupported_dns_reported() {
        let yaml = r#"
id: dns-only
info:
  name: DNS
  author: x
  severity: info
dns:
  - name: "{{FQDN}}"
    type: A
    matchers:
      - type: word
        words: ["1.1.1.1"]
"#;
        let parsed = parse_template(yaml).expect("parse");
        assert!(parsed.http_requests.is_empty());
        let keys = unsupported_protocol_keys(&parsed.raw_root);
        assert!(keys.contains(&"dns".to_string()));
    }

    #[test]
    fn matchers_condition_and_logic_unit() {
        use crate::engine::http_exec::HttpResponse;
        use crate::engine::parse::HttpRequest;
        use std::collections::HashMap;

        let req = HttpRequest {
            method: "GET".into(),
            path: vec!["{{BaseURL}}/".into()],
            headers: HashMap::new(),
            body: None,
            raw: vec![],
            matchers_condition: "and".into(),
            matchers: vec![
                parse::Matcher {
                    matcher_type: "status".into(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    size: vec![],
                    binary: vec![],
                    dsl: vec![],
                    condition: "or".into(),
                    part: "body".into(),
                    name: String::new(),
                    negative: false,
                    case_insensitive: false,
                },
                parse::Matcher {
                    matcher_type: "word".into(),
                    words: vec!["hello".into()],
                    regex: vec![],
                    status: vec![],
                    size: vec![],
                    binary: vec![],
                    dsl: vec![],
                    condition: "or".into(),
                    part: "body".into(),
                    name: String::new(),
                    negative: false,
                    case_insensitive: false,
                },
            ],
            extractors: vec![],
            redirects: false,
            max_redirects: 0,
            stop_at_first_match: false,
            payloads: HashMap::new(),
            attack: None,
            cookie_reuse: true,
        };

        let ok = HttpResponse {
            status: 200,
            headers_text: String::new(),
            headers_map: HashMap::new(),
            body: "hello world".into(),
            body_bytes: b"hello world".to_vec(),
            final_url: "http://x/".into(),
        };
        let bad = HttpResponse {
            status: 200,
            headers_text: String::new(),
            headers_map: HashMap::new(),
            body: "nope".into(),
            body_bytes: b"nope".to_vec(),
            final_url: "http://x/".into(),
        };
        let scope = HashMap::new();
        assert!(matchers::evaluate_matchers(&req, &ok, &scope).unwrap());
        assert!(!matchers::evaluate_matchers(&req, &bad, &scope).unwrap());
    }
}
