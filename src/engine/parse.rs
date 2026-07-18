use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CompatReport {
    /// 0–100 rough compatibility score for HTTP features used.
    pub score: u8,
    pub supported_notes: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedTemplate {
    pub id: String,
    pub info_name: String,
    /// Nuclei `info.severity` (critical/high/medium/low/info/…).
    pub severity: String,
    pub http_requests: Vec<HttpRequest>,
    pub variables: HashMap<String, String>,
    pub stop_at_first_match: bool,
    pub raw_root: Value,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: Vec<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub raw: Vec<String>,
    pub matchers_condition: String,
    pub matchers: Vec<Matcher>,
    pub extractors: Vec<Extractor>,
    pub redirects: bool,
    pub max_redirects: usize,
    pub stop_at_first_match: bool,
    pub payloads: HashMap<String, Vec<String>>,
    pub attack: Option<String>,
    pub cookie_reuse: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub matcher_type: String,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub size: Vec<i64>,
    #[serde(default)]
    pub binary: Vec<String>,
    #[serde(default)]
    pub dsl: Vec<String>,
    #[serde(default = "default_or")]
    pub condition: String,
    #[serde(default = "default_body")]
    pub part: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub negative: bool,
    #[serde(default, rename = "case-insensitive")]
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Extractor {
    #[serde(rename = "type")]
    pub extractor_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_body")]
    pub part: String,
    #[serde(default)]
    pub group: usize,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub kval: Vec<String>,
    #[serde(default)]
    pub json: Vec<String>,
    #[serde(default)]
    pub xpath: Vec<String>,
    #[serde(default)]
    pub dsl: Vec<String>,
    #[serde(default)]
    pub internal: bool,
}

fn default_or() -> String {
    "or".into()
}
fn default_body() -> String {
    "body".into()
}

#[derive(Debug, Deserialize)]
struct RawTemplate {
    id: String,
    #[serde(default)]
    info: RawInfo,
    #[serde(default)]
    http: Vec<Value>,
    #[serde(default)]
    requests: Vec<Value>,
    #[serde(default)]
    variables: HashMap<String, Value>,
    #[serde(default, rename = "stop-at-first-match")]
    stop_at_first_match: bool,
}

#[derive(Debug, Default, Deserialize)]
struct RawInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    author: Value,
    #[serde(default)]
    severity: Value,
}

pub fn parse_template(yaml: &str) -> Result<ParsedTemplate, String> {
    let root: Value =
        serde_yaml::from_str(yaml).map_err(|e| format!("YAML Parse Error: {e}"))?;
    let raw: RawTemplate =
        serde_yaml::from_value(root.clone()).map_err(|e| format!("Template schema error: {e}"))?;

    let mut http_blocks = raw.http;
    if http_blocks.is_empty() {
        http_blocks = raw.requests;
    }

    let mut http_requests = Vec::new();
    for block in http_blocks {
        http_requests.push(parse_http_request(block)?);
    }

    let mut variables = HashMap::new();
    for (k, v) in raw.variables {
        variables.insert(k, value_to_string(&v));
    }

    Ok(ParsedTemplate {
        id: raw.id,
        info_name: raw.info.name,
        severity: value_to_string(&raw.info.severity).to_ascii_lowercase(),
        http_requests,
        variables,
        stop_at_first_match: raw.stop_at_first_match,
        raw_root: root,
    })
}

fn parse_http_request(block: Value) -> Result<HttpRequest, String> {
    #[derive(Deserialize)]
    struct RawReq {
        #[serde(default = "default_get")]
        method: String,
        #[serde(default)]
        path: Vec<String>,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        raw: Vec<String>,
        #[serde(default = "default_or", rename = "matchers-condition")]
        matchers_condition: String,
        #[serde(default)]
        matchers: Vec<Matcher>,
        #[serde(default)]
        extractors: Vec<Extractor>,
        #[serde(default)]
        redirects: bool,
        #[serde(default = "default_max_redirects", rename = "max-redirects")]
        max_redirects: usize,
        #[serde(default, rename = "stop-at-first-match")]
        stop_at_first_match: bool,
        #[serde(default)]
        payloads: HashMap<String, Value>,
        #[serde(default)]
        attack: Option<String>,
        #[serde(default = "default_true", rename = "cookie-reuse")]
        cookie_reuse: bool,
        #[serde(default, rename = "disable-cookie")]
        disable_cookie: bool,
    }

    fn default_get() -> String {
        "GET".into()
    }
    fn default_max_redirects() -> usize {
        10
    }
    fn default_true() -> bool {
        true
    }

    let raw: RawReq =
        serde_yaml::from_value(block).map_err(|e| format!("HTTP request parse error: {e}"))?;

    let mut payloads = HashMap::new();
    for (k, v) in raw.payloads {
        payloads.insert(k, value_to_string_list(&v));
    }

    let cookie_reuse = if raw.disable_cookie {
        false
    } else {
        raw.cookie_reuse
    };

    Ok(HttpRequest {
        method: raw.method,
        path: raw.path,
        headers: raw.headers,
        body: raw.body,
        raw: raw.raw,
        matchers_condition: raw.matchers_condition,
        matchers: raw.matchers,
        extractors: raw.extractors,
        redirects: raw.redirects,
        max_redirects: raw.max_redirects,
        stop_at_first_match: raw.stop_at_first_match,
        payloads,
        attack: raw.attack,
        cookie_reuse,
    })
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => serde_yaml::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn value_to_string_list(v: &Value) -> Vec<String> {
    match v {
        Value::Sequence(seq) => seq.iter().map(value_to_string).collect(),
        Value::String(s) => {
            // File reference like payloads from file — treat as single token list for now.
            if s.ends_with(".txt") || s.contains('/') {
                vec![format!("__FILE_REF__:{s}")]
            } else {
                vec![s.clone()]
            }
        }
        other => vec![value_to_string(other)],
    }
}

/// Analyze which features are used and how well we support them.
pub fn analyze_compatibility(parsed: &ParsedTemplate) -> CompatReport {
    let mut warnings = Vec::new();
    let mut supported = Vec::new();
    let mut score: i32 = 100;

    let root = &parsed.raw_root;
    for key in ["dns", "tcp", "network", "ssl", "websocket", "file", "headless", "code", "javascript", "whois"]
    {
        if root.get(key).is_some() {
            warnings.push(format!("Unsupported protocol: {key}"));
            score -= 25;
        }
    }
    if root.get("flow").is_some() {
        warnings.push("Unsupported: flow".into());
        score -= 15;
    }
    if root.get("workflows").is_some() {
        warnings.push("Unsupported: workflows".into());
        score -= 20;
    }

    if parsed.http_requests.is_empty() {
        if warnings.is_empty() {
            warnings.push("No http/requests blocks found".into());
        }
        score -= 40;
    } else {
        supported.push("http/requests".into());
    }

    for (i, req) in parsed.http_requests.iter().enumerate() {
        if !req.raw.is_empty() {
            supported.push(format!("req[{i}].raw"));
        }
        if !req.headers.is_empty() {
            supported.push(format!("req[{i}].headers"));
        }
        if req.body.is_some() {
            supported.push(format!("req[{i}].body"));
        }
        if !req.payloads.is_empty() {
            for vals in req.payloads.values() {
                if vals.iter().any(|v| v.starts_with("__FILE_REF__:")) {
                    warnings.push(format!(
                        "req[{i}]: payload file references not loaded (inline lists only)"
                    ));
                    score -= 10;
                }
            }
            supported.push(format!("req[{i}].payloads"));
        }
        if req.redirects {
            supported.push(format!("req[{i}].redirects"));
        }

        for m in &req.matchers {
            match m.matcher_type.as_str() {
                "status" | "word" | "regex" | "size" | "binary" | "dsl" => {
                    supported.push(format!("matcher:{}", m.matcher_type));
                }
                "xpath" => {
                    warnings.push("matcher type xpath not implemented".into());
                    score -= 8;
                }
                other => {
                    warnings.push(format!("matcher type '{other}' not implemented"));
                    score -= 8;
                }
            }
        }
        for e in &req.extractors {
            match e.extractor_type.as_str() {
                "regex" | "kval" | "json" | "dsl" => {
                    supported.push(format!("extractor:{}", e.extractor_type));
                }
                "xpath" => {
                    warnings.push("extractor type xpath not implemented".into());
                    score -= 5;
                }
                other => {
                    warnings.push(format!("extractor type '{other}' not implemented"));
                    score -= 5;
                }
            }
            if !e.xpath.is_empty() && e.extractor_type != "xpath" {
                // ignore
            }
        }
    }

    // Dedup notes
    supported.sort();
    supported.dedup();
    warnings.sort();
    warnings.dedup();

    CompatReport {
        score: score.clamp(0, 100) as u8,
        supported_notes: supported,
        warnings,
    }
}

impl CompatReport {
    pub fn summary_line(&self) -> String {
        format!(
            "Compat {}% — supported: {}{}",
            self.score,
            if self.supported_notes.is_empty() {
                "none".into()
            } else {
                self.supported_notes.join(", ")
            },
            if self.warnings.is_empty() {
                String::new()
            } else {
                format!(" | warnings: {}", self.warnings.join("; "))
            }
        )
    }
}
