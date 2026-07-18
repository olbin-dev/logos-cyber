use crate::engine::http_exec::HttpResponse;
use crate::engine::parse::{Extractor, HttpRequest};
use regex::Regex;
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// Returns list of (name, value, internal).
pub fn run_extractors(
    req: &HttpRequest,
    resp: &HttpResponse,
    _scope: &mut HashMap<String, String>,
) -> Result<Vec<(String, String, bool)>, String> {
    let mut out = Vec::new();
    for ext in &req.extractors {
        let mut values = match ext.extractor_type.as_str() {
            "regex" => extract_regex(ext, resp)?,
            "kval" => extract_kval(ext, resp),
            "json" => extract_json(ext, resp)?,
            "dsl" => extract_dsl(ext, resp),
            "xpath" => Vec::new(), // not implemented — compat warns
            _ => Vec::new(),
        };
        if values.is_empty() {
            continue;
        }
        // Nuclei often uses first match for chaining.
        if ext.name.is_empty() {
            for (i, v) in values.into_iter().enumerate() {
                out.push((format!("extract_{i}"), v, ext.internal));
            }
        } else {
            // Prefer first value as named variable; also expose all.
            let first = values.remove(0);
            out.push((ext.name.clone(), first.clone(), ext.internal));
            for (i, v) in values.into_iter().enumerate() {
                out.push((format!("{}_{}", ext.name, i + 1), v, ext.internal));
            }
        }
    }
    Ok(out)
}

fn part_text(ext: &Extractor, resp: &HttpResponse) -> String {
    match ext.part.to_lowercase().as_str() {
        "header" | "headers" => resp.headers_text.clone(),
        "all" => format!("{}\n{}", resp.headers_text, resp.body),
        _ => resp.body.clone(),
    }
}

fn extract_regex(ext: &Extractor, resp: &HttpResponse) -> Result<Vec<String>, String> {
    let hay = part_text(ext, resp);
    let mut found = Vec::new();
    for pat in &ext.regex {
        let re = Regex::new(pat).map_err(|e| format!("Invalid extractor regex: {e}"))?;
        for cap in re.captures_iter(&hay) {
            let val = if ext.group > 0 {
                cap.get(ext.group).map(|m| m.as_str().to_string())
            } else {
                cap.get(0).map(|m| m.as_str().to_string())
            };
            if let Some(v) = val {
                found.push(v);
            }
        }
    }
    Ok(found)
}

fn extract_kval(ext: &Extractor, resp: &HttpResponse) -> Vec<String> {
    let mut found = Vec::new();
    for key in &ext.kval {
        let lk = key.to_lowercase();
        if let Some(v) = resp.headers_map.get(&lk) {
            found.push(v.clone());
        }
        // Also try cookie-style from set-cookie
        if lk == "cookie" || key.eq_ignore_ascii_case("set-cookie") {
            if let Some(v) = resp.headers_map.get("set-cookie") {
                found.push(v.clone());
            }
        }
    }
    found
}

fn extract_json(ext: &Extractor, resp: &HttpResponse) -> Result<Vec<String>, String> {
    let parsed: JsonValue = match serde_json::from_str(&resp.body) {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };
    let mut found = Vec::new();
    for path in &ext.json {
        if let Some(v) = json_path_get(&parsed, path) {
            found.push(json_value_to_string(&v));
        }
    }
    Ok(found)
}

/// Supports simple jq-like paths: `.token`, `.data[0].id`, `token` (implicit root).
fn json_path_get(root: &JsonValue, path: &str) -> Option<JsonValue> {
    let mut path = path.trim();
    if path.starts_with('.') {
        path = &path[1..];
    }
    if path.is_empty() {
        return Some(root.clone());
    }

    let mut cur = root;
    for seg in split_json_path(path) {
        match seg {
            PathSeg::Key(k) => {
                cur = cur.get(&k)?;
            }
            PathSeg::Index(i) => {
                cur = cur.get(i)?;
            }
        }
    }
    Some(cur.clone())
}

enum PathSeg {
    Key(String),
    Index(usize),
}

fn split_json_path(path: &str) -> Vec<PathSeg> {
    let mut segs = Vec::new();
    let mut buf = String::new();
    let chars: Vec<char> = path.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '.' => {
                if !buf.is_empty() {
                    segs.push(PathSeg::Key(std::mem::take(&mut buf)));
                }
                i += 1;
            }
            '[' => {
                if !buf.is_empty() {
                    segs.push(PathSeg::Key(std::mem::take(&mut buf)));
                }
                i += 1;
                let mut num = String::new();
                while i < chars.len() && chars[i] != ']' {
                    num.push(chars[i]);
                    i += 1;
                }
                if let Ok(n) = num.parse::<usize>() {
                    segs.push(PathSeg::Index(n));
                }
                i += 1; // skip ]
            }
            c => {
                buf.push(c);
                i += 1;
            }
        }
    }
    if !buf.is_empty() {
        segs.push(PathSeg::Key(buf));
    }
    segs
}

fn json_value_to_string(v: &JsonValue) -> String {
    match v {
        JsonValue::String(s) => s.clone(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Null => String::new(),
        other => other.to_string(),
    }
}

fn extract_dsl(ext: &Extractor, resp: &HttpResponse) -> Vec<String> {
    let mut found = Vec::new();
    for expr in &ext.dsl {
        let e = expr.trim();
        if e == "body" {
            found.push(resp.body.clone());
        } else if e == "status_code" {
            found.push(resp.status.to_string());
        } else if e == "len(body)" {
            found.push(resp.body.len().to_string());
        } else if let Some(inner) = e.strip_prefix("contains(body, ") {
            // not an extractor typically
            let _ = inner;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_path_simple() {
        let v: JsonValue = serde_json::from_str(r#"{"token":"abc","data":[{"id":1}]}"#).unwrap();
        assert_eq!(
            json_path_get(&v, ".token").unwrap(),
            JsonValue::String("abc".into())
        );
        assert_eq!(
            json_path_get(&v, ".data[0].id").unwrap(),
            JsonValue::Number(1.into())
        );
    }
}
