use crate::engine::http_exec::HttpResponse;
use crate::engine::parse::{HttpRequest, Matcher};
use regex::Regex;
use std::collections::HashMap;

pub fn evaluate_matchers(
    req: &HttpRequest,
    resp: &HttpResponse,
    _scope: &HashMap<String, String>,
) -> Result<bool, String> {
    if req.matchers.is_empty() {
        // Nuclei typically requires matchers; treat empty as no-match for safety.
        return Ok(false);
    }

    let results: Result<Vec<bool>, String> = req
        .matchers
        .iter()
        .map(|m| evaluate_one(m, resp))
        .collect();
    let results = results?;

    let combined = if req.matchers_condition.eq_ignore_ascii_case("and") {
        results.iter().all(|r| *r)
    } else {
        results.iter().any(|r| *r)
    };
    Ok(combined)
}

fn evaluate_one(m: &Matcher, resp: &HttpResponse) -> Result<bool, String> {
    let haystack = part_text(m.part.as_str(), resp);
    let mut matched = match m.matcher_type.as_str() {
        "status" => m.status.contains(&resp.status),
        "word" => match_words(m, &haystack),
        "regex" => match_regex(m, &haystack)?,
        "size" => m.size.iter().any(|s| *s == resp.body_bytes.len() as i64),
        "binary" => match_binary(m, &resp.body_bytes)?,
        "dsl" => match_dsl(m, resp)?,
        other => {
            // Unknown types fail closed (no match) — caller may warn via compat.
            let _ = other;
            false
        }
    };

    if m.negative {
        matched = !matched;
    }
    Ok(matched)
}

fn part_text(part: &str, resp: &HttpResponse) -> String {
    match part.to_lowercase().as_str() {
        "header" | "headers" => resp.headers_text.clone(),
        "all" => format!("{}\n{}", resp.headers_text, resp.body),
        "body_binary" => String::from_utf8_lossy(&resp.body_bytes).to_string(),
        _ => resp.body.clone(),
    }
}

fn match_words(m: &Matcher, haystack: &str) -> bool {
    let hay = if m.case_insensitive {
        haystack.to_lowercase()
    } else {
        haystack.to_string()
    };
    let words: Vec<String> = m
        .words
        .iter()
        .map(|w| {
            if m.case_insensitive {
                w.to_lowercase()
            } else {
                w.clone()
            }
        })
        .collect();

    if m.condition.eq_ignore_ascii_case("and") {
        words.iter().all(|w| hay.contains(w))
    } else {
        words.iter().any(|w| hay.contains(w))
    }
}

fn match_regex(m: &Matcher, haystack: &str) -> Result<bool, String> {
    let flags_ci = m.case_insensitive;
    let check = |pat: &str| -> Result<bool, String> {
        let pattern = if flags_ci && !pat.starts_with("(?i)") {
            format!("(?i){pat}")
        } else {
            pat.to_string()
        };
        let re = Regex::new(&pattern).map_err(|e| format!("Invalid matcher regex: {e}"))?;
        Ok(re.is_match(haystack))
    };

    if m.condition.eq_ignore_ascii_case("and") {
        for r in &m.regex {
            if !check(r)? {
                return Ok(false);
            }
        }
        Ok(!m.regex.is_empty())
    } else {
        for r in &m.regex {
            if check(r)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn match_binary(m: &Matcher, body: &[u8]) -> Result<bool, String> {
    let needles: Result<Vec<Vec<u8>>, String> = m
        .binary
        .iter()
        .map(|hex_str| {
            let cleaned: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            hex::decode(&cleaned).map_err(|e| format!("Invalid binary hex: {e}"))
        })
        .collect();
    let needles = needles?;

    let found = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);

    if m.condition.eq_ignore_ascii_case("and") {
        Ok(needles.iter().all(|n| found(n)))
    } else {
        Ok(needles.iter().any(|n| found(n)))
    }
}

/// Minimal DSL subset: contains, status_code, len, to_lower helpers via simple expressions.
fn match_dsl(m: &Matcher, resp: &HttpResponse) -> Result<bool, String> {
    let exprs = &m.dsl;
    if exprs.is_empty() {
        return Ok(false);
    }

    let eval_one = |expr: &str| -> bool {
        let e = expr.trim();
        // status_code == 200
        if let Some(rest) = e.strip_prefix("status_code==") {
            return rest.trim().parse::<u16>().ok() == Some(resp.status);
        }
        if let Some(rest) = e.strip_prefix("status_code == ") {
            return rest.trim().parse::<u16>().ok() == Some(resp.status);
        }
        // len(body) > N / < N / == N
        if let Some(rest) = e.strip_prefix("len(body)") {
            let len = resp.body.len() as i64;
            return cmp_num(rest.trim(), len);
        }
        // contains(body, 'x') / contains(to_lower(body), 'x')
        if let Some(inner) = extract_contains(e) {
            let (hay_expr, needle) = inner;
            let hay = if hay_expr.contains("to_lower") {
                resp.body.to_lowercase()
            } else if hay_expr.contains("header") {
                resp.headers_text.clone()
            } else {
                resp.body.clone()
            };
            let needle = if hay_expr.contains("to_lower") {
                needle.to_lowercase()
            } else {
                needle
            };
            return hay.contains(&needle);
        }
        // !contains(...)
        if let Some(rest) = e.strip_prefix('!') {
            return !match_dsl(
                &Matcher {
                    dsl: vec![rest.to_string()],
                    ..m.clone()
                },
                resp,
            )
            .unwrap_or(false);
        }
        false
    };

    if m.condition.eq_ignore_ascii_case("and") {
        Ok(exprs.iter().all(|e| eval_one(e)))
    } else {
        Ok(exprs.iter().any(|e| eval_one(e)))
    }
}

fn cmp_num(op_rhs: &str, left: i64) -> bool {
    let op_rhs = op_rhs.trim();
    if let Some(rhs) = op_rhs.strip_prefix("==") {
        return left == rhs.trim().parse::<i64>().unwrap_or(i64::MIN);
    }
    if let Some(rhs) = op_rhs.strip_prefix(">=") {
        return left >= rhs.trim().parse::<i64>().unwrap_or(i64::MAX);
    }
    if let Some(rhs) = op_rhs.strip_prefix("<=") {
        return left <= rhs.trim().parse::<i64>().unwrap_or(i64::MIN);
    }
    if let Some(rhs) = op_rhs.strip_prefix('>') {
        return left > rhs.trim().parse::<i64>().unwrap_or(i64::MAX);
    }
    if let Some(rhs) = op_rhs.strip_prefix('<') {
        return left < rhs.trim().parse::<i64>().unwrap_or(i64::MIN);
    }
    false
}

fn extract_contains(expr: &str) -> Option<(String, String)> {
    // contains(BODY_EXPR, 'needle') or contains(BODY_EXPR, "needle")
    let expr = expr.trim();
    let start = expr.find("contains(")?;
    let rest = &expr[start + "contains(".len()..];
    let comma = rest.find(',')?;
    let hay = rest[..comma].trim().to_string();
    let mut needle_part = rest[comma + 1..].trim();
    if needle_part.ends_with(')') {
        needle_part = &needle_part[..needle_part.len() - 1];
    }
    needle_part = needle_part.trim();
    let needle = if (needle_part.starts_with('\'') && needle_part.ends_with('\''))
        || (needle_part.starts_with('"') && needle_part.ends_with('"'))
    {
        needle_part[1..needle_part.len() - 1].to_string()
    } else {
        needle_part.to_string()
    };
    Some((hay, needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsl_contains_and_status() {
        let resp = HttpResponse {
            status: 200,
            headers_text: String::new(),
            headers_map: HashMap::new(),
            body: "Hello WORLD".into(),
            body_bytes: b"Hello WORLD".to_vec(),
            final_url: "http://x".into(),
        };
        let m = Matcher {
            matcher_type: "dsl".into(),
            words: vec![],
            regex: vec![],
            status: vec![],
            size: vec![],
            binary: vec![],
            dsl: vec![
                "status_code==200".into(),
                "contains(to_lower(body), 'hello')".into(),
            ],
            condition: "and".into(),
            part: "body".into(),
            name: String::new(),
            negative: false,
            case_insensitive: false,
        };
        assert!(evaluate_one(&m, &resp).unwrap());
    }
}
