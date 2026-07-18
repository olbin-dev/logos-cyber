use rand::{distributions::Alphanumeric, Rng};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone)]
pub struct BuiltinVars {
    pub map: HashMap<String, String>,
}

impl BuiltinVars {
    pub fn from_target(target: &str) -> Result<Self, String> {
        let trimmed = target.trim();
        let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("http://{trimmed}")
        };

        let url = Url::parse(&with_scheme).map_err(|e| format!("Invalid target URL: {e}"))?;
        let scheme = url.scheme().to_string();
        let host = url.host_str().unwrap_or("").to_string();
        let port = url
            .port_or_known_default()
            .map(|p| p.to_string())
            .unwrap_or_default();
        let hostname = if port.is_empty() {
            host.clone()
        } else if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
            host.clone()
        } else {
            format!("{host}:{port}")
        };

        let path = url.path().to_string();
        let base = with_scheme.trim_end_matches('/').to_string();
        let root = format!(
            "{}://{}",
            scheme,
            if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
                host.clone()
            } else if port.is_empty() {
                host.clone()
            } else {
                format!("{host}:{port}")
            }
        );

        let mut map = HashMap::new();
        map.insert("BaseURL".into(), base.clone());
        map.insert("RootURL".into(), root);
        map.insert("Hostname".into(), hostname);
        map.insert("Host".into(), host);
        map.insert("Port".into(), port);
        map.insert("Path".into(), path);
        map.insert("Scheme".into(), scheme);
        // Common lowercase aliases seen in some templates
        map.insert("BaseURL".into(), base);

        Ok(Self { map })
    }
}

/// Replace `{{Var}}` placeholders. Generates fresh `randstr` / `randstr_N` on each call.
pub fn substitute(input: &str, builtins: &BuiltinVars, dynamic: &HashMap<String, String>) -> String {
    let mut out = input.to_string();

    // Handle {{randstr}} and {{randstr_N}}
    while let Some(start) = out.find("{{randstr") {
        let rest = &out[start + 2..];
        if let Some(end_rel) = rest.find("}}") {
            let token = &rest[..end_rel];
            let len = if token == "randstr" {
                8
            } else if let Some(n) = token.strip_prefix("randstr_") {
                n.parse::<usize>().unwrap_or(8)
            } else {
                break;
            };
            let val: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(len)
                .map(char::from)
                .collect();
            let placeholder = format!("{{{{{token}}}}}");
            out = out.replacen(&placeholder, &val, 1);
        } else {
            break;
        }
    }

    // Dynamic first (can override), then builtins
    for (k, v) in dynamic {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    for (k, v) in &builtins.map {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }

    // Simple DSL helpers embedded in templates: {{base64('x')}} — limited
    out = expand_simple_helpers(&out);

    out
}

fn expand_simple_helpers(s: &str) -> String {
    // {{md5('text')}} not fully implemented — leave as-is if unknown
    let mut out = s.to_string();
    // base64('...')
    while let Some(idx) = out.find("{{base64('") {
        if let Some(end) = out[idx..].find("')}}") {
            let inner_start = idx + "{{base64('".len();
            let inner_end = idx + end;
            let inner = &out[inner_start..inner_end];
            let encoded = b64_encode(inner.as_bytes());
            let whole_end = idx + end + "')}}".len();
            out.replace_range(idx..whole_end, &encoded);
        } else {
            break;
        }
    }
    out
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, b) in chunk.iter().enumerate() {
            buf[i] = *b;
        }
        let n = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_from_https() {
        let b = BuiltinVars::from_target("https://example.com:8443/app").unwrap();
        assert_eq!(b.map.get("Host").unwrap(), "example.com");
        assert_eq!(b.map.get("Port").unwrap(), "8443");
        assert!(b.map.get("BaseURL").unwrap().contains("example.com"));
    }

    #[test]
    fn substitute_baseurl() {
        let b = BuiltinVars::from_target("http://t.test").unwrap();
        let d = HashMap::new();
        let s = substitute("{{BaseURL}}/.git/config", &b, &d);
        assert_eq!(s, "http://t.test/.git/config");
    }
}
