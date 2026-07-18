use crate::engine::parse::HttpRequest;
use crate::engine::vars::{substitute, BuiltinVars};
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers_text: String,
    pub headers_map: HashMap<String, String>,
    pub body: String,
    pub body_bytes: Vec<u8>,
    pub final_url: String,
}

pub fn build_client(
    proxy_url: Option<&str>,
    accept_invalid_certs: bool,
    timeout_secs: u64,
) -> Result<Client, String> {
    let jar = reqwest::cookie::Jar::default();
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(accept_invalid_certs)
        .cookie_provider(Arc::new(jar))
        .redirect(reqwest::redirect::Policy::none()); // we handle redirects manually when enabled

    if let Some(proxy_str) = proxy_url {
        if !proxy_str.trim().is_empty() {
            let proxy = reqwest::Proxy::all(proxy_str)
                .map_err(|e| format!("Proxy Config Error: {e}"))?;
            builder = builder.proxy(proxy);
        }
    }

    builder.build().map_err(|e| e.to_string())
}

pub async fn execute_request(
    client: &Client,
    req: &HttpRequest,
    builtins: &BuiltinVars,
    dynamic: &HashMap<String, String>,
) -> Result<Vec<HttpResponse>, String> {
    if !req.raw.is_empty() {
        let scheme = builtins
            .map
            .get("Scheme")
            .cloned()
            .unwrap_or_else(|| "http".into());
        let mut out = Vec::new();
        for raw in &req.raw {
            let rendered = substitute(raw, builtins, dynamic);
            out.push(send_raw(client, &rendered, req, &scheme).await?);
        }
        return Ok(out);
    }

    let method = parse_method(&req.method);
    let mut out = Vec::new();

    let paths = if req.path.is_empty() {
        vec!["{{BaseURL}}".to_string()]
    } else {
        req.path.clone()
    };

    for path_tpl in paths {
        let path = substitute(&path_tpl, builtins, dynamic);
        let url = if path.starts_with("http://") || path.starts_with("https://") {
            path
        } else {
            let base = builtins.map.get("BaseURL").cloned().unwrap_or_default();
            format!("{base}{path}")
        };

        let mut current_url = url;
        let max_hops = if req.redirects {
            req.max_redirects.max(1)
        } else {
            1
        };

        for hop in 0..max_hops {
            let mut builder = client.request(method.clone(), &current_url);

            for (k, v) in &req.headers {
                let hv = substitute(v, builtins, dynamic);
                builder = builder.header(k, hv);
            }

            if let Some(body) = &req.body {
                let b = substitute(body, builtins, dynamic);
                builder = builder.body(b);
            }

            let response = builder
                .send()
                .await
                .map_err(|e| format!("Request error: {e}"))?;

            let status = response.status().as_u16();
            let final_url = response.url().to_string();
            let mut headers_map = HashMap::new();
            let mut headers_text = String::new();
            for (k, v) in response.headers().iter() {
                let val = v.to_str().unwrap_or("").to_string();
                headers_map.insert(k.as_str().to_lowercase(), val.clone());
                headers_text.push_str(&format!("{k}: {val}\n"));
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let body_bytes = response
                .bytes()
                .await
                .map_err(|e| format!("Body read error: {e}"))?
                .to_vec();
            let body = String::from_utf8_lossy(&body_bytes).to_string();

            let http_resp = HttpResponse {
                status,
                headers_text,
                headers_map,
                body,
                body_bytes,
                final_url: final_url.clone(),
            };

            let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
            if req.redirects && is_redirect && hop + 1 < max_hops {
                if let Some(loc) = location {
                    current_url = resolve_redirect(&final_url, &loc);
                    continue;
                }
            }

            out.push(http_resp);
            break;
        }
    }

    Ok(out)
}

async fn send_raw(
    client: &Client,
    raw: &str,
    req: &HttpRequest,
    scheme: &str,
) -> Result<HttpResponse, String> {
    let (method, url, headers, body) = parse_raw_http(raw, scheme)?;
    let mut current_url = url;
    let max_hops = if req.redirects {
        req.max_redirects.max(1)
    } else {
        1
    };

    for hop in 0..max_hops {
        let mut builder = client.request(method.clone(), &current_url);
        for (k, v) in &headers {
            builder = builder.header(k, v);
        }
        if let Some(b) = &body {
            builder = builder.body(b.clone());
        }

        let response = builder
            .send()
            .await
            .map_err(|e| format!("Raw request error: {e}"))?;

        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let mut headers_map = HashMap::new();
        let mut headers_text = String::new();
        for (k, v) in response.headers().iter() {
            let val = v.to_str().unwrap_or("").to_string();
            headers_map.insert(k.as_str().to_lowercase(), val.clone());
            headers_text.push_str(&format!("{k}: {val}\n"));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| format!("Body read error: {e}"))?
            .to_vec();
        let body_str = String::from_utf8_lossy(&body_bytes).to_string();

        let http_resp = HttpResponse {
            status,
            headers_text,
            headers_map,
            body: body_str,
            body_bytes,
            final_url: final_url.clone(),
        };

        let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
        if req.redirects && is_redirect && hop + 1 < max_hops {
            if let Some(loc) = location {
                current_url = resolve_redirect(&final_url, &loc);
                continue;
            }
        }
        return Ok(http_resp);
    }

    Err("Redirect loop without final response".into())
}

fn parse_raw_http(
    raw: &str,
    scheme: &str,
) -> Result<(Method, String, Vec<(String, String)>, Option<String>), String> {
    let normalized = raw.replace("\r\n", "\n");
    let mut parts = normalized.splitn(2, "\n\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().map(|s| s.to_string());

    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "Raw request missing request line".to_string())?;
    let mut rl = request_line.split_whitespace();
    let method_s = rl.next().unwrap_or("GET");
    let path = rl.next().unwrap_or("/");
    let method = parse_method(method_s);

    let mut headers = Vec::new();
    let mut host = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("host") {
                host = val.clone();
            }
            if !key.eq_ignore_ascii_case("content-length") {
                headers.push((key, val));
            }
        }
    }

    if host.is_empty() {
        return Err("Raw request missing Host header".into());
    }

    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("{scheme}://{host}{path}")
    };

    Ok((method, url, headers, body))
}

fn resolve_redirect(current: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if let Ok(base) = url::Url::parse(current) {
        base.join(location)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| location.to_string())
    } else {
        location.to_string()
    }
}

fn parse_method(s: &str) -> Method {
    match s.to_uppercase().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "PATCH" => Method::PATCH,
        "OPTIONS" => Method::OPTIONS,
        "HEAD" => Method::HEAD,
        "TRACE" => Method::TRACE,
        "CONNECT" => Method::CONNECT,
        _ => Method::GET,
    }
}
