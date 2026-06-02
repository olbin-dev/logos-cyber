use serde::{Deserialize, Serialize};
use reqwest::{Client, Method};
use regex::Regex;
use std::time::Duration;

#[derive(Debug, Deserialize, Serialize)]
pub struct Template {
    pub id: String,
    pub info: Info,
    #[serde(default)]
    pub requests: Vec<Request>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Info {
    pub name: String,
    pub author: String,
    pub severity: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    pub method: String,
    pub path: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Extractor {
    #[serde(rename = "type")]
    pub extractor_type: String, // regex
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub part: String, // body, header
    #[serde(default)]
    pub group: usize, // default 0 (full match)
    #[serde(default)]
    pub regex: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub matcher_type: String, // word, regex, status
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default = "default_condition")]
    pub condition: String, // and, or
}

fn default_condition() -> String {
    "or".to_string()
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub template_id: String,
    pub target: String,
    pub matched: bool,
    pub details: String,
    pub extracted_data: Vec<String>,
}

pub async fn run_scan(target: &str, template_yaml: &str, proxy_url: Option<String>) -> Result<ScanResult, String> {
    let template: Template = serde_yaml::from_str(template_yaml).map_err(|e| format!("YAML Parse Error: {}", e))?;
    
    // Ignore invalid certs for security scanning tools
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true);

    if let Some(proxy_str) = proxy_url {
        if !proxy_str.trim().is_empty() {
            let proxy = reqwest::Proxy::all(&proxy_str).map_err(|e| format!("Proxy Config Error: {}", e))?;
            builder = builder.proxy(proxy);
        }
    }

    let client = builder.build().map_err(|e| e.to_string())?;

    let base_url = target.trim_end_matches('/');

    for req in &template.requests {
        let method = match req.method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            _ => Method::GET,
        };

        for path_tpl in &req.path {
            // Nuclei uses {{BaseURL}} as the placeholder
            let path = path_tpl.replace("{{BaseURL}}", base_url);
            let url = if path.starts_with("http") {
                path
            } else {
                format!("{}{}", base_url, path)
            };

            let response = client.request(method.clone(), &url).send().await;
            
            if let Ok(resp) = response {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();

                for matcher in &req.matchers {
                    let mut matched = false;
                    match matcher.matcher_type.as_str() {
                        "status" => {
                            matched = matcher.status.contains(&status);
                        }
                        "word" => {
                            if matcher.condition == "and" {
                                matched = matcher.words.iter().all(|w| body.contains(w));
                            } else {
                                matched = matcher.words.iter().any(|w| body.contains(w));
                            }
                        }
                        "regex" => {
                            if matcher.condition == "and" {
                                matched = matcher.regex.iter().all(|r| {
                                    Regex::new(r).map(|re| re.is_match(&body)).unwrap_or(false)
                                });
                            } else {
                                matched = matcher.regex.iter().any(|r| {
                                    Regex::new(r).map(|re| re.is_match(&body)).unwrap_or(false)
                                });
                            }
                        }
                        _ => {}
                    }

                    if matched {
                        let mut extracted_data = Vec::new();
                        for ext in &req.extractors {
                            if ext.extractor_type == "regex" {
                                for r in &ext.regex {
                                    if let Ok(re) = Regex::new(r) {
                                        for cap in re.captures_iter(&body) {
                                            if let Some(m) = cap.get(ext.group) {
                                                extracted_data.push(format!("{}: {}", ext.name, m.as_str()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        let mut details = format!("VULNERABILITY FOUND: {} on {} (Matcher: {})", template.id, url, matcher.matcher_type);
                        if !extracted_data.is_empty() {
                            details.push_str(&format!("\nExtracted Data:\n  - {}", extracted_data.join("\n  - ")));
                        }

                        return Ok(ScanResult {
                            template_id: template.id.clone(),
                            target: target.to_string(),
                            matched: true,
                            details,
                            extracted_data,
                        });
                    }
                }
            }
        }
    }

    Ok(ScanResult {
        template_id: template.id.clone(),
        target: target.to_string(),
        matched: false,
        details: "Clean. No vulnerabilities matched.".to_string(),
        extracted_data: Vec::new(),
    })
}
