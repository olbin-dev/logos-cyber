//! Fetch official Nuclei templates from GitHub (`projectdiscovery/nuclei-templates`).

use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const REPO: &str = "projectdiscovery/nuclei-templates";
const API_ROOT: &str = "https://api.github.com/repos/projectdiscovery/nuclei-templates";
const RAW_ROOT: &str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main";
const USER_AGENT: &str = "LogosCyber-template-fetcher";
/// Safety cap so a broad keyword does not flood the disk/API.
pub const MAX_DOWNLOADS: usize = 40;

#[derive(Debug, Clone)]
pub struct FetchReport {
    pub saved: Vec<PathBuf>,
    /// Paths matched for this query before the download cap.
    pub matched_total: usize,
    pub skipped: usize,
    pub query: String,
    pub notes: Vec<String>,
}

/// Cached inventory of official nuclei-templates YAML paths (from GitHub git tree).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct RemoteCatalog {
    pub yaml_paths: Vec<String>,
    pub fetched_at_unix: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct CoverageSnapshot {
    pub local_total: usize,
    pub remote_total: usize,
    pub remote_http: usize,
    pub query: String,
    pub query_remote: usize,
    pub query_local: usize,
    pub catalog_age_hint: String,
    pub catalog_truncated: bool,
}

impl CoverageSnapshot {
    pub fn library_percent(&self) -> f32 {
        if self.remote_total == 0 {
            0.0
        } else {
            (self.local_total as f32 / self.remote_total as f32) * 100.0
        }
    }

    pub fn query_percent(&self) -> f32 {
        if self.query_remote == 0 {
            0.0
        } else {
            (self.query_local as f32 / self.query_remote as f32) * 100.0
        }
    }

    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "防衛準備率（公式ライブラリ）: ローカル {} / 公式YAML約 {} 本 → 約 {:.1}%",
                self.local_total,
                self.remote_total,
                self.library_percent()
            ),
            format!(
                "HTTP系テンプレ母数（公式）: 約 {} 本",
                self.remote_http
            ),
            format!(
                "今回フォーカス「{}」: 配備済 {} / 公式該当 {} 本 → 約 {:.1}%",
                if self.query.is_empty() {
                    "（未指定）"
                } else {
                    &self.query
                },
                self.query_local,
                self.query_remote,
                self.query_percent()
            ),
            format!(
                "カタログ同期: {}{}",
                self.catalog_age_hint,
                if self.catalog_truncated {
                    " / tree truncated"
                } else {
                    ""
                }
            ),
            "定義: 本指標はクライアント資産を守るための『見える化された防衛準備率』です（テンプレ配備の達成度）。".into(),
            "残差領域（未知のゼロデイ等）は定点観測とプロによる継続監視で補完します。".into(),
        ]
    }
}

#[derive(Debug, Deserialize)]
struct ContentItem {
    #[allow(dead_code)]
    name: String,
    path: String,
    #[serde(rename = "type")]
    item_type: String,
    download_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TreeResponse {
    tree: Vec<TreeItem>,
    truncated: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct TreeItem {
    path: String,
    #[serde(rename = "type")]
    item_type: String,
}

pub fn templates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates")
}

/// Download a single template path from raw.githubusercontent.com into `templates/`.
///
/// Example path: `http/exposures/configs/git-config.yaml`
pub async fn fetch_template_from_github(path: &str) -> Result<PathBuf, String> {
    let rel = path.trim().trim_start_matches('/');
    if rel.is_empty() {
        return Err("path is empty".into());
    }
    if !is_yaml_path(rel) {
        return Err("path must end with .yaml or .yml".into());
    }
    let client = authed_client()?;
    let dest_root = templates_dir();
    download_one(&client, rel, &dest_root).await
}

/// Resolve local relative display names for UI list refresh checks.
pub fn list_saved_yaml_names(dir: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    if !dir.is_dir() {
        return Ok(names);
    }
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let p = entry.path();
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    Ok(names)
}

fn github_token() -> Option<String> {
    env::var("GITHUB_TOKEN")
        .or_else(|_| env::var("GH_TOKEN"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn authed_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| e.to_string())
}

async fn api_get_json(client: &Client, url: &str) -> Result<serde_json::Value, String> {
    let mut req = client.get(url).header("Accept", "application/vnd.github+json");
    if let Some(tok) = github_token() {
        req = req.bearer_auth(tok);
    }
    let resp = req.send().await.map_err(|e| format!("GitHub request failed: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("GitHub HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("GitHub JSON error: {e}"))
}

fn is_yaml_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml")
}

fn normalize_query(q: &str) -> String {
    q.trim().trim_matches('/').to_string()
}

fn looks_like_path(q: &str) -> bool {
    q.contains('/')
        || q.starts_with("http")
        || q.starts_with("cves")
        || q.starts_with("network")
        || q.starts_with("dns")
        || q.starts_with("ssl")
        || q.starts_with("exposures")
        || q.starts_with("misconfiguration")
        || q.starts_with("vulnerabilities")
        || q.starts_with("technologies")
}

pub fn catalog_cache_path() -> PathBuf {
    templates_dir().join(".remote_catalog.json")
}

pub fn load_catalog_cache() -> Option<RemoteCatalog> {
    let raw = fs::read_to_string(catalog_cache_path()).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_catalog_cache(catalog: &RemoteCatalog) -> Result<(), String> {
    let dir = templates_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let raw = serde_json::to_string_pretty(catalog).map_err(|e| e.to_string())?;
    fs::write(catalog_cache_path(), raw).map_err(|e| e.to_string())
}

/// Refresh official YAML path inventory from GitHub (recursive git tree).
pub async fn refresh_remote_catalog() -> Result<RemoteCatalog, String> {
    let client = authed_client()?;
    let (paths, truncated) = fetch_all_yaml_paths(&client).await?;
    let catalog = RemoteCatalog {
        yaml_paths: paths,
        fetched_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        truncated,
    };
    save_catalog_cache(&catalog)?;
    Ok(catalog)
}

async fn fetch_all_yaml_paths(client: &Client) -> Result<(Vec<String>, bool), String> {
    let url = format!("{API_ROOT}/git/trees/main?recursive=1");
    let json = api_get_json(client, &url).await?;
    let tree: TreeResponse =
        serde_json::from_value(json).map_err(|e| format!("parse git tree: {e}"))?;
    let truncated = tree.truncated.unwrap_or(false);
    let mut paths: Vec<String> = tree
        .tree
        .into_iter()
        .filter(|t| t.item_type == "blob" && is_yaml_path(&t.path))
        .map(|t| t.path)
        .collect();
    paths.sort();
    Ok((paths, truncated))
}

fn paths_matching_query(all: &[String], query: &str) -> Vec<String> {
    let q = normalize_query(query);
    if q.is_empty() {
        return all.to_vec();
    }
    if looks_like_path(&q) {
        let prefixes = if q.starts_with("http/") {
            vec![q.clone()]
        } else {
            vec![q.clone(), format!("http/{q}")]
        };
        all.iter()
            .filter(|p| {
                prefixes.iter().any(|pre| {
                    p == &pre
                        || p.starts_with(&format!("{pre}/"))
                        || p.starts_with(pre)
                })
            })
            .cloned()
            .collect()
    } else {
        let kw = q.to_lowercase();
        let mut paths: Vec<String> = all
            .iter()
            .filter(|p| p.to_lowercase().contains(&kw))
            .cloned()
            .collect();
        paths.sort_by_key(|p| if p.starts_with("http/") { 0 } else { 1 });
        paths
    }
}

fn count_local_yaml(dir: &Path) -> usize {
    list_saved_yaml_names(dir).map(|v| v.len()).unwrap_or(0)
}

fn count_local_matching_query(dir: &Path, query: &str) -> usize {
    let q = normalize_query(query);
    if !dir.is_dir() {
        return 0;
    }
    let mut n = 0;
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let p = entry.path();
        if !is_yaml_path(&p.to_string_lossy()) {
            continue;
        }
        let rel = p
            .strip_prefix(dir)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if q.is_empty() {
            n += 1;
            continue;
        }
        if looks_like_path(&q) {
            let ok = rel == q
                || rel.starts_with(&format!("{q}/"))
                || rel.starts_with(&format!("http/{q}/"))
                || rel.starts_with(&format!("http/{q}"))
                || rel.contains(&q);
            if ok {
                n += 1;
            }
        } else if rel.to_lowercase().contains(&q.to_lowercase())
            || p.file_name()
                .and_then(|f| f.to_str())
                .map(|f| f.to_lowercase().contains(&q.to_lowercase()))
                .unwrap_or(false)
        {
            n += 1;
        }
    }
    n
}

/// Build coverage snapshot from cache (or empty) + local templates dir.
pub fn compute_coverage(query: &str, catalog: Option<&RemoteCatalog>) -> CoverageSnapshot {
    let local_dir = templates_dir();
    let local_total = count_local_yaml(&local_dir);
    let query = normalize_query(query);

    let (remote_total, remote_http, query_remote, age, truncated) = if let Some(c) = catalog {
        let remote_total = c.yaml_paths.len();
        let remote_http = c.yaml_paths.iter().filter(|p| p.starts_with("http/")).count();
        let query_remote = if query.is_empty() {
            0
        } else {
            paths_matching_query(&c.yaml_paths, &query).len()
        };
        let age = if c.fetched_at_unix == 0 {
            "未取得".into()
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mins = now.saturating_sub(c.fetched_at_unix) / 60;
            if mins < 60 {
                format!("{mins} 分前")
            } else {
                format!("{} 時間前", mins / 60)
            }
        };
        (remote_total, remote_http, query_remote, age, c.truncated)
    } else {
        (0, 0, 0, "未取得 — 「公式カタログ更新」を押してください".into(), false)
    };

    let query_local = if query.is_empty() {
        0
    } else {
        count_local_matching_query(&local_dir, &query)
    };

    CoverageSnapshot {
        local_total,
        remote_total,
        remote_http,
        query,
        query_remote,
        query_local,
        catalog_age_hint: age,
        catalog_truncated: truncated,
    }
}

/// Resolve candidate paths then download into `dest_root` (typically `templates/`).
pub async fn fetch_and_save(query: &str, dest_root: &Path) -> Result<FetchReport, String> {
    let q = normalize_query(query);
    if q.is_empty() {
        return Err("Query is empty. Try e.g. `log4j` or `http/cves/2024`.".into());
    }

    let client = authed_client()?;
    let mut notes = Vec::new();
    if github_token().is_none() {
        notes.push(
            "No GITHUB_TOKEN/GH_TOKEN — using unauthenticated API (lower rate limit).".into(),
        );
    }

    // Prefer full tree (accurate match counts + coverage).
    notes.push("Loading official template catalog (git tree)…".into());
    let (all_yaml, truncated) = fetch_all_yaml_paths(&client).await?;
    if truncated {
        notes.push("Warning: GitHub tree was truncated; counts may be slightly low.".into());
    }
    let catalog = RemoteCatalog {
        yaml_paths: all_yaml.clone(),
        fetched_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        truncated,
    };
    let _ = save_catalog_cache(&catalog);

    let paths = paths_matching_query(&all_yaml, &q);
    if paths.is_empty() {
        // Fallback to contents API for brand-new paths
        notes.push("Tree had no match; trying Contents API…".into());
        let fallback = if looks_like_path(&q) {
            let first = collect_paths_under(&client, &q).await.unwrap_or_default();
            if first.is_empty() && !q.starts_with("http/") {
                collect_paths_under(&client, &format!("http/{q}"))
                    .await
                    .unwrap_or_default()
            } else {
                first
            }
        } else {
            Vec::new()
        };
        if fallback.is_empty() {
            return Err(format!(
                "No YAML templates matched `{q}` in {REPO}. Try a path like `http/exposures` or another keyword."
            ));
        }
        return download_limited(fallback, dest_root, q, notes).await;
    }

    notes.push(format!(
        "Query matched {} official template(s). Cap per fetch: {}.",
        paths.len(),
        MAX_DOWNLOADS
    ));
    download_limited(paths, dest_root, q, notes).await
}

async fn download_limited(
    paths: Vec<String>,
    dest_root: &Path,
    q: String,
    mut notes: Vec<String>,
) -> Result<FetchReport, String> {
    let matched_total = paths.len();
    let mut limited = paths;
    let skipped = limited.len().saturating_sub(MAX_DOWNLOADS);
    if skipped > 0 {
        limited.truncate(MAX_DOWNLOADS);
        notes.push(format!(
            "Capped downloads at {MAX_DOWNLOADS} (remaining in this query: {skipped}). Re-fetch later or narrow/widen query in batches."
        ));
    }

    fs::create_dir_all(dest_root).map_err(|e| format!("mkdir templates: {e}"))?;

    let client = authed_client()?;
    let mut saved = Vec::new();
    for rel in &limited {
        match download_one(&client, rel, dest_root).await {
            Ok(p) => {
                notes.push(format!("Saved {}", p.display()));
                saved.push(p);
            }
            Err(e) => notes.push(format!("Skip {rel}: {e}")),
        }
    }

    if saved.is_empty() {
        return Err(format!(
            "Matched {} path(s) but none saved. Last notes: {}",
            matched_total,
            notes.last().cloned().unwrap_or_default()
        ));
    }

    let remain = matched_total.saturating_sub(saved.len());
    notes.push(format!(
        "Coverage note: this query has ~{matched_total} official file(s); saved {} now; ~{remain} not downloaded yet (cap/skips).",
        saved.len()
    ));

    Ok(FetchReport {
        saved,
        matched_total,
        skipped,
        query: q,
        notes,
    })
}

async fn collect_paths_under(client: &Client, path: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut stack = vec![path.to_string()];
    while let Some(cur) = stack.pop() {
        let url = format!("{API_ROOT}/contents/{cur}");
        let json = api_get_json(client, &url).await?;
        // File object vs array
        if json.is_object() {
            let item: ContentItem = serde_json::from_value(json)
                .map_err(|e| format!("parse content item: {e}"))?;
            if item.item_type == "file" && is_yaml_path(&item.path) {
                out.push(item.path);
            } else if item.item_type == "dir" {
                stack.push(item.path);
            }
            continue;
        }
        let items: Vec<ContentItem> =
            serde_json::from_value(json).map_err(|e| format!("parse content list: {e}"))?;
        for item in items {
            if item.item_type == "dir" {
                // Prefer diving into reasonable dirs; avoid huge trees without filter
                stack.push(item.path);
            } else if item.item_type == "file" && is_yaml_path(&item.path) {
                out.push(item.path);
            }
        }
        if out.len() > MAX_DOWNLOADS * 3 {
            break;
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[allow(dead_code)]
async fn collect_paths_by_keyword(client: &Client, keyword: &str) -> Result<Vec<String>, String> {
    let url = format!("{API_ROOT}/git/trees/main?recursive=1");
    let json = api_get_json(client, &url).await?;
    let tree: TreeResponse =
        serde_json::from_value(json).map_err(|e| format!("parse git tree: {e}"))?;
    if tree.truncated.unwrap_or(false) {
        // Still usable — filter what we got
    }
    let kw = keyword.to_lowercase();
    let mut paths: Vec<String> = tree
        .tree
        .into_iter()
        .filter(|t| t.item_type == "blob" && is_yaml_path(&t.path))
        .map(|t| t.path)
        .filter(|p| p.to_lowercase().contains(&kw))
        .collect();
    paths.sort();
    // Prefer http/ hits first for LogosCyber engine
    paths.sort_by_key(|p| if p.starts_with("http/") { 0 } else { 1 });
    Ok(paths)
}

async fn download_one(client: &Client, rel_path: &str, dest_root: &Path) -> Result<PathBuf, String> {
    let raw_url = format!("{RAW_ROOT}/{rel_path}");
    let mut req = client.get(&raw_url);
    if let Some(tok) = github_token() {
        // raw also accepts token for higher limits sometimes
        req = req.bearer_auth(tok);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("download {rel_path}: {e}"))?;
    if !resp.status().is_success() {
        // Fallback: contents API download_url
        let meta_url = format!("{API_ROOT}/contents/{rel_path}");
        let json = api_get_json(client, &meta_url).await?;
        let item: ContentItem =
            serde_json::from_value(json).map_err(|e| format!("meta parse: {e}"))?;
        let dl = item
            .download_url
            .ok_or_else(|| format!("no download_url for {rel_path}"))?;
        let body = client
            .get(dl)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .text()
            .await
            .map_err(|e| e.to_string())?;
        return write_template(dest_root, rel_path, &body);
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    write_template(dest_root, rel_path, &body)
}

fn write_template(dest_root: &Path, rel_path: &str, body: &str) -> Result<PathBuf, String> {
    let dest = dest_root.join(rel_path);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(&dest, body).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn path_detection() {
        assert!(looks_like_path("http/cves/2024"));
        assert!(looks_like_path("cves/2026/"));
        assert!(!looks_like_path("log4j"));
    }

    #[test]
    fn yaml_ext() {
        assert!(is_yaml_path("a/b.yaml"));
        assert!(!is_yaml_path("README.md"));
    }

    #[test]
    fn templates_dir_ends_with_templates() {
        let d = templates_dir();
        assert!(d.ends_with("templates"));
    }

    #[test]
    fn list_saved_yaml_updates_after_write() {
        let tmp = templates_dir().join("_test_list_mock");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("alpha.yaml"), "id: a\n").unwrap();
        let names = list_saved_yaml_names(&tmp).unwrap();
        assert!(names.iter().any(|n| n == "alpha.yaml"));
        fs::write(tmp.join("beta.yml"), "id: b\n").unwrap();
        let names2 = list_saved_yaml_names(&tmp).unwrap();
        assert_eq!(names2.len(), 2);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn coverage_math_from_empty_catalog() {
        let snap = compute_coverage("http/exposures/configs", None);
        assert_eq!(snap.remote_total, 0);
        assert!(snap.summary_lines().iter().any(|l| l.contains("防衛準備率")));
    }

    #[test]
    fn paths_matching_prefix() {
        let all = vec![
            "http/exposures/configs/a.yaml".into(),
            "http/cves/2024/x.yaml".into(),
            "dns/foo.yaml".into(),
        ];
        let m = paths_matching_query(&all, "http/exposures/configs");
        assert_eq!(m.len(), 1);
        let m2 = paths_matching_query(&all, "exposures");
        assert!(m2.len() >= 1);
    }

    #[test]
    fn fetch_template_path_validation() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(fetch_template_from_github("readme.md"));
        assert!(err.is_err());
        let err2 = rt.block_on(fetch_template_from_github(""));
        assert!(err2.is_err());
    }
}
