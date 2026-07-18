use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const DEFAULT_PROXY_URL: &str = "socks5://127.0.0.1:1080";

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub proxy_url: String,
    pub require_proxy: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy_url: DEFAULT_PROXY_URL.to_owned(),
            require_proxy: true,
        }
    }
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    proxy_url: Option<String>,
    require_proxy: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHealth {
    Unknown,
    Ok,
    Down(String),
}

pub fn config_path() -> PathBuf {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("logos_cyber").join("config.toml")
}

pub fn load_config() -> AppConfig {
    let mut cfg = AppConfig::default();

    let path = config_path();
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(file) = toml::from_str::<FileConfig>(&raw) {
            if let Some(url) = file.proxy_url {
                if !url.trim().is_empty() {
                    cfg.proxy_url = url;
                }
            }
            if let Some(req) = file.require_proxy {
                cfg.require_proxy = req;
            }
        }
    }

    if let Ok(url) = env::var("LOGOSCYBER_PROXY_URL") {
        if !url.trim().is_empty() {
            cfg.proxy_url = url;
        }
    }
    if let Ok(req) = env::var("LOGOSCYBER_REQUIRE_PROXY") {
        match req.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => cfg.require_proxy = true,
            "0" | "false" | "no" | "off" => cfg.require_proxy = false,
            _ => {}
        }
    }

    cfg
}

/// Extract host:port from socks/http proxy URL for a TCP reachability probe.
pub fn proxy_socket_addr(proxy_url: &str) -> Result<(String, u16), String> {
    let url = proxy_url.trim();
    if url.is_empty() {
        return Err("Proxy URL is empty".to_string());
    }

    let rest = url
        .strip_prefix("socks5h://")
        .or_else(|| url.strip_prefix("socks5://"))
        .or_else(|| url.strip_prefix("socks4://"))
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let rest = rest.split('/').next().unwrap_or(rest);
    let (host, port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("Proxy URL missing port: {}", proxy_url))?;

    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("Proxy URL missing host: {}", proxy_url));
    }

    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("Proxy URL has invalid port: {}", proxy_url))?;

    Ok((host.to_string(), port))
}

pub fn check_proxy_reachable(proxy_url: &str, timeout: Duration) -> Result<(), String> {
    let (host, port) = proxy_socket_addr(proxy_url)?;
    let addr_str = format!("{}:{}", host, port);
    let mut addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("Proxy unreachable: {} ({})", proxy_url, e))?;
    let addr = addrs
        .next()
        .ok_or_else(|| format!("Proxy unreachable: {} (no address)", proxy_url))?;

    TcpStream::connect_timeout(&addr, timeout)
        .map(|_| ())
        .map_err(|e| format!("Proxy unreachable: {} ({})", proxy_url, e))
}

pub struct ProxyMonitor {
    pub health: ProxyHealth,
    last_check: Instant,
    interval: Duration,
}

impl ProxyMonitor {
    pub fn new() -> Self {
        Self {
            health: ProxyHealth::Unknown,
            last_check: Instant::now() - Duration::from_secs(60),
            interval: Duration::from_secs(2),
        }
    }

    pub fn maybe_refresh(&mut self, proxy_url: &str, force: bool) {
        if !force && self.last_check.elapsed() < self.interval {
            return;
        }
        self.last_check = Instant::now();
        if proxy_url.trim().is_empty() {
            self.health = ProxyHealth::Down("Proxy URL is empty".to_string());
            return;
        }
        match check_proxy_reachable(proxy_url, Duration::from_millis(400)) {
            Ok(()) => self.health = ProxyHealth::Ok,
            Err(e) => self.health = ProxyHealth::Down(e),
        }
    }

    pub fn label(&self) -> String {
        match &self.health {
            ProxyHealth::Unknown => "Proxy: …".to_string(),
            ProxyHealth::Ok => "Proxy: OK".to_string(),
            ProxyHealth::Down(_) => "Proxy: DOWN".to_string(),
        }
    }
}

/// Fetch the public IP as seen by `https://api.ipify.org`.
/// When `proxy_url` is Some, the request goes through that proxy (scan egress).
/// When None, the request is direct from this Mac (home / ISP IP).
pub async fn fetch_public_ip(proxy_url: Option<&str>) -> Result<String, String> {
    let mut builder = Client::builder().timeout(Duration::from_secs(10));

    match proxy_url {
        Some(url) if !url.trim().is_empty() => {
            let proxy = reqwest::Proxy::all(url.trim())
                .map_err(|e| format!("Proxy config error: {}", e))?;
            builder = builder.proxy(proxy);
        }
        _ => {
            builder = builder.no_proxy();
        }
    }

    let client = builder.build().map_err(|e| e.to_string())?;
    let body = client
        .get("https://api.ipify.org")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;

    let ip = body.trim().to_string();
    if ip.is_empty() {
        return Err("Empty IP response".to_string());
    }
    Ok(ip)
}

#[derive(Debug, Clone, Default)]
pub struct EgressIpView {
    pub via_proxy: String,
    pub direct: String,
    pub fetching: bool,
    pub last_error: String,
    last_fetch: Option<Instant>,
}

impl EgressIpView {
    pub fn vpn_status_label(&self) -> String {
        if self.fetching {
            return "VPN egress: checking…".to_string();
        }
        let via = self.via_proxy.trim();
        let direct = self.direct.trim();
        if via.is_empty() || direct.is_empty() {
            return "VPN egress: unknown (click Recheck)".to_string();
        }
        if via.starts_with("ERR:") || direct.starts_with("ERR:") {
            return "VPN egress: check failed".to_string();
        }
        if via == direct {
            "VPN egress: SAME AS DIRECT (proxy not masking IP)".to_string()
        } else {
            "VPN egress: ACTIVE (differs from direct)".to_string()
        }
    }

    pub fn should_auto_refresh(&self, interval: Duration) -> bool {
        if self.fetching {
            return false;
        }
        match self.last_fetch {
            None => true,
            Some(t) => t.elapsed() >= interval,
        }
    }

    pub fn mark_fetching(&mut self) {
        self.fetching = true;
        self.last_error.clear();
    }

    pub fn apply_result(&mut self, via: String, direct: String) {
        self.via_proxy = via;
        self.direct = direct;
        self.fetching = false;
        self.last_fetch = Some(Instant::now());
        self.last_error.clear();
    }
}
