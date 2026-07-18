use eframe::egui;
use eframe::egui::{FontData, FontDefinitions, FontFamily, RichText};
use logos_cyber::ai_gen;
use logos_cyber::engine;
use logos_cyber::github_templates;
use logos_cyber::proxy_guard::{
    fetch_public_ip, load_config, EgressIpView, ProxyHealth, ProxyMonitor,
};
use logos_cyber::report_style::{
    print_cli_line, print_cli_readiness, print_cli_residual_gap, residual_gap_tone,
    tone_from_finding, tone_from_log_line, tone_from_readiness_percent, Tone,
};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

fn tone_fg(tone: Tone) -> egui::Color32 {
    let (r, g, b) = tone.fg_rgb();
    egui::Color32::from_rgb(r, g, b)
}

fn tone_bg(tone: Tone) -> egui::Color32 {
    let (r, g, b) = tone.bg_rgb();
    egui::Color32::from_rgb(r, g, b)
}

fn tone_banner_bg(tone: Tone) -> egui::Color32 {
    let (r, g, b) = tone.banner_bg_rgb();
    egui::Color32::from_rgb(r, g, b)
}

/// Color-bordered section card for left panel / report grouping.
fn tone_section(
    ui: &mut egui::Ui,
    tone: Tone,
    title: &str,
    add_contents: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::none()
        .fill(tone_bg(tone))
        .stroke(egui::Stroke::new(2.0, tone_fg(tone)))
        .inner_margin(egui::style::Margin::same(8.0))
        .rounding(4.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(
                    tone_fg(tone),
                    RichText::new(format!("● {}", tone.label_ja())).small().strong(),
                );
                ui.label(RichText::new(title).strong());
            });
            ui.add_space(4.0);
            add_contents(ui);
        });
}

fn tone_callout(ui: &mut egui::Ui, tone: Tone, text: &str) {
    egui::Frame::none()
        .fill(tone_banner_bg(tone))
        .stroke(egui::Stroke::new(2.5, tone_fg(tone)))
        .inner_margin(egui::style::Margin::same(8.0))
        .rounding(4.0)
        .show(ui, |ui| {
            ui.colored_label(
                tone_fg(tone),
                RichText::new(text).strong(),
            );
        });
}

fn report_row(ui: &mut egui::Ui, tone: Tone, line: &str) {
    egui::Frame::none()
        .fill(tone_bg(tone))
        .stroke(egui::Stroke::new(1.5, tone_fg(tone)))
        .inner_margin(egui::style::Margin::symmetric(8.0, 4.0))
        .rounding(3.0)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    tone_fg(tone),
                    RichText::new(format!("[{}]", tone.label_en())).monospace().strong(),
                );
                ui.colored_label(tone_fg(tone), line);
            });
        });
    ui.add_space(3.0);
}

fn main() -> Result<(), eframe::Error> {
    let rt = Runtime::new().unwrap();
    let _guard = rt.enter();

    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(1280.0, 820.0)),
        ..Default::default()
    };
    eframe::run_native(
        "LogosCyber",
        options,
        Box::new(|cc| Box::new(LogosCyberApp::new(cc))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppMode {
    Scan,
    AttackerInsight,
}

#[derive(Debug, Clone)]
struct TemplateEntry {
    path: String,
    name: String,
    content: String,
    compat_score: u8,
    compat_line: String,
    parse_ok: bool,
}

#[derive(Debug, Clone)]
struct ScanLogEntry {
    template_id: String,
    matched: bool,
    severity: String,
    details: String,
    warnings: Vec<String>,
}

struct LogosCyberApp {
    mode: AppMode,
    target_url: String,
    proxy_url: String,
    require_proxy: bool,
    proxy_monitor: ProxyMonitor,
    egress_ip: EgressIpView,

    // Scan mode — template browser
    templates: Vec<TemplateEntry>,
    selected_idx: usize,
    template_filter: String,
    yaml_input: String,
    compat_summary: String,
    gh_query: String,
    is_fetching_github: bool,
    is_refreshing_catalog: bool,
    coverage_lines: Vec<String>,
    remote_catalog: Option<github_templates::RemoteCatalog>,

    // Logs shared → Insight context
    scan_results: Vec<String>,
    scan_log: Vec<ScanLogEntry>,

    // Attacker Insight
    insight_text: String,
    insight_status: String,

    tx: Sender<String>,
    rx: Receiver<String>,
    is_scanning: bool,
    is_generating: bool,
    scans_completed: usize,
    scans_total: usize,

    openrouter_api_key_override: String,
    ai_model: String,
    ai_prompt: String,
    ai_key_status: String,
    auto_scan_after_ai: bool,
    pending_ai_scan: bool,
}

impl LogosCyberApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_japanese_font(cc.egui_ctx.clone());
        let cfg = load_config();
        let (tx, rx) = mpsc::channel();
        let mut app = Self {
            mode: AppMode::Scan,
            target_url: "http://example.com".to_owned(),
            proxy_url: cfg.proxy_url,
            require_proxy: cfg.require_proxy,
            proxy_monitor: ProxyMonitor::new(),
            egress_ip: EgressIpView::default(),
            templates: vec![],
            selected_idx: 0,
            template_filter: String::new(),
            yaml_input: default_yaml_sample(),
            compat_summary: String::new(),
            gh_query: "http/exposures/configs".to_owned(),
            is_fetching_github: false,
            is_refreshing_catalog: false,
            coverage_lines: vec![
                "公式カタログを同期すると、防衛準備率（全体／Query別）が表示されます。".into(),
                "定義: クライアント資産を守るための『見える化された防衛準備率』。".into(),
            ],
            remote_catalog: github_templates::load_catalog_cache(),
            scan_results: vec![],
            scan_log: vec![],
            insight_text: String::new(),
            insight_status: "Scan Mode で診断を実行したあと、ここから攻撃者心理シミュレーションを起動できます。"
                .into(),
            tx,
            rx,
            is_scanning: false,
            is_generating: false,
            scans_completed: 0,
            scans_total: 0,
            openrouter_api_key_override: String::new(),
            ai_model: ai_gen::DEFAULT_MODEL.to_owned(),
            ai_prompt: "認可済み監査対象で、カスタムヘッダー X-App-Version の漏洩や異常な Server 指紋を攻撃者がどう悪用し得るか深く考えたうえで、安全に検知するHTTPテンプレートを作って".into(),
            ai_key_status: ai_gen::api_key_status(),
            auto_scan_after_ai: false,
            pending_ai_scan: false,
        };
        app.reload_local_templates();
        app.refresh_coverage_display();
        app
    }

    fn busy(&self) -> bool {
        self.is_scanning || self.is_generating || self.is_fetching_github || self.is_refreshing_catalog
    }

    fn refresh_coverage_display(&mut self) {
        let snap = github_templates::compute_coverage(
            &self.gh_query,
            self.remote_catalog.as_ref(),
        );
        self.coverage_lines = snap.summary_lines();
    }

    fn reload_local_templates(&mut self) {
        let dir = github_templates::templates_dir();
        if dir.is_dir() {
            let keep_selection = self
                .templates
                .get(self.selected_idx)
                .map(|t| t.path.clone());
            self.load_templates_folder(&dir, true);
            if let Some(path) = keep_selection {
                if let Some(i) = self.templates.iter().position(|t| t.path == path) {
                    self.select_template(i);
                }
            }
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let q = self.template_filter.to_lowercase();
        self.templates
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                q.is_empty()
                    || t.name.to_lowercase().contains(&q)
                    || t.path.to_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn select_template(&mut self, idx: usize) {
        if idx >= self.templates.len() {
            return;
        }
        self.selected_idx = idx;
        let t = &self.templates[idx];
        self.yaml_input = t.content.clone();
        self.compat_summary = t.compat_line.clone();
    }

    fn cycle_template(&mut self, delta: isize) {
        let ids = self.filtered_indices();
        if ids.is_empty() {
            return;
        }
        let pos = ids.iter().position(|&i| i == self.selected_idx).unwrap_or(0);
        let next = if delta >= 0 {
            (pos + 1) % ids.len()
        } else {
            (pos + ids.len() - 1) % ids.len()
        };
        self.select_template(ids[next]);
    }

    fn load_templates_folder(&mut self, path: &Path, quiet: bool) {
        self.templates.clear();
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !e.file_type().is_dir())
        {
            let Some(ext) = entry.path().extension() else {
                continue;
            };
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            let Ok(content) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let name = entry
                .path()
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("template")
                .to_string();
            let path_s = entry.path().display().to_string();
            let (score, line, ok) = match engine::parse_template(&content) {
                Ok(parsed) => {
                    let r = engine::analyze_compatibility(&parsed);
                    (r.score, r.summary_line(), true)
                }
                Err(e) => (0, format!("Parse error: {e}"), false),
            };
            self.templates.push(TemplateEntry {
                path: path_s,
                name,
                content,
                compat_score: score,
                compat_line: line,
                parse_ok: ok,
            });
        }
        self.templates.sort_by(|a, b| a.name.cmp(&b.name));
        if !self.templates.is_empty() {
            self.select_template(0);
            if !quiet {
                let avg = self.templates.iter().map(|t| t.compat_score as u32).sum::<u32>()
                    / self.templates.len() as u32;
                self.scan_results.push(format!(
                    "Loaded {} templates (avg compat ~{}%). Use ◀ ▶ or list to switch.",
                    self.templates.len(),
                    avg
                ));
            }
        } else if !quiet {
            self.scan_results
                .push("No .yaml/.yml templates found in folder.".into());
        }
    }

    fn resolve_api_key(&self) -> String {
        if !self.openrouter_api_key_override.trim().is_empty() {
            self.openrouter_api_key_override.trim().to_string()
        } else {
            ai_gen::openrouter_api_key().unwrap_or_default()
        }
    }

    fn insight_context(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("Target: {}", self.target_url));
        if !self.scan_log.is_empty() {
            parts.push("## Structured findings".into());
            for e in &self.scan_log {
                parts.push(format!(
                    "- [{}|{}] {} | {}",
                    if e.matched { "MATCH" } else { "clean" },
                    e.severity,
                    e.template_id,
                    e.details
                ));
                for w in &e.warnings {
                    parts.push(format!("  warning: {w}"));
                }
            }
        }
        parts.push("## Recent log tail".into());
        let tail: Vec<_> = self.scan_results.iter().rev().take(80).cloned().collect();
        for line in tail.into_iter().rev() {
            parts.push(line);
        }
        parts.join("\n")
    }
}

fn default_yaml_sample() -> String {
    "id: example-extractor-template\ninfo:\n  name: Example\n  author: user\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers-condition: and\n    matchers:\n      - type: status\n        status:\n          - 200\n      - type: word\n        words:\n          - \"</html>\"\n    extractors:\n      - type: regex\n        name: title\n        group: 1\n        regex:\n          - \"(?i)<title>(.*?)</title>\"".into()
}

fn apply_japanese_font(ctx: eframe::egui::Context) {
    let mut fonts = FontDefinitions::default();
    static NOTO_SANS_JP: &[u8] = include_bytes!("../assets/NotoSansCJKjp-Regular.otf");
    fonts
        .font_data
        .insert("noto_jp".to_owned(), FontData::from_static(NOTO_SANS_JP));
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .unwrap()
        .insert(0, "noto_jp".to_owned());
    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .unwrap()
        .insert(0, "noto_jp".to_owned());
    ctx.set_fonts(fonts);
}

impl eframe::App for LogosCyberApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.proxy_monitor.maybe_refresh(&self.proxy_url, false);
        if self.egress_ip.should_auto_refresh(Duration::from_secs(30)) {
            self.refresh_egress_ips(ctx.clone());
        }
        ctx.request_repaint_after(Duration::from_secs(2));

        while let Ok(result) = self.rx.try_recv() {
            if result == "___SCAN_FINISHED___" {
                self.is_scanning = false;
            } else if result == "___AI_FINISHED___" {
                self.is_generating = false;
            } else if result == "___SCAN_STEP___" {
                self.scans_completed += 1;
            } else if let Some(payload) = result.strip_prefix("___EGRESS_IP___") {
                let mut parts = payload.splitn(2, '|');
                let via = parts.next().unwrap_or("").to_string();
                let direct = parts.next().unwrap_or("").to_string();
                self.egress_ip.apply_result(via, direct);
            } else if let Some(payload) = result.strip_prefix("___SCAN_LOG___") {
                // matched|severity|template_id|details|||warnings joined by ;;
                let mut parts = payload.splitn(4, '|');
                let matched = parts.next().unwrap_or("0") == "1";
                let severity = parts.next().unwrap_or("info").to_string();
                let tid = parts.next().unwrap_or("?").to_string();
                let rest = parts.next().unwrap_or("");
                let (details, warn_s) = rest
                    .split_once("|||")
                    .map(|(d, w)| (d.to_string(), w.to_string()))
                    .unwrap_or_else(|| (rest.to_string(), String::new()));
                let warnings: Vec<String> = if warn_s.is_empty() {
                    vec![]
                } else {
                    warn_s.split(";;").map(|s| s.to_string()).collect()
                };
                let tone = tone_from_finding(&severity, matched);
                self.scan_log.push(ScanLogEntry {
                    template_id: tid.clone(),
                    matched,
                    severity: severity.clone(),
                    details: details.clone(),
                    warnings: warnings.clone(),
                });
                let flag = if matched { "MATCH" } else { "clean" };
                let line = format!("[{flag}|{severity}] {tid}: {details}");
                self.scan_results.push(line.clone());
                print_cli_line(tone, &line);
                for w in warnings {
                    let wline = format!("  ⚠ {w}");
                    self.scan_results.push(wline.clone());
                    print_cli_line(Tone::Warning, &wline);
                }
            } else if result == "___GH_FINISHED___" {
                self.is_fetching_github = false;
                self.remote_catalog = github_templates::load_catalog_cache();
                self.reload_local_templates();
                self.refresh_coverage_display();
                self.scan_results
                    .push("GitHub fetch finished — local templates/ list refreshed.".into());
            } else if result == "___CATALOG_FINISHED___" {
                self.is_refreshing_catalog = false;
                self.remote_catalog = github_templates::load_catalog_cache();
                self.refresh_coverage_display();
                let msg = "Official catalog refreshed — coverage % updated.";
                self.scan_results.push(msg.into());
                print_cli_line(Tone::Success, msg);
                if let Some(cat) = &self.remote_catalog {
                    let snap = github_templates::compute_coverage(&self.gh_query, Some(cat));
                    print_cli_readiness("全体防衛準備率", snap.library_percent());
                    if snap.query_remote > 0 {
                        print_cli_readiness("本Query防衛準備率", snap.query_percent());
                    }
                    print_cli_residual_gap();
                }
            } else if let Some(msg) = result.strip_prefix("___GH_STATUS___") {
                self.scan_results.push(msg.to_string());
            } else if let Some(path) = result.strip_prefix("___GH_SAVED___") {
                self.scan_results.push(format!("↓ saved {path}"));
            } else if let Some(raw) = result.strip_prefix("___AI_GENERATED___") {
                match ai_gen::prepare_template(raw) {
                    Ok(prep) => {
                        self.yaml_input = prep.yaml;
                        self.compat_summary = prep.compat.summary_line();
                        self.scan_results.push(format!(
                            "✅ Kimi template `{}` ready (compat {}%).",
                            prep.template_id, prep.compat.score
                        ));
                        for n in prep.notes {
                            self.scan_results.push(format!("  · {n}"));
                        }
                        if self.auto_scan_after_ai {
                            self.pending_ai_scan = true;
                        }
                    }
                    Err(e) => {
                        self.yaml_input = ai_gen::clean_ai_yaml(raw);
                        self.compat_summary = format!("AI validation failed: {e}");
                        self.scan_results
                            .push(format!("❌ AI output rejected by engine: {e}"));
                    }
                }
            } else if let Some(text) = result.strip_prefix("___INSIGHT___") {
                self.insight_text = text.to_string();
                self.insight_status = "Insight ready.".into();
                self.mode = AppMode::AttackerInsight;
            } else {
                self.scan_results.push(result);
            }
        }

        if self.is_generating || self.is_fetching_github || self.is_refreshing_catalog {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        if self.pending_ai_scan && !self.busy() {
            self.pending_ai_scan = false;
            let yaml = self.yaml_input.clone();
            self.start_scan(vec![yaml], ctx.clone());
        }

        // Top mode tabs
        egui::TopBottomPanel::top("mode_tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("LogosCyber");
                ui.separator();
                ui.selectable_value(&mut self.mode, AppMode::Scan, "① Scan Mode");
                ui.selectable_value(
                    &mut self.mode,
                    AppMode::AttackerInsight,
                    "② Attacker Insight Mode",
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(&self.ai_key_status).small());
                });
            });
        });

        match self.mode {
            AppMode::Scan => self.ui_scan_mode(ctx),
            AppMode::AttackerInsight => self.ui_insight_mode(ctx),
        }
    }
}

impl LogosCyberApp {
    fn ui_scan_mode(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("scan_side")
            .resizable(true)
            .default_width(400.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.ui_target_block(ui, ctx);
                    ui.add_space(12.0);
                    self.ui_template_browser(ui, ctx);
                    ui.add_space(12.0);
                    self.ui_ai_template_gen(ui, ctx);
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("📊 Scan Results / Response Log");
                if ui.button("Clear log").clicked() {
                    self.scan_results.clear();
                    self.scan_log.clear();
                }
                if ui
                    .button("→ Insight Mode")
                    .on_hover_text("このログをコンテキストに攻撃者心理シミュレーションへ")
                    .clicked()
                {
                    self.mode = AppMode::AttackerInsight;
                }
            });
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                for t in [Tone::Success, Tone::Warning, Tone::Important, Tone::Critical] {
                    ui.colored_label(
                        tone_fg(t),
                        RichText::new(format!("■ {}", t.label_ja())).small(),
                    );
                }
            });
            if !self.scan_log.is_empty() {
                let matches = self.scan_log.iter().filter(|e| e.matched).count();
                let crit = self
                    .scan_log
                    .iter()
                    .filter(|e| e.matched && e.severity.eq_ignore_ascii_case("critical"))
                    .count();
                ui.label(format!(
                    "Findings: {matches} match / {} total  (critical matches: {crit})",
                    self.scan_log.len()
                ));
            }
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for result in &self.scan_results {
                        report_row(ui, tone_from_log_line(result), result);
                    }
                    if self.scan_results.is_empty() {
                        ui.label("テンプレートを選び、Run Selected / Run All で診断を開始してください。");
                    }
                });
        });
    }

    fn ui_insight_mode(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("insight_side")
            .resizable(true)
            .default_width(360.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("🧠 Attacker Insight");
                    ui.label("スキャン結果をコンテキストに、Kimi K3 が攻撃者心理と本質防衛を推論します。");
                    ui.separator();
                    self.ui_ai_credentials(ui);
                    ui.add_space(8.0);
                    ui.label("Context preview (from Scan Mode):");
                    let preview = self.insight_context();
                    let short: String = preview.chars().take(500).collect();
                    ui.label(RichText::new(&short).monospace().small());
                    if preview.chars().count() > 500 {
                        ui.label("… (truncated; full context is sent to Kimi)");
                    }

                    ui.add_space(10.0);
                    let busy = self.busy();
                    if ui
                        .add_enabled(!busy, egui::Button::new("🔮 Run Attacker Insight (Kimi K3)"))
                        .clicked()
                    {
                        self.run_attacker_insight(ctx.clone());
                    }
                    if self.is_generating {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Kimi K3 reasoning… UI stays responsive.");
                        });
                    }
                    ui.label(RichText::new(&self.insight_status).italics());
                    ui.add_space(8.0);
                    if ui.button("← Back to Scan Mode").clicked() {
                        self.mode = AppMode::Scan;
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Attacker Insight Briefing");
                if ui.button("Clear").clicked() {
                    self.insight_text.clear();
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                if self.insight_text.is_empty() {
                    ui.label("まだブリーフィングはありません。左の Run Attacker Insight を実行してください。");
                } else {
                    for block in self.insight_text.split("\n\n") {
                        let t = block.trim();
                        if t.is_empty() {
                            continue;
                        }
                        let tone = if t.contains("緊急") || t.contains("即時") || t.contains("Critical")
                        {
                            Tone::Critical
                        } else if t.contains("横展開") || t.contains("リスク") || t.contains("重要")
                        {
                            Tone::Important
                        } else if t.contains("注意") || t.contains("警告") || t.contains("更新")
                        {
                            Tone::Warning
                        } else if t.starts_with("──") || t.starts_with('#') {
                            Tone::Success
                        } else {
                            tone_from_log_line(t)
                        };
                        if t.starts_with('#') {
                            ui.add_space(8.0);
                            ui.colored_label(
                                tone_fg(tone),
                                RichText::new(t.trim_start_matches('#').trim()).strong().size(18.0),
                            );
                        } else {
                            report_row(ui, tone, t);
                        }
                    }
                }
            });
        });
    }

    fn ui_target_block(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let tone = match &self.proxy_monitor.health {
            ProxyHealth::Ok if self.egress_ip.vpn_status_label().contains("ACTIVE") => {
                Tone::Success
            }
            ProxyHealth::Down(_) => Tone::Critical,
            ProxyHealth::Unknown if self.require_proxy => Tone::Warning,
            _ => Tone::Success,
        };
        tone_section(ui, tone, "🎯 Target / Proxy", |ui| {
            ui.label("Target URL / IP:");
            ui.text_edit_singleline(&mut self.target_url);
            ui.label("Proxy URL (scan only):");
            ui.text_edit_singleline(&mut self.proxy_url);
            ui.checkbox(
                &mut self.require_proxy,
                "Require Proton proxy (refuse scan if down)",
            );
            ui.horizontal(|ui| {
                ui.label(self.proxy_monitor.label());
                if ui.button("Recheck").clicked() {
                    self.proxy_monitor.maybe_refresh(&self.proxy_url, true);
                    self.refresh_egress_ips(ctx.clone());
                }
            });
            if let ProxyHealth::Down(msg) = &self.proxy_monitor.health {
                ui.colored_label(tone_fg(Tone::Critical), msg);
            }
            ui.label(format!(
                "Egress via proxy: {} | Direct: {}",
                if self.egress_ip.via_proxy.is_empty() {
                    "…"
                } else {
                    &self.egress_ip.via_proxy
                },
                if self.egress_ip.direct.is_empty() {
                    "…"
                } else {
                    &self.egress_ip.direct
                }
            ));
            let vpn_tone = if self.egress_ip.vpn_status_label().contains("ACTIVE") {
                Tone::Success
            } else {
                Tone::Warning
            };
            ui.colored_label(tone_fg(vpn_tone), self.egress_ip.vpn_status_label());
        });
    }

    fn ui_template_browser(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let (lib_pct, query_pct, has_catalog) = if let Some(cat) = &self.remote_catalog {
            let snap = github_templates::compute_coverage(&self.gh_query, Some(cat));
            (snap.library_percent(), snap.query_percent(), true)
        } else {
            (0.0, 0.0, false)
        };
        let readiness_tone = if has_catalog {
            // Prefer query focus when available; else whole library.
            if query_pct > 0.0 {
                tone_from_readiness_percent(query_pct)
            } else {
                tone_from_readiness_percent(lib_pct)
            }
        } else {
            Tone::Warning
        };

        tone_section(ui, readiness_tone, "📦 Template Manager / 防衛準備率", |ui| {
            ui.label(RichText::new("GitHub realtime fetch").strong());
            ui.label("projectdiscovery/nuclei-templates から最新 YAML を取得 → templates/");
            ui.horizontal(|ui| {
                ui.label("Query:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.gh_query)
                        .desired_width(220.0)
                        .hint_text("log4j  or  http/cves/2024"),
                );
                if resp.changed() {
                    self.refresh_coverage_display();
                }
            });
            ui.horizontal(|ui| {
                let can_fetch = !self.is_fetching_github && !self.gh_query.trim().is_empty();
                if ui
                    .add_enabled(can_fetch, egui::Button::new("☁ Fetch from GitHub"))
                    .clicked()
                {
                    self.fetch_from_github(ctx.clone());
                }
                if ui.small_button("Reload templates/").clicked() {
                    self.reload_local_templates();
                    self.refresh_coverage_display();
                    self.scan_results.push("Reloaded local templates/.".into());
                }
            });
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.is_refreshing_catalog && !self.is_fetching_github,
                        egui::Button::new("📊 公式カタログ更新（全体件数）"),
                    )
                    .on_hover_text("公式リポジトリの YAML 総数を同期し、防衛準備率を更新します")
                    .clicked()
                {
                    self.refresh_official_catalog(ctx.clone());
                }
            });
            if self.is_fetching_github {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Fetching from GitHub (async)…");
                });
            }
            if self.is_refreshing_catalog {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Refreshing official catalog counts…");
                });
            }

            ui.add_space(6.0);
            ui.colored_label(
                tone_fg(readiness_tone),
                RichText::new("防衛準備率（Visible Defense Readiness）").strong(),
            );
            ui.label(
                RichText::new(
                    "最新攻撃トレンドに対するテンプレ配備の達成度。色は達成度に応じて動的に変化します。",
                )
                .small(),
            );
            for line in &self.coverage_lines {
                let line_tone = if line.contains("残差") {
                    residual_gap_tone()
                } else if line.contains("防衛準備率") || line.contains("今回フォーカス") {
                    readiness_tone
                } else {
                    Tone::Success
                };
                ui.colored_label(tone_fg(line_tone), RichText::new(line).small());
            }

            if has_catalog {
                let lib_tone = tone_from_readiness_percent(lib_pct);
                ui.add(
                    egui::ProgressBar::new((lib_pct / 100.0).clamp(0.0, 1.0))
                        .fill(tone_fg(lib_tone))
                        .text(format!(
                            "全体準備率 {:.1}%  [{}]",
                            lib_pct,
                            lib_tone.label_ja()
                        )),
                );
                if query_pct > 0.0 || self.remote_catalog.as_ref().is_some() {
                    let q_tone = tone_from_readiness_percent(query_pct);
                    ui.add(
                        egui::ProgressBar::new((query_pct / 100.0).clamp(0.0, 1.0))
                            .fill(tone_fg(q_tone))
                            .text(format!(
                                "本Query準備率 {:.1}%  [{}]",
                                query_pct,
                                q_tone.label_ja()
                            )),
                    );
                }
                // Echo readiness to CLI when catalog is present (once per paint is noisy —
                // only on catalog refresh we print; here GUI only).
            }

            ui.add_space(6.0);
            tone_callout(
                ui,
                residual_gap_tone(),
                "残差1%領域（未知のゼロデイ等）— 定点観測とプロによる継続監視で補完。経営判断の重点ゾーンです。",
            );

            ui.label(
                RichText::new(format!(
                    "Save dir: {}",
                    github_templates::templates_dir().display()
                ))
                .small()
                .weak(),
            );
        });

        ui.add_space(10.0);

        let list_tone = Tone::Success;
        tone_section(ui, list_tone, "Local templates/ (click to load)", |ui| {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.template_filter);
            });

            let filtered = self.filtered_indices();
            ui.horizontal(|ui| {
                if ui.button("◀ Prev").clicked() {
                    self.cycle_template(-1);
                }
                if ui.button("Next ▶").clicked() {
                    self.cycle_template(1);
                }
                if !self.templates.is_empty() {
                    ui.label(format!(
                        "{}/{}  (shown {})",
                        self.selected_idx + 1,
                        self.templates.len(),
                        filtered.len()
                    ));
                }
            });

            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    if filtered.is_empty() {
                        ui.label("templates/ が空です。上で Fetch from GitHub するかローカルを配置してください。");
                    }
                    for &i in &filtered {
                        let t = &self.templates[i];
                        let row_tone = if !t.parse_ok {
                            Tone::Critical
                        } else if t.compat_score >= 70 {
                            Tone::Success
                        } else if t.compat_score >= 40 {
                            Tone::Warning
                        } else {
                            Tone::Important
                        };
                        let label = if t.parse_ok {
                            format!("[{}%] {}", t.compat_score, t.name)
                        } else {
                            format!("[ERR] {}", t.name)
                        };
                        let selected = i == self.selected_idx;
                        let resp = ui.selectable_label(
                            selected,
                            RichText::new(label).color(tone_fg(row_tone)),
                        );
                        if resp.clicked() {
                            self.select_template(i);
                        }
                    }
                });

            if let Some(t) = self.templates.get(self.selected_idx) {
                let color = if t.compat_score >= 70 {
                    Tone::Success
                } else if t.compat_score >= 40 {
                    Tone::Warning
                } else {
                    Tone::Critical
                };
                ui.colored_label(tone_fg(color), &t.compat_line);
                ui.label(RichText::new(&t.path).small().weak());
            }

            ui.add_space(6.0);
            ui.label("YAML editor (カチカチ選択で即反映):");
            ui.add(
                egui::TextEdit::multiline(&mut self.yaml_input)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            if ui.button("🔎 Re-analyze Compat").clicked() {
                self.refresh_compat_for_yaml(&self.yaml_input.clone());
            }
            if !self.compat_summary.is_empty() {
                ui.colored_label(tone_fg(Tone::Success), &self.compat_summary);
            }

            let busy = self.busy();
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("🚀 Run Selected"))
                    .clicked()
                {
                    self.start_scan(vec![self.yaml_input.clone()], ctx.clone());
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("📂 Run Filtered / All"))
                    .clicked()
                {
                    let ids = self.filtered_indices();
                    if ids.is_empty() {
                        self.scan_results.push("No templates to run.".into());
                    } else {
                        let templates: Vec<String> =
                            ids.iter().map(|&i| self.templates[i].content.clone()).collect();
                        self.start_scan(templates, ctx.clone());
                    }
                }
            });
            if self.is_scanning {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!(
                        "Scanning… ({}/{})",
                        self.scans_completed, self.scans_total
                    ));
                });
                ui.add(
                    egui::ProgressBar::new(if self.scans_total > 0 {
                        self.scans_completed as f32 / self.scans_total as f32
                    } else {
                        0.0
                    })
                    .fill(tone_fg(Tone::Success))
                    .animate(true),
                );
            }

            ui.add_space(4.0);
            if ui
                .small_button("Also open external folder…")
                .on_hover_text("任意フォルダを追加読み込み（マージではなく置き換え）")
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.load_templates_folder(&path, false);
                }
            }
        });
    }

    fn fetch_from_github(&mut self, ctx: egui::Context) {
        let query = self.gh_query.trim().to_string();
        if query.is_empty() {
            self.scan_results.push("GitHub query is empty.".into());
            return;
        }
        self.is_fetching_github = true;
        self.scan_results.push(format!(
            "GitHub: searching/downloading `{query}` from {REPO} …",
            REPO = "projectdiscovery/nuclei-templates"
        ));
        let dest = github_templates::templates_dir();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let _ = tx.send(format!(
                "___GH_STATUS___Fetching into {} …",
                dest.display()
            ));
            ctx.request_repaint();

            match github_templates::fetch_and_save(&query, &dest).await {
                Ok(report) => {
                    for n in &report.notes {
                        let _ = tx.send(format!("___GH_STATUS___{n}"));
                    }
                    for p in &report.saved {
                        let _ = tx.send(format!("___GH_SAVED___{}", p.display()));
                    }
                    let _ = tx.send(format!(
                        "___GH_STATUS___Done: saved {} / matched {} for query `{}` (skipped by cap: {}).",
                        report.saved.len(),
                        report.matched_total,
                        report.query,
                        report.skipped
                    ));
                }
                Err(e) => {
                    let _ = tx.send(format!("___GH_STATUS___GitHub fetch error: {e}"));
                }
            }
            let _ = tx.send("___GH_FINISHED___".into());
            ctx.request_repaint();
        });
    }

    fn refresh_official_catalog(&mut self, ctx: egui::Context) {
        self.is_refreshing_catalog = true;
        self.scan_results
            .push("Refreshing official nuclei-templates catalog (YAML counts)…".into());
        let tx = self.tx.clone();
        tokio::spawn(async move {
            match github_templates::refresh_remote_catalog().await {
                Ok(cat) => {
                    let _ = tx.send(format!(
                        "___GH_STATUS___Catalog OK: {} YAML paths (http/: {}).",
                        cat.yaml_paths.len(),
                        cat.yaml_paths.iter().filter(|p| p.starts_with("http/")).count()
                    ));
                }
                Err(e) => {
                    let _ = tx.send(format!("___GH_STATUS___Catalog refresh error: {e}"));
                }
            }
            let _ = tx.send("___CATALOG_FINISHED___".into());
            ctx.request_repaint();
        });
    }

    fn ui_ai_credentials(&mut self, ui: &mut egui::Ui) {
        ui.colored_label(
            if self.ai_key_status.contains("loaded") {
                egui::Color32::from_rgb(40, 160, 80)
            } else {
                egui::Color32::from_rgb(220, 80, 80)
            },
            &self.ai_key_status,
        );
        ui.label("API key override (optional):");
        ui.add(
            egui::TextEdit::singleline(&mut self.openrouter_api_key_override).password(true),
        );
        if ui.small_button("Reload .env status").clicked() {
            self.ai_key_status = ai_gen::api_key_status();
        }
        ui.label("Model:");
        ui.text_edit_singleline(&mut self.ai_model);
    }

    fn ui_ai_template_gen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let ai_tone = if self.ai_key_status.contains("loaded") {
            Tone::Success
        } else {
            Tone::Warning
        };
        tone_section(ui, ai_tone, "🤖 AI Template (optional)", |ui| {
        ui.label("Kimi K3 → 検知YAML生成");
        self.ui_ai_credentials(ui);
        ui.label("Prompt:");
        ui.add(egui::TextEdit::multiline(&mut self.ai_prompt).desired_rows(2));
        ui.checkbox(
            &mut self.auto_scan_after_ai,
            "Generate 後に自動 Quick Scan",
        );
        let busy = self.busy();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("💡 Generate YAML"))
                .clicked()
            {
                self.generate_with_ai(ctx.clone());
            }
            if ui
                .add_enabled(!busy, egui::Button::new("💡➔🚀 Generate + Scan"))
                .clicked()
            {
                self.auto_scan_after_ai = true;
                self.generate_with_ai(ctx.clone());
            }
        });
        if self.is_generating && self.mode == AppMode::Scan {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Kimi generating template…");
            });
        }
        });
    }

    fn refresh_egress_ips(&mut self, ctx: egui::Context) {
        if self.egress_ip.fetching {
            return;
        }
        self.egress_ip.mark_fetching();
        let proxy = self.proxy_url.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let via = match fetch_public_ip(Some(proxy.as_str())).await {
                Ok(ip) => ip,
                Err(e) => format!("ERR: {e}"),
            };
            let direct = match fetch_public_ip(None).await {
                Ok(ip) => ip,
                Err(e) => format!("ERR: {e}"),
            };
            let _ = tx.send(format!("___EGRESS_IP___{via}|{direct}"));
            ctx.request_repaint();
        });
    }

    fn ensure_proxy_ready(&mut self) -> bool {
        if !self.require_proxy {
            return true;
        }
        if self.proxy_url.trim().is_empty() {
            self.scan_results.push(
                "Scan blocked: Require Proton proxy is ON but Proxy URL is empty.".into(),
            );
            return false;
        }
        self.proxy_monitor.maybe_refresh(&self.proxy_url, true);
        match &self.proxy_monitor.health {
            ProxyHealth::Ok => true,
            ProxyHealth::Down(err) => {
                self.scan_results.push(format!(
                    "Scan blocked (kill switch): {err}. See docs/PROTON_SOCKS.md"
                ));
                false
            }
            ProxyHealth::Unknown => {
                self.scan_results.push(
                    "Scan blocked: Proxy health unknown. Click Recheck.".into(),
                );
                false
            }
        }
    }

    fn start_scan(&mut self, templates: Vec<String>, ctx: egui::Context) {
        if !self.ensure_proxy_ready() {
            return;
        }
        self.is_scanning = true;
        self.scans_completed = 0;
        self.scans_total = templates.len();
        self.scan_results
            .push(format!("Starting scan on: {} …", self.target_url));
        if !self.proxy_url.trim().is_empty() {
            self.scan_results
                .push(format!("Using proxy: {}", self.proxy_url.trim()));
        }

        let target = self.target_url.clone();
        let proxy = if self.proxy_url.trim().is_empty() {
            None
        } else {
            Some(self.proxy_url.clone())
        };
        let tx = self.tx.clone();

        tokio::spawn(async move {
            for yaml in templates {
                match engine::run_scan(&target, &yaml, proxy.clone()).await {
                    Ok(res) => {
                        let warns = res.warnings.join(";;");
                        let sev = res.severity.replace('|', "_");
                        let _ = tx.send(format!(
                            "___SCAN_LOG___{}|{}|{}|{}|||{}",
                            if res.matched { "1" } else { "0" },
                            sev,
                            res.template_id.replace('|', "_"),
                            res.details.replace('|', "/").replace("|||", " / "),
                            warns.replace('|', "/")
                        ));
                    }
                    Err(e) => {
                        let _ = tx.send(format!("Error processing template: {e}"));
                    }
                }
                let _ = tx.send("___SCAN_STEP___".into());
                ctx.request_repaint();
            }
            let _ = tx.send("___SCAN_FINISHED___".into());
            ctx.request_repaint();
        });
    }

    fn refresh_compat_for_yaml(&mut self, yaml: &str) {
        match engine::parse_template(yaml) {
            Ok(parsed) => {
                let report = engine::analyze_compatibility(&parsed);
                self.compat_summary = report.summary_line();
                self.scan_results.push(format!(
                    "Template `{}`: {}",
                    parsed.id,
                    report.summary_line()
                ));
            }
            Err(e) => {
                self.compat_summary = format!("Parse error: {e}");
                self.scan_results
                    .push(format!("Compat analyze failed: {e}"));
            }
        }
    }

    fn generate_with_ai(&mut self, ctx: egui::Context) {
        self.is_generating = true;
        self.scan_results.push(format!(
            "OpenRouter/Kimi K3: template generation (timeout {}s)…",
            ai_gen::AI_HTTP_TIMEOUT_SECS
        ));
        let api_key = self.resolve_api_key();
        let model = self.ai_model.clone();
        let user_prompt = self.ai_prompt.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            if api_key.is_empty() {
                let _ = tx.send("Error: OPENROUTER_API_KEY is empty.".into());
                let _ = tx.send("___AI_FINISHED___".into());
                ctx.request_repaint();
                return;
            }
            let alive = Arc::new(AtomicBool::new(true));
            let alive_hb = alive.clone();
            let tx_hb = tx.clone();
            let ctx_hb = ctx.clone();
            tokio::spawn(async move {
                let mut ticks = 0u32;
                while alive_hb.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if !alive_hb.load(Ordering::Relaxed) {
                        break;
                    }
                    ticks += 1;
                    let _ = tx_hb.send(format!("… Kimi still reasoning ({ticks}×5s)"));
                    ctx_hb.request_repaint();
                }
            });

            match ai_gen::call_openrouter(&api_key, &model, &user_prompt).await {
                Ok(reply) => {
                    let yaml_src = ai_gen::extract_yaml_from_reply(&reply);
                    let _ = tx.send(format!("___AI_GENERATED___{yaml_src}"));
                }
                Err(e) => {
                    let _ = tx.send(format!("OpenRouter/Kimi error: {e}"));
                }
            }
            alive.store(false, Ordering::Relaxed);
            let _ = tx.send("___AI_FINISHED___".into());
            ctx.request_repaint();
        });
    }

    fn run_attacker_insight(&mut self, ctx: egui::Context) {
        self.is_generating = true;
        self.insight_status = format!(
            "Kimi K3 attacker-psychology simulation running (timeout {}s)…",
            ai_gen::AI_HTTP_TIMEOUT_SECS
        );
        let api_key = self.resolve_api_key();
        let model = self.ai_model.clone();
        let target = self.target_url.clone();
        let context = self.insight_context();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            if api_key.is_empty() {
                let _ = tx.send("Error: OPENROUTER_API_KEY is empty.".into());
                let _ = tx.send("___AI_FINISHED___".into());
                ctx.request_repaint();
                return;
            }
            let alive = Arc::new(AtomicBool::new(true));
            let alive_hb = alive.clone();
            let tx_hb = tx.clone();
            let ctx_hb = ctx.clone();
            tokio::spawn(async move {
                let mut ticks = 0u32;
                while alive_hb.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if !alive_hb.load(Ordering::Relaxed) {
                        break;
                    }
                    ticks += 1;
                    let _ = tx_hb.send(format!("… Insight reasoning ({ticks}×5s)"));
                    ctx_hb.request_repaint();
                }
            });

            match ai_gen::call_attacker_insight(&api_key, &model, &target, &context).await {
                Ok(reply) => {
                    let display = ai_gen::format_insight_display(&reply);
                    let _ = tx.send(format!("___INSIGHT___{display}"));
                }
                Err(e) => {
                    let _ = tx.send(format!("Insight error: {e}"));
                }
            }
            alive.store(false, Ordering::Relaxed);
            let _ = tx.send("___AI_FINISHED___".into());
            ctx.request_repaint();
        });
    }
}
