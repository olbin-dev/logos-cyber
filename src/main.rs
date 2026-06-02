mod engine;

use eframe::egui;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc;
use std::thread;
use std::fs;
use tokio::runtime::Runtime;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 750.0])
            .with_title("LogosCyber Security Scanner"),
        ..Default::default()
    };
    eframe::run_native(
        "LogosCyber",
        options,
        Box::new(|_cc| Ok(Box::new(LogosCyberApp::new()))),
    )
}

struct LogosCyberApp {
    target_url: String,
    proxy_url: String,
    yaml_input: String,
    loaded_templates: Vec<(String, String)>, // (Filename/Path, Content)
    scan_results: Vec<String>,
    tx: Sender<String>,
    rx: Receiver<String>,
    is_scanning: bool,
    scans_completed: usize,
    scans_total: usize,
    gemini_api_key: String,
    ai_model: String,
    ai_prompt: String,
}

impl LogosCyberApp {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            target_url: "http://example.com".to_owned(),
            proxy_url: "".to_owned(),
            yaml_input: "id: example-extractor-template\ninfo:\n  name: Example\n  author: user\n  severity: info\nrequests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: status\n        status:\n          - 200\n    extractors:\n      - type: regex\n        name: title\n        group: 1\n        regex:\n          - \"(?i)<title>(.*?)</title>\"".to_owned(),
            loaded_templates: vec![],
            scan_results: vec![],
            tx,
            rx,
            is_scanning: false,
            scans_completed: 0,
            scans_total: 0,
            gemini_api_key: "".to_owned(),
            ai_model: "gemini-2.5-pro".to_owned(),
            ai_prompt: "ログイン不要で /profile にアクセスして、メールアドレスが漏れないか確認するNucleiテンプレートを生成して".to_owned(),
        }
    }
}

impl eframe::App for LogosCyberApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Check for async results
        while let Ok(result) = self.rx.try_recv() {
            if result == "___SCAN_FINISHED___" {
                self.is_scanning = false;
            } else if result == "___SCAN_STEP___" {
                self.scans_completed += 1;
            } else if let Some(yaml) = result.strip_prefix("___AI_GENERATED___") {
                self.yaml_input = yaml.to_string();
                self.scan_results.push("✅ AI successfully generated the template.".to_string());
            } else {
                self.scan_results.push(result);
            }
        }

        // Left Panel: Configuration & Templates
        egui::Panel::left("config_panel")
            .resizable(true)
            .default_size(380.0)
            .show_inside(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("🎯 Target Configuration");
                    ui.separator();
                    
                    ui.label("Target URL / IP:");
                    ui.text_edit_singleline(&mut self.target_url);

                    ui.label("Proxy URL (Optional, e.g. socks5://127.0.0.1:1080):");
                    ui.text_edit_singleline(&mut self.proxy_url);
                    
                    ui.add_space(20.0);
                    ui.heading("🤖 AI Template Generator");
                    ui.label("Gemini API Key:");
                    ui.add(egui::TextEdit::singleline(&mut self.gemini_api_key).password(true));
                    ui.label("Model:");
                    ui.text_edit_singleline(&mut self.ai_model);
                    ui.label("What to test?");
                    ui.add(egui::TextEdit::multiline(&mut self.ai_prompt).desired_rows(3));
                    if ui.button("💡 Generate with AI").clicked() && !self.is_scanning {
                        self.generate_with_ai(ctx.clone());
                    }

                    ui.add_space(20.0);
                    ui.heading("📝 Quick YAML Template");
                    ui.label("Test a single Nuclei YAML template here:");
                    ui.add(egui::TextEdit::multiline(&mut self.yaml_input)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(12)
                        .desired_width(f32::INFINITY));
                    
                    ui.add_space(20.0);
                    ui.heading("📂 Load Templates Folder");
                    if ui.button("Select Folder...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.loaded_templates.clear();
                            for entry in walkdir::WalkDir::new(&path)
                                .into_iter()
                                .filter_map(Result::ok)
                                .filter(|e| !e.file_type().is_dir())
                            {
                                if let Some(ext) = entry.path().extension() {
                                    if ext == "yaml" || ext == "yml" {
                                        if let Ok(content) = fs::read_to_string(entry.path()) {
                                            self.loaded_templates.push((
                                                entry.path().display().to_string(),
                                                content,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !self.loaded_templates.is_empty() {
                        ui.label(format!("Loaded {} templates.", self.loaded_templates.len()));
                    }

                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        if ui.button("🚀 Run Quick Scan (Text)").clicked() && !self.is_scanning {
                            self.start_scan(vec![self.yaml_input.clone()], ctx.clone());
                        }
                        if ui.button("📂 Run Folder Scan").clicked() && !self.is_scanning {
                            if self.loaded_templates.is_empty() {
                                self.scan_results.push("Error: No templates loaded from folder.".to_string());
                            } else {
                                let templates = self.loaded_templates.iter().map(|(_, content)| content.clone()).collect();
                                self.start_scan(templates, ctx.clone());
                            }
                        }
                    });
                    
                    if self.is_scanning {
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(format!("Scanning... ({}/{})", self.scans_completed, self.scans_total));
                        });
                        ui.add(egui::ProgressBar::new(
                            if self.scans_total > 0 { self.scans_completed as f32 / self.scans_total as f32 } else { 0.0 }
                        ).animate(true));
                    }
                });
            });

        // Central Panel: Results & Logs
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("📊 Scan Results");
                if ui.button("Clear").clicked() {
                    self.scan_results.clear();
                }
            });
            ui.separator();
            
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for result in &self.scan_results {
                    ui.label(result);
                }
                
                if self.scan_results.is_empty() {
                    ui.label("No results yet. Enter a target and run a scan.");
                }
            });
        });
    }
}

impl LogosCyberApp {
    fn start_scan(&mut self, templates: Vec<String>, ctx: egui::Context) {
        self.is_scanning = true;
        self.scans_completed = 0;
        self.scans_total = templates.len();
        self.scan_results.push(format!("Starting scan on: {} ...", self.target_url));
        
        let target = self.target_url.clone();
        let proxy = if self.proxy_url.trim().is_empty() { None } else { Some(self.proxy_url.clone()) };
        let tx = self.tx.clone();
        
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                for yaml in templates {
                    match engine::run_scan(&target, &yaml, proxy.clone()).await {
                        Ok(res) => {
                            if res.matched {
                                let _ = tx.send(res.details);
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(format!("Error processing template: {}", e));
                        }
                    }
                    let _ = tx.send("___SCAN_STEP___".to_string());
                    ctx.request_repaint();
                }
            });
            let _ = tx.send("___SCAN_FINISHED___".to_string());
            ctx.request_repaint();
        });
    }

    fn generate_with_ai(&mut self, ctx: egui::Context) {
        self.is_scanning = true;
        self.scan_results.push(format!("Sending request to Gemini API..."));
        
        let api_key = self.gemini_api_key.clone();
        let model = self.ai_model.clone();
        let prompt = self.ai_prompt.clone();
        let tx = self.tx.clone();
        
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                if api_key.trim().is_empty() {
                    let _ = tx.send("Error: Gemini API Key is empty. Please enter your API key.".to_string());
                    return;
                }

                let target_url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", model, api_key.trim());
                let client = reqwest::Client::new();
                
                let payload = serde_json::json!({
                    "contents": [{
                        "parts": [{"text": format!("Please output ONLY valid YAML for a Nuclei template. Do not include markdown formatting. Prompt: {}", prompt)}]
                    }],
                    "safetySettings": [
                        { "category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE" },
                        { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE" },
                        { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE" },
                        { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE" }
                    ],
                    "generationConfig": {
                        "temperature": 0.1
                    }
                });
                
                match client.post(&target_url).json(&payload).send().await {
                    Ok(resp) => {
                        if let Ok(text) = resp.text().await {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                if let Some(content) = json["candidates"][0]["content"]["parts"][0]["text"].as_str() {
                                    let clean_yaml = content.replace("```yaml\n", "").replace("```\n", "").replace("```", "");
                                    let _ = tx.send(format!("___AI_GENERATED___{}", clean_yaml));
                                } else {
                                    let _ = tx.send(format!("AI Response Error. Raw: {}", text));
                                }
                            } else {
                                let _ = tx.send(format!("Failed to parse JSON. Raw: {}", text));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(format!("AI Request Failed: {}", e));
                    }
                }
            });
            let _ = tx.send("___SCAN_FINISHED___".to_string());
            ctx.request_repaint();
        });
    }
}
