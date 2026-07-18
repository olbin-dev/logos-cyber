//! OpenRouter (Kimi K3) → LogosCyber engine bridge: prompts, cleanup, and validation.

use crate::engine::{analyze_compatibility, parse_template, CompatReport};
use reqwest::Client;
use serde_json::Value;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_MODEL: &str = "moonshotai/kimi-k3";
pub const OPENROUTER_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
/// Kimi K3 reasoning can take several minutes.
pub const AI_HTTP_TIMEOUT_SECS: u64 = 300;

/// Result of preparing AI output for the scan pipeline.
#[derive(Debug, Clone)]
pub struct PreparedTemplate {
    pub yaml: String,
    pub template_id: String,
    pub compat: CompatReport,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OpenRouterReply {
    pub content: String,
    pub reasoning: String,
}

/// Load `.env` from the crate dir and its parent (repo root `32_LogosCyber/.env`).
pub fn load_dotenv() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let _ = dotenvy::from_path(manifest.join(".env"));
    let _ = dotenvy::from_path(manifest.join("..").join(".env"));
    let _ = dotenvy::dotenv(); // cwd
}

pub fn openrouter_api_key() -> Option<String> {
    load_dotenv();
    env::var("OPENROUTER_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Masked status for the GUI (never show the full key).
pub fn api_key_status() -> String {
    match openrouter_api_key() {
        Some(k) if k.len() > 8 => format!(
            "OPENROUTER_API_KEY loaded (…{})",
            &k[k.len().saturating_sub(4)..]
        ),
        Some(_) => "OPENROUTER_API_KEY loaded".into(),
        None => "OPENROUTER_API_KEY missing — set it in ../.env".into(),
    }
}

/// Deep adversary-simulation prompt; final artifact must remain a detection template.
pub fn build_generation_prompt(user_request: &str) -> String {
    format!(
        r#"You are LogosCyber's senior offensive-security analyst compiling DEFENSIVE Nuclei templates.
You think like an advanced adversary (chaining, misconfig abuse, auth bypass patterns, header/path tricks),
THEN emit a detection template that safely confirms exposure — never a weaponized exploit runner.

## THINKING (internal — do NOT put this in the final answer block)
1. Threat model: what would a skilled attacker try against the described surface?
2. Preconditions, signals, false positives.
3. Minimal HTTP checks that prove the issue without destructive payloads / RCE shells.

## FINAL OUTPUT RULES (mandatory)
- After thinking, output ONE Nuclei-compatible YAML document for LogosCyber's Rust engine.
- Prefer wrapping the YAML in a ```yaml fence so parsers can extract it cleanly.
- Use modern top-level key `http:` (NEVER `requests:`; never dns/tcp/ssl/file/headless/code).
- Include: `id` (kebab-case), `info` (name, author: logoscyber-kimi, severity), ≥1 http request.
- Prefer method+path with {{{{BaseURL}}}}; use raw: only when needed.
- If 2+ matchers: `matchers-condition: and`.
- Matcher part: body|header|all. Types ONLY: status, word, regex, size, binary, dsl.
- Extractor types ONLY: regex, kval, json, dsl (no xpath).
- DSL subset: status_code==N, len(body)>N, contains(body,'x'), contains(to_lower(body),'x'), !contains(...)
- Vars: {{{{BaseURL}}}}, {{{{Hostname}}}}, {{{{Host}}}}, {{{{Port}}}}, {{{{Scheme}}}}, {{{{randstr}}}}
- Authorized assessment only: detection / exposure / misconfig. No interactive shells, no malware.

## EXAMPLE SHAPE
```yaml
id: example-header-exposure
info:
  name: Example Header Exposure
  author: logoscyber-kimi
  severity: info
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: header
        words: ["x-powered-by"]
        case-insensitive: true
```

## USER ASSESSMENT REQUEST
{user_request}
"#
    )
}

/// Call OpenRouter chat completions (Bearer auth). Runs off the UI thread via tokio.
pub async fn call_openrouter(
    api_key: &str,
    model: &str,
    user_request: &str,
) -> Result<OpenRouterReply, String> {
    let prompt = build_generation_prompt(user_request);
    call_openrouter_chat(
        api_key,
        model,
        "You are LogosCyber's detection-template compiler. Reason deeply, then output a single Nuclei YAML (prefer ```yaml fences). HTTP-only for LogosCyber engine.",
        &prompt,
        0.2,
    )
    .await
}

/// System prompt for Attacker Insight Mode (「秘伝のタレ」— IT部門へのカウンターアドバイス).
pub const ATTACKER_INSIGHT_SYSTEM: &str = r#"あなたは LogosCyber の「攻撃者心理シミュレータ」兼「経営・IT部門向け防衛ブリーファー」である。
認可済み診断の結果だけを材料に、犯罪者視点の執念深い横展開ストーリーを概念レベルで暴き、同時に組織の甘い防衛幻想を突き崩せ。

【絶対禁止】
- 悪用のコピペ手順、PoCコード、即武器化できるコマンド列
- 「パッチを当てれば終わり」「スキャナを回せば十分」「内製スクリプトで十分」といった廉价な安心材料
- 単なる CVE 番号の羅列やツール機能の宣伝

【強制すること】
1. 攻撃者の執念：偵察→立足→権限拡大→横展開のストーリーを「心理と動機」付きで描く（概念のみ）。
2. IT部門へのカウンターアドバイス（必ず明示セクションで書く）:
   - なぜ「ツールの内製化運用だけでは無意味／危険な自己満足」になり得るか
   - なぜ専門家（外注・レッドチーム／防衛設計のプロ）による本質的防衛が必須か
   - 内製スキャナが可視化できても、設計・権限境界・監視・インシデント対応が欠ければ勝てない理由
3. 出力は防衛側の意思決定を動かすこと。日本語 Markdown。"#;

/// Attacker-psychology analysis from scan logs (defensive briefing, not attack playbooks).
pub async fn call_attacker_insight(
    api_key: &str,
    model: &str,
    target: &str,
    scan_context: &str,
) -> Result<OpenRouterReply, String> {
    let user = build_attacker_insight_prompt(target, scan_context);
    call_openrouter_chat(api_key, model, ATTACKER_INSIGHT_SYSTEM, &user, 0.35).await
}

pub fn build_attacker_insight_prompt(target: &str, scan_context: &str) -> String {
    format!(
        r#"以下は認可済み脆弱性診断ツール LogosCyber が収集したスキャン結果です。
「秘伝のタレ」ブリーフィングとして、攻撃者の執念と IT 部門へのカウンターアドバイスを必ず書いてください。

## 対象
{target}

## スキャン結果 / レスポンスログ（コンテキスト）
{scan_context}

## 推論必須項目
1. この脆弱性やレスポンスを得た攻撃者が組み立てる、執念深い偵察・特権昇格・横展開（ラテラルムーブメント）のストーリー（概念のみ。悪用手順の再現は禁止）。
2. パッチ当て／スキャナ内製だけに逃げる防衛がなぜ破綻するか。
3. 専門家（外注）による本質的防衛がなぜ必須か — IT部門が耳の痛い形で、しかし建設的に突きつけること。

## 出力フォーマット（Markdown・見出しは厳守）
# Attacker Insight Briefing
## 観測の要約
## 攻撃者の執念深い次のストーリー（概念）
## 心理・動機の読み
## IT部門へのカウンターアドバイス（内製スキャナ運用の限界）
## 本質的な防衛アクション（優先度付き）
## 外注・専門家に依頼すべき観点

日本語で、読みやすく、実務と意思決定に使える長さで。"#,
        target = target,
        scan_context = if scan_context.trim().is_empty() {
            "(スキャンログが空です。露出検知後の攻撃者行動と、内製偏重へのカウンターを一般論として論じてください。)"
        } else {
            scan_context
        }
    )
}

/// Low-level OpenRouter chat call shared by template gen and insight mode.
pub async fn call_openrouter_chat(
    api_key: &str,
    model: &str,
    system: &str,
    user: &str,
    temperature: f32,
) -> Result<OpenRouterReply, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(AI_HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|e| e.to_string())?;

    let body = serde_json::json!({
        "model": model,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user }
        ],
        "temperature": temperature,
        "reasoning": { "effort": "high" }
    });

    let resp = client
        .post(OPENROUTER_URL)
        .header("Authorization", format!("Bearer {}", api_key.trim()))
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", "https://github.com/olbin-dev/logos-cyber")
        .header("X-Title", "LogosCyber")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("OpenRouter request failed: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("OpenRouter body read failed: {e}"))?;

    if !status.is_success() {
        return Err(format!("OpenRouter HTTP {status}: {text}"));
    }

    let json: Value = serde_json::from_str(&text)
        .map_err(|e| format!("OpenRouter JSON parse failed: {e}; body={text}"))?;

    let message = &json["choices"][0]["message"];
    let content = message["content"].as_str().unwrap_or("").to_string();
    let reasoning = message
        .get("reasoning")
        .and_then(|v| v.as_str())
        .or_else(|| message.get("reasoning_content").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    if content.trim().is_empty() && reasoning.trim().is_empty() {
        return Err(format!("OpenRouter returned empty message. Raw: {text}"));
    }

    Ok(OpenRouterReply { content, reasoning })
}

/// Format insight reply for GUI display (reasoning collapsed above content).
pub fn format_insight_display(reply: &OpenRouterReply) -> String {
    let mut out = String::new();
    if !reply.reasoning.trim().is_empty() {
        out.push_str("── Kimi Reasoning (excerpt) ──\n");
        let excerpt: String = reply.reasoning.chars().take(1200).collect();
        out.push_str(&excerpt);
        if reply.reasoning.chars().count() > 1200 {
            out.push_str("\n…");
        }
        out.push_str("\n\n── Briefing ──\n");
    }
    out.push_str(reply.content.trim());
    if out.trim().is_empty() {
        out.push_str(reply.reasoning.trim());
    }
    out
}

/// Combine model fields and extract pure YAML (handles long reasoning dumps).
pub fn extract_yaml_from_reply(reply: &OpenRouterReply) -> String {
    // Prefer content; fall back to reasoning if content has no YAML.
    let primary = if looks_like_has_yaml(&reply.content) {
        reply.content.as_str()
    } else if looks_like_has_yaml(&reply.reasoning) {
        reply.reasoning.as_str()
    } else {
        // Concatenate: reasoning then content (YAML often at the end)
        return clean_ai_yaml(&format!("{}\n{}", reply.reasoning, reply.content));
    };
    clean_ai_yaml(primary)
}

fn looks_like_has_yaml(s: &str) -> bool {
    s.contains("```yaml")
        || s.contains("```yml")
        || s.lines().any(|l| {
            let t = l.trim();
            t.starts_with("id:") || t == "http:" || t == "requests:"
        })
}

/// Strip reasoning prose / fences and normalize for LogosCyber engine.
pub fn clean_ai_yaml(raw: &str) -> String {
    let mut s = raw.trim().to_string();

    // Drop common thinking wrappers
    for tag in ["</think>", "<think>", "</reasoning>", "<reasoning>"] {
        s = s.replace(tag, "\n");
    }

    // Prefer last ```yaml ... ``` block (final answer after reasoning)
    if let Some(yaml_from_fence) = extract_last_fenced_yaml(&s) {
        s = yaml_from_fence;
    } else if let Some(from_id) = extract_from_id_key(&s) {
        s = from_id;
    }

    // Legacy key rewrite
    let mut rewritten = String::new();
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed == "requests:" {
            let indent = line.len() - line.trim_start().len();
            rewritten.push_str(&" ".repeat(indent));
            rewritten.push_str("http:\n");
        } else {
            rewritten.push_str(line);
            rewritten.push('\n');
        }
    }

    rewritten.trim().to_string()
}

fn extract_last_fenced_yaml(s: &str) -> Option<String> {
    let mut last: Option<String> = None;
    let mut rest = s;
    while let Some(start) = rest.find("```") {
        let after = &rest[start + 3..];
        let after = after
            .strip_prefix("yaml")
            .or_else(|| after.strip_prefix("yml"))
            .or_else(|| after.strip_prefix("YAML"))
            .unwrap_or(after);
        let after = after.strip_prefix('\n').unwrap_or(after);
        if let Some(end) = after.find("```") {
            let block = after[..end].trim().to_string();
            if block.lines().any(|l| l.trim().starts_with("id:")) {
                last = Some(block);
            }
            rest = &after[end + 3..];
        } else {
            let block = after.trim().to_string();
            if block.lines().any(|l| l.trim().starts_with("id:")) {
                last = Some(block);
            }
            break;
        }
    }
    last
}

/// Take from the last top-level `id:` line through end (or until trailing prose).
fn extract_from_id_key(s: &str) -> Option<String> {
    let lines: Vec<&str> = s.lines().collect();
    let mut start_idx = None;
    for (i, line) in lines.iter().enumerate() {
        if line.trim().starts_with("id:") && !line.trim().starts_with("id: ") {
            // still ok if id: foo
            start_idx = Some(i);
        } else if line.trim().starts_with("id:") {
            start_idx = Some(i);
        }
    }
    let start = start_idx?;
    let mut out: Vec<&str> = Vec::new();
    for line in &lines[start..] {
        let t = line.trim();
        // Stop if clear prose after YAML (heuristic)
        if !out.is_empty()
            && !t.is_empty()
            && !t.starts_with('#')
            && !t.contains(':')
            && !t.starts_with('-')
            && !t.starts_with('|')
            && !t.starts_with('>')
            && !t.starts_with('"')
            && !t.starts_with('\'')
            && out.iter().any(|l| l.trim() == "http:" || l.trim() == "requests:")
            && t.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false)
            && !t.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
        {
            // e.g. "Here is an explanation..." after the template
            if t.split_whitespace().count() > 6 {
                break;
            }
        }
        out.push(line);
    }
    let joined = out.join("\n").trim().to_string();
    if joined.contains("id:") && (joined.contains("http:") || joined.contains("requests:")) {
        Some(joined)
    } else if joined.contains("id:") {
        Some(joined)
    } else {
        None
    }
}

/// Parse + score AI YAML for LogosCyber engine readiness.
pub fn prepare_template(raw_ai_text: &str) -> Result<PreparedTemplate, String> {
    let cleaned = clean_ai_yaml(raw_ai_text);
    let mut notes = Vec::new();

    if raw_ai_text.contains("requests:") && cleaned.contains("http:") {
        notes.push("Rewrote deprecated `requests:` → `http:`.".into());
    }
    if raw_ai_text.contains("```") {
        notes.push("Extracted YAML from markdown / reasoning output.".into());
    }

    let parsed =
        parse_template(&cleaned).map_err(|e| format!("AI YAML failed engine parse: {e}"))?;
    if parsed.http_requests.is_empty() {
        return Err(
            "AI YAML has no HTTP requests. LogosCyber is HTTP-only — regenerate with `http:`."
                .into(),
        );
    }

    let compat = analyze_compatibility(&parsed);
    if compat.score < 50 {
        notes.push(format!(
            "Low compat score {}% — review warnings before scanning.",
            compat.score
        ));
    }
    for w in &compat.warnings {
        notes.push(format!("Compat: {w}"));
    }

    for (i, req) in parsed.http_requests.iter().enumerate() {
        if req.matchers.len() > 1 && !req.matchers_condition.eq_ignore_ascii_case("and") {
            notes.push(format!(
                "req[{i}]: multiple matchers with condition `{}` (prefer `and` for detections).",
                req.matchers_condition
            ));
        }
    }

    Ok(PreparedTemplate {
        yaml: cleaned,
        template_id: parsed.id,
        compat,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_fences_and_legacy_key() {
        let raw = "```yaml\nid: t\ninfo:\n  name: T\n  author: a\n  severity: info\nrequests:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: status\n        status: [200]\n```";
        let cleaned = clean_ai_yaml(raw);
        assert!(cleaned.contains("http:"), "{cleaned}");
        assert!(!cleaned.contains("```"));
        let prep = prepare_template(raw).expect("prepare");
        assert_eq!(prep.template_id, "t");
        assert!(prep.compat.score >= 70);
    }

    #[test]
    fn extracts_yaml_after_long_reasoning() {
        let raw = r#"
I am thinking about SSRF chains and auth bypass...
Step 1: attacker would probe...
Step 2: then check headers...

Final template:

```yaml
id: deep-header-check
info:
  name: Deep Header Check
  author: logoscyber-kimi
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: header
        words: ["server"]
```

Hope this helps with authorized testing.
"#;
        let cleaned = clean_ai_yaml(raw);
        assert!(cleaned.starts_with("id: deep-header-check"), "{cleaned}");
        assert!(!cleaned.contains("SSRF"));
        prepare_template(raw).expect("prepare after reasoning");
    }

    #[test]
    fn extract_prefers_content_yaml() {
        let reply = OpenRouterReply {
            reasoning: "long thoughts without yaml".into(),
            content: "```yaml\nid: from-content\ninfo:\n  name: C\n  author: a\n  severity: info\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n    matchers:\n      - type: status\n        status: [200]\n```".into(),
        };
        let y = extract_yaml_from_reply(&reply);
        assert!(y.contains("from-content"));
    }

    #[test]
    fn rejects_dns_only() {
        let raw = r#"
id: dns
info:
  name: d
  author: a
  severity: info
dns:
  - name: "{{FQDN}}"
    type: A
"#;
        assert!(prepare_template(raw).is_err());
    }

    #[test]
    fn prompt_mentions_adversary_and_http() {
        let p = build_generation_prompt("check X-Foo header");
        assert!(p.contains("`http:`"));
        assert!(p.contains("adversary") || p.contains("attacker"));
        assert!(p.contains("check X-Foo header"));
    }

    #[test]
    fn insight_prompt_covers_lateral_and_defense() {
        let p = build_attacker_insight_prompt("https://example.com", "FINDING: git-config");
        assert!(p.contains("ラテラル") || p.contains("横展開"));
        assert!(p.contains("防衛"));
        assert!(p.contains("FINDING: git-config"));
    }

    #[test]
    fn insight_secret_sauce_counters_diy_scanner_fantasy() {
        let sys = ATTACKER_INSIGHT_SYSTEM;
        assert!(sys.contains("内製"));
        assert!(sys.contains("外注") || sys.contains("専門家"));
        assert!(sys.contains("絶対禁止"));
        // Cheap closure is listed only as something to forbid / counter
        assert!(sys.contains("パッチを当てれば終わり") && sys.contains("禁止"));

        let p = build_attacker_insight_prompt("https://corp.example", "MATCH git-config");
        assert!(p.contains("カウンターアドバイス"));
        assert!(p.contains("内製"));
        assert!(p.contains("執念"));
        assert!(p.contains("IT部門へのカウンターアドバイス"));
        assert!(p.contains("パッチ当て") || p.contains("スキャナ内製"));
    }
}
