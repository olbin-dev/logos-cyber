//! Shared severity / readiness color strategy for GUI (egui) and CLI (termcolor).
//!
//! Four tones:
//! - Success  — healthy / defense maintained (green–blue)
//! - Warning  — template refresh needed / below-average coverage (yellow)
//! - Important — structural misconfig / lateral-movement footholds (orange)
//! - Critical — immediate patch / breach indicators (red)

use std::io;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

/// Visual / operational tone used across reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tone {
    /// 成功・現状維持（緑/青系）
    Success,
    /// 警告・注意（黄色）
    Warning,
    /// 重要・リスク（オレンジ）— 横展開の起点など
    Important,
    /// 緊急・侵害（赤）
    Critical,
}

impl Tone {
    pub fn label_ja(self) -> &'static str {
        match self {
            Tone::Success => "成功・現状維持",
            Tone::Warning => "警告・注意",
            Tone::Important => "重要・リスク",
            Tone::Critical => "緊急・侵害",
        }
    }

    pub fn label_en(self) -> &'static str {
        match self {
            Tone::Success => "OK",
            Tone::Warning => "WARN",
            Tone::Important => "RISK",
            Tone::Critical => "CRIT",
        }
    }

    /// Foreground RGB for text / borders / progress fill.
    pub fn fg_rgb(self) -> (u8, u8, u8) {
        match self {
            Tone::Success => (40, 150, 120),
            Tone::Warning => (200, 160, 40),
            Tone::Important => (220, 120, 40),
            Tone::Critical => (210, 55, 55),
        }
    }

    /// Soft background tint for cards / rows (light theme friendly).
    pub fn bg_rgb(self) -> (u8, u8, u8) {
        match self {
            Tone::Success => (230, 245, 240),
            Tone::Warning => (250, 245, 220),
            Tone::Important => (255, 238, 220),
            Tone::Critical => (255, 230, 230),
        }
    }

    /// Stronger fill for callout banners (e.g. residual 1%).
    pub fn banner_bg_rgb(self) -> (u8, u8, u8) {
        match self {
            Tone::Success => (210, 235, 225),
            Tone::Warning => (245, 230, 180),
            Tone::Important => (255, 210, 170),
            Tone::Critical => (255, 200, 200),
        }
    }

    fn term_color(self) -> Color {
        match self {
            Tone::Success => Color::Green,
            Tone::Warning => Color::Yellow,
            Tone::Important => Color::Rgb(255, 140, 0),
            Tone::Critical => Color::Red,
        }
    }
}

/// Defence readiness % → tone (90+ blue/green, 80s yellow, ≤70 orange).
pub fn tone_from_readiness_percent(percent: f32) -> Tone {
    if percent >= 90.0 {
        Tone::Success
    } else if percent >= 80.0 {
        Tone::Warning
    } else if percent > 0.0 {
        Tone::Important
    } else {
        Tone::Warning // unknown / not yet measured
    }
}

/// Map Nuclei `info.severity` (+ match flag) to report tone.
pub fn tone_from_finding(severity: &str, matched: bool) -> Tone {
    if !matched {
        return Tone::Success;
    }
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => Tone::Critical,
        "high" => Tone::Important,
        "medium" => Tone::Warning,
        "low" | "info" | "unknown" | "" => Tone::Important,
        other if other.contains("crit") => Tone::Critical,
        other if other.contains("high") => Tone::Important,
        _ => Tone::Important,
    }
}

/// Heuristic for free-form log lines (GUI string log / CLI echo).
pub fn tone_from_log_line(line: &str) -> Tone {
    let lower = line.to_ascii_lowercase();
    // Structured: [MATCH|critical] or [clean|info]
    if let Some(rest) = lower.strip_prefix('[') {
        if let Some((flag_sev, _)) = rest.split_once(']') {
            let mut parts = flag_sev.splitn(2, '|');
            let flag = parts.next().unwrap_or("");
            let sev = parts.next().unwrap_or("");
            if flag == "match" {
                return tone_from_finding(sev, true);
            }
            if flag == "clean" {
                return Tone::Success;
            }
        }
    }
    if lower.contains("[match]") || lower.contains("finding:") {
        if lower.contains("critical") || lower.contains("crit]") {
            return Tone::Critical;
        }
        if lower.contains("high") || lower.contains("exposure") || lower.contains("config") {
            return Tone::Important;
        }
        return Tone::Important;
    }
    if lower.contains("error")
        || lower.contains("blocked")
        || lower.contains("rejected")
        || lower.contains("❌")
    {
        return Tone::Critical;
    }
    if lower.contains("⚠")
        || lower.contains("warning")
        || lower.contains("below")
        || lower.contains("更新")
    {
        return Tone::Warning;
    }
    if lower.contains("✅")
        || lower.contains("[clean]")
        || lower.contains("vpn active")
        || lower.contains("loaded")
    {
        return Tone::Success;
    }
    Tone::Success
}

/// Residual 1% / continuous monitoring callout — always elevated.
pub fn residual_gap_tone() -> Tone {
    Tone::Important
}

/// Write one colored CLI report line to stdout.
pub fn print_cli_line(tone: Tone, text: &str) {
    let mut out = StandardStream::stdout(ColorChoice::Auto);
    let _ = write_cli_line(&mut out, tone, text);
}

pub fn write_cli_line(
    out: &mut impl WriteColor,
    tone: Tone,
    text: &str,
) -> io::Result<()> {
    let mut spec = ColorSpec::new();
    spec.set_fg(Some(tone.term_color())).set_bold(true);
    out.set_color(&spec)?;
    write!(out, "[{}]", tone.label_en())?;
    out.reset()?;
    writeln!(out, " {text}")?;
    Ok(())
}

/// Print a readiness progress-style CLI summary.
pub fn print_cli_readiness(label: &str, percent: f32) {
    let tone = tone_from_readiness_percent(percent);
    print_cli_line(
        tone,
        &format!("{label}: {percent:.1}%  ({})", tone.label_ja()),
    );
}

/// Print the residual-gap callout (経営層向け強調).
pub fn print_cli_residual_gap() {
    print_cli_line(
        residual_gap_tone(),
        "残差1%領域（未知のゼロデイ等）— 定点観測とプロによる継続監視で補完が必要です。",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_bands() {
        assert_eq!(tone_from_readiness_percent(95.0), Tone::Success);
        assert_eq!(tone_from_readiness_percent(85.0), Tone::Warning);
        assert_eq!(tone_from_readiness_percent(70.0), Tone::Important);
        assert_eq!(tone_from_readiness_percent(40.0), Tone::Important);
    }

    #[test]
    fn finding_severity() {
        assert_eq!(tone_from_finding("info", false), Tone::Success);
        assert_eq!(tone_from_finding("critical", true), Tone::Critical);
        assert_eq!(tone_from_finding("high", true), Tone::Important);
        assert_eq!(tone_from_finding("medium", true), Tone::Warning);
    }

    #[test]
    fn log_line_match() {
        assert_eq!(
            tone_from_log_line("[MATCH|critical] git-config: FINDING"),
            Tone::Critical
        );
        assert_eq!(
            tone_from_log_line("[MATCH|high] git-config: FINDING"),
            Tone::Important
        );
        assert_eq!(
            tone_from_log_line("[clean|info] example: Clean."),
            Tone::Success
        );
        assert_eq!(
            tone_from_log_line("Scan blocked (kill switch)"),
            Tone::Critical
        );
    }
}
