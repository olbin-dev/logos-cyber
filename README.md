# 🛡️ LogosCyber: LLM-Powered Nuclei Template Generator & Scanner

<p align="center">
  <img src="assets/logos_cyber_owl.png" alt="LogosCyber Owl Icon" width="250" style="border-radius: 12px; box-shadow: 0 4px 20px rgba(0, 242, 254, 0.3);"/>
</p>

LogosCyber is a lightweight native desktop GUI application written in Rust. It leverages the Google Gemini API to automatically generate **Nuclei-compatible YAML vulnerability scanning templates** from natural language prompts, allowing you to run quick verification scans against your targets immediately.

---

## 🌟 Key Features

*   **🤖 AI Template Generation**:
    Create templates simply by describing what you want to test (e.g., "Check if `/wp-config.php.bak` exists" or "Verify custom headers").
*   **⚡ On-the-Fly Scanning**:
    Instantly execute the generated or custom YAML template against a target URL to check for vulnerability matches.
*   **📂 Multi-Template Directory Loading**:
    Load a local directory containing multiple Nuclei templates to run sequential scans.
*   **🔒 Secure Direct Connection**:
    *   No local proxies required. The app communicates directly with Google's Gemini API over HTTPS, ensuring your API keys and target details remain confidential.
    *   Optimized safety settings (`BLOCK_NONE`) prevent AI from falsely blocking security-related templates.
*   **🚀 Lightweight Native UI**:
    Uses the `eframe` (egui) library to provide a fast and lightweight native application experience (consuming only a few megabytes of RAM).

---

## 🛠️ Prerequisites

*   **Rust (Cargo)** toolchain installed.
*   **Google Gemini API Key** (available for free via Google AI Studio).

---

## 🚀 Build and Run

```bash
# Clone the repository
git clone https://github.com/OS-Sovereign/logos-cyber.git
cd logos-cyber

# Build and run the application
cargo run --release
```

---

## 📖 How to Use

1.  **Set Target**: Input the target URL/IP in the `Target URL / IP` field in the top-left panel.
2.  **Enter API Key**: Provide your Gemini API key in the `Gemini API Key` field (input is masked for security).
3.  **Prompt the AI**: Describe what you want to test in the `What to test?` text area.
    *   *Example: "Create a template to check if accessing `/admin` returns a 403 Forbidden status code."*
4.  **Generate**: Click the `💡 Generate with AI` button. The generated YAML code will appear in the quick template editor in the center.
5.  **Scan**: Click `🚀 Run Quick Scan (Text)` to execute the template against the target and see results in the right panel.

---

## ⚠️ Disclaimer

*   This tool is for **authorized security testing and educational research purposes only**.
*   Do not scan targets without explicit prior permission from the owner.
*   The developer assumes no liability for any misuse or damage caused by this application.

---

## 📝 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

## 🇯🇵 日本語概要 (Japanese Overview)

LogosCyber は、Google Gemini API を活用して自然言語のプロンプトから **Nuclei 互換の脆弱性スキャン用 YAML テンプレート**を自動生成し、その場ですぐにターゲットに対して簡易スキャンを実行できる Rust 製のネイティブ GUI アプリケーションです。

*   **自然言語からの生成**: 「`/admin` にアクセスした際に 403 Forbidden が返ってくるか確認するテンプレートを作って」などの指示からYAMLを自動生成。
*   **直接通信**: ローカルプロキシを中継せず、直接 Gemini API と通信するため安全です。
*   **軽量・高速**: `eframe` (egui) を用いて構築されており、極めて少ないメモリ消費で動作します。

*(※詳細なビルド方法や使い方は、上記の英語セクションをご参照ください)*
