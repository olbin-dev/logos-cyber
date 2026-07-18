# Proton 非アプリ常時経由（スキャン専用 SOCKS）

Proton VPN **アプリは使わない**。スキャン出口だけを Proton 経由にし、他アプリ（Gemini / Dropbox / n8n 等）は通常回線のままにする。

## アーキテクチャ

```
LogosCyber  --socks5://127.0.0.1:1080-->  tunmux (--local-proxy)
                                              |
                                         userspace WireGuard
                                              |
                                         Proton 出口 --> スキャン対象

Gemini API  <--HTTPS 直結-- LogosCyber（プロキシ外）
```

## 1. WireGuard `.conf` を取得（一度だけ）

アカウントの ID/パスワードは **ダッシュボードログイン専用**。アプリや git には入れない。

1. [account.protonvpn.com](https://account.protonvpn.com) にログイン
2. **Downloads → WireGuard configuration**
3. 名前を付け、Platform / サーバーを選んで **Create** → **Download**
4. 保存先（推奨）:

```bash
mkdir -p "$HOME/Library/Application Support/LogosCyber"
mv ~/Downloads/*.conf "$HOME/Library/Application Support/LogosCyber/proton.conf"
chmod 600 "$HOME/Library/Application Support/LogosCyber/proton.conf"
```

Free プランでも `.conf` は取得可能（国・機能は制限あり）。Plus なら出口国を選べる。

## 2. tunmux を入れる（SOCKS 常駐）

```bash
cargo install --git https://github.com/CaddyGlow/tunmux tunmux
```

手動起動:

```bash
./scripts/proton_socks/start_socks.sh
# 典型: socks5://127.0.0.1:1080
```

ログイン時自動起動:

```bash
./scripts/proton_socks/install_launch_agent.sh
```

停止:

```bash
./scripts/proton_socks/stop_socks.sh
# または LaunchAgent 解除
./scripts/proton_socks/uninstall_launch_agent.sh
```

確認:

```bash
curl --socks5 127.0.0.1:1080 -s https://api.ipify.org
# 自宅 IP ではなく Proton 出口 IP になること
```

## 3. LogosCyber 側

既定:

- Proxy URL: `socks5://127.0.0.1:1080`
- **Require Proton proxy**: ON（不通ならスキャン拒否）

UI 左パネルに次を表示（約30秒ごと / Recheck で更新）:

- **Scan egress IP (via proxy)** … スキャンが使う出口IP（Proton 側であるべき）
- **Direct IP (this Mac / ISP)** … VPN を通さない自宅IP
- **VPN egress: ACTIVE** … 両者が異なれば VPN 動作中

任意の上書き: `~/.config/logos_cyber/config.toml`（リポジトリの `config.toml.example` を参照）

```toml
proxy_url = "socks5://127.0.0.1:1080"
require_proxy = true
```

環境変数でも上書き可:

- `LOGOSCYBER_PROXY_URL`
- `LOGOSCYBER_REQUIRE_PROXY` (`true` / `false`)

## やらないこと

- Proton VPN 公式アプリ / 公式 WireGuard Mac アプリでの **システム全体トンネル**
- アカウントパスワードのハードコード
- Gemini 通信の SOCKS 強制（別トラブルを増やさない）
