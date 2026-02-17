# VPS Unlock Checker

检测 VPS 对主流流媒体和 AI 服务的解锁状态，支持 IPv4/IPv6 双栈。

## 支持平台

| 类别 | 平台 |
|------|------|
| 流媒体 | Netflix · YouTube Premium · HBO Max · Hulu · Discovery+ · BBC iPLAYER |
| AI 服务 | ChatGPT · Google Gemini · Claude |
| 区域检测 | Apple Region · Google Play · Google CAPTCHA · YouTube CDN · Netflix CDN |
| 社交 | Reddit |
| 区域限定 | Bilibili 港澳台 · Bilibili 台湾 |

## 快速开始

```bash
# 需要 Python 3.10+ 和 uv
uv run check.py
```

依赖（`httpx` · `rich`）由 uv 自动安装，无需手动配置。

## 使用方式

```bash
uv run check.py          # 双栈测试（IPv4 + IPv6）
uv run check.py -4       # 仅 IPv4
uv run check.py -6       # 仅 IPv6
uv run check.py -I eth0  # 绑定网卡
uv run check.py -I 1.2.3.4  # 绑定 IP
```

## 输出示例

```
╭─ VPS Unlock Checker — IPv4 ──────────────────╮
│  🌐  Network: China Telecom (103.45.*.*)      │
│  📡  Protocol: IPv4                            │
╰───────────────────────────────────────────────╯
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Platform           ┃ Result                  ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Netflix            │ ✅ Yes (US)              │
│ YouTube Premium    │ ✅ Yes (US)              │
│ ChatGPT            │ ✅ Yes                   │
│ HBO Max            │ ❌ No                    │
│ BBC iPLAYER        │ ⚠️  Failed (Network)     │
└────────────────────┴─────────────────────────┘
```

## 技术栈

- **Python 3.10+** — match/case, type union, dataclass
- **httpx** — 异步 HTTP，支持 local_address 绑定
- **rich** — 终端表格与面板渲染
- **asyncio.gather** — 17 项检测并发执行

## 环境要求

- Linux（`-I` 网卡绑定依赖 `ip` 命令）
- Python ≥ 3.10
- [uv](https://docs.astral.sh/uv/)

## License

MIT
