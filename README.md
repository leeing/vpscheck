# VPS Unlock Checker

检测 VPS 对主流服务的解锁状态，支持 IPv4/IPv6 双栈。

## 支持平台

| 类别 | 平台 |
|------|------|
| AI 服务 | ChatGPT · Google Gemini · Claude |
| Google | Google Play Store · Google Search CAPTCHA Free · YouTube Premium |
| 其他 | Reddit · Apple Region |

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

## 环境要求

- Linux（`-I` 网卡绑定依赖 `ip` 命令）
- Python ≥ 3.10
- [uv](https://docs.astral.sh/uv/)

## License

MIT
