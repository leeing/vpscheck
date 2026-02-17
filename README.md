# VPS Unlock Checker

检测 VPS 对主流服务的解锁状态，支持 IPv4/IPv6 双栈。

**零依赖** — 仅使用 Python 3.10+ 标准库，无需 pip install 任何包。

## 支持平台

| 类别 | 平台 |
|------|------|
| AI 服务 | ChatGPT · Google Gemini · Claude |
| Google | Google Play Store · Google Search CAPTCHA Free · YouTube Premium |
| 其他 | Reddit · Apple Region |

## 快速开始

```bash
# 只需 Python 3.10+，无需任何第三方依赖
python3 check.py
```

## 使用方式

```bash
python3 check.py          # 双栈测试（IPv4 + IPv6）
python3 check.py -4       # 仅 IPv4
python3 check.py -6       # 仅 IPv6
python3 check.py -I eth0  # 绑定网卡
python3 check.py -I 1.2.3.4  # 绑定 IP
```

## 环境要求

- Python ≥ 3.10
- Linux（`-I` 网卡绑定依赖 `ip` 命令）

## License

MIT
