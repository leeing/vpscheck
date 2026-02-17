# VPS Unlock Checker

检测 VPS 对主流服务的解锁状态，支持 IPv4/IPv6 双栈。

**零依赖** — 仅使用 Python 3.10+ 标准库，无需 pip install 任何包。

## 一键运行

```bash
curl -sL https://raw.githubusercontent.com/leeing/vpscheck/refs/heads/main/check.py | python3
```

## 支持平台

| 类别 | 平台 |
|------|------|
| AI 服务 | ChatGPT · Google Gemini · Claude |
| Google | Google Play Store · Google Search CAPTCHA Free · YouTube Premium |
| 其他 | Reddit · Apple Region |

## 使用方式

```bash
# 一键运行（推荐）
curl -sL https://raw.githubusercontent.com/leeing/vpscheck/refs/heads/main/check.py | python3

# 带参数
curl -sL https://raw.githubusercontent.com/leeing/vpscheck/refs/heads/main/check.py | python3 - -4       # 仅 IPv4
curl -sL https://raw.githubusercontent.com/leeing/vpscheck/refs/heads/main/check.py | python3 - -6       # 仅 IPv6
curl -sL https://raw.githubusercontent.com/leeing/vpscheck/refs/heads/main/check.py | python3 - -I eth0  # 绑定网卡

# 本地运行
python3 check.py
python3 check.py -4
python3 check.py -6
python3 check.py -I eth0
python3 check.py -I 1.2.3.4
```

## 环境要求

- Python ≥ 3.10
- Linux（`-I` 网卡绑定依赖 `ip` 命令）

## License

MIT
