# VPS Unlock Checker — SPEC

## Overview

Python reimplementation of selected checks from [lmc999/RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck/blob/main/check.sh). Detection logic must stay **1:1** with upstream bash.

## Upstream Mapping

| # | Python Function | Bash Function | Line | curl flags | Key Logic |
|---|----------------|---------------|------|------------|-----------|
| 1 | `check_reddit` | `WebTest_Reddit` | L3701 | `-fsL` (follow, fail silent) | HTTP status only: 200→Yes, 403→No. IPv6 not supported. |
| 2 | `check_youtube_premium` | `MediaUnlockTest_YouTube_Premium` | L1694 | `-sL` (follow) | CN redirect → No. `'Premium is not available'` → No. `'ad-free'` → Yes. Region from `INNERTUBE_CONTEXT_GL`. |
| 3 | `check_apple_region` | `RegionTest_Apple` | L1738 | `-sL` (follow, **no** custom UA) | Response body = region code. Empty → Failed. |
| 4 | `check_chatgpt` | `WebTest_OpenAI` | L4510 | `-s` (**no** redirect follow) | Two requests. `grep -i 'unsupported_country'` + `grep -i 'VPN'` (both case-insensitive). 4-way matrix. |
| 5 | `check_gemini` | `WebTest_Gemini` | L4544 | `-sL` (follow) | `'45631641,null,true'` → available. Country from `,2,1,200,"[A-Z]{3}"`. |
| 6 | `check_claude` | `WebTest_Claude` | L4564 | `-s -L` (follow) | Final URL comparison. `claude.ai/` → Yes. `app-unavailable-in-region` → No. |
| 7 | `check_google_captcha` | `WebTest_GoogleSearchCAPTCHA` | L1789 | `-sL` (follow) | `grep -iE 'unusual traffic\|blocked\|abuse'` → blocked. `grep -i 'curl'` → ok. Blocked takes priority. |

## Shared Behavior

| Aspect | Bash | Python |
|--------|------|--------|
| Retry | `--retry 3 --retry-max-time 20` | `_MAX_RETRIES = 3`, `_RETRY_DELAY = 1s` |
| Timeout | `--max-time 10` | `TIMEOUT = 15` (slightly longer for Python overhead) |
| User-Agent | `UA_BROWSER` (Chrome 125) | Same string |
| Header casing | curl preserves casing | `_make_request` bypasses `add_header()` to preserve casing |

## Sync Mechanism

`sync-check.yml` runs weekly (Monday 08:00 UTC) and compares SHA-256 hashes of upstream function bodies. Changed functions trigger a GitHub Issue tagged `[sync]`.
