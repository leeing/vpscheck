#!/usr/bin/env python3
"""VPS Service Unlock Checker.

Zero dependencies — uses only Python 3.10+ standard library.

Usage:
    python3 check.py          # test both IPv4 and IPv6
    python3 check.py -4       # IPv4 only
    python3 check.py -6       # IPv6 only
    python3 check.py -I eth0  # bind to specific interface
"""
from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import re
import ssl
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Callable

# ── Constants ──────────────────────────────────────────────────────────────────

UA_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
UA_SEC_CH_UA = '"Chromium";v="125", "Not-A.Brand";v="24"'

TIMEOUT = 15

# ANSI escape codes
C_GREEN = "\033[32m"
C_RED = "\033[31m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RESET = "\033[0m"


# ── Data Models ────────────────────────────────────────────────────────────────

class CheckStatus(Enum):
    OK = "ok"
    NO = "no"
    FAILED = "failed"
    WARNING = "warning"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    region: str = ""
    detail: str = ""


@dataclass
class Response:
    status_code: int
    text: str
    url: str


@dataclass
class IPInfo:
    ip: str = ""
    isp: str = ""
    country: str = ""

    @property
    def masked(self) -> str:
        if not self.ip:
            return "Unknown"
        if ":" in self.ip:
            parts = self.ip.split(":")
            return ":".join(parts[:3]) + ":*:*"
        parts = self.ip.split(".")
        return ".".join(parts[:2]) + ".*.*"


@dataclass
class CheckContext:
    opener: urllib.request.OpenerDirector
    is_ipv6: bool = False


# ── Utilities ──────────────────────────────────────────────────────────────────

def resolve_interface(name: str, ipv6: bool) -> str:
    """Resolve network interface name to bound IP address (Linux only)."""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    family = "6" if ipv6 else "4"
    kind = "inet6" if ipv6 else "inet"
    try:
        result = subprocess.run(
            ["ip", "-o", f"-{family}", "addr", "show", name],
            capture_output=True, text=True, check=False,
        )
        for line in result.stdout.splitlines():
            m = re.search(rf"{kind}\s+(\S+?)/", line)
            if m:
                addr = m.group(1)
                if ipv6 and addr.startswith("fe80"):
                    continue
                return addr
    except FileNotFoundError:
        pass
    sys.exit(f"Error: cannot resolve interface '{name}' to {'IPv6' if ipv6 else 'IPv4'} address")


# ── HTTP Layer (stdlib) ───────────────────────────────────────────────────────


class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS handler that binds to a specific source address."""

    def __init__(self, source_address: tuple[str, int] | None = None) -> None:
        ctx = ssl.create_default_context()
        super().__init__(context=ctx)
        self._source_address = source_address

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(self._conn, req, context=self._context)

    def _conn(self, host: str, **kwargs: object) -> http.client.HTTPSConnection:
        kwargs["source_address"] = self._source_address  # type: ignore[assignment]
        return http.client.HTTPSConnection(host, **kwargs)  # type: ignore[arg-type]


class _BoundHTTPHandler(urllib.request.HTTPHandler):
    """HTTP handler that binds to a specific source address."""

    def __init__(self, source_address: tuple[str, int] | None = None) -> None:
        super().__init__()
        self._source_address = source_address

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(self._conn, req)

    def _conn(self, host: str, **kwargs: object) -> http.client.HTTPConnection:
        kwargs["source_address"] = self._source_address  # type: ignore[assignment]
        return http.client.HTTPConnection(host, **kwargs)  # type: ignore[arg-type]


def create_opener(local_address: str) -> urllib.request.OpenerDirector:
    """Build a urllib opener bound to the given local address."""
    if local_address in ("0.0.0.0", "::"):
        source: tuple[str, int] | None = (local_address, 0)
    else:
        source = (local_address, 0)
    return urllib.request.build_opener(
        _BoundHTTPHandler(source_address=source),
        _BoundHTTPSHandler(source_address=source),
    )


def _make_request(url: str, headers: dict[str, str] | None = None) -> urllib.request.Request:
    """Build a Request preserving exact header casing.

    urllib.request.Request.add_header() calls str.capitalize() on keys,
    which turns 'sec-ch-ua' into 'Sec-ch-ua'. This breaks Google's browser
    fingerprinting. We bypass this by writing to req.headers directly.
    """
    hdrs = {"User-Agent": UA_BROWSER}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url)
    # Bypass add_header() to preserve original header casing
    req.headers = hdrs  # type: ignore[assignment]
    return req


# Retry matching bash CURL_DEFAULT_OPTS (--retry 3, ~1s default interval)
_MAX_RETRIES = 3
_RETRY_DELAY = 1  # seconds between retries


def fetch(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = TIMEOUT,
) -> Response | None:
    """GET a URL; returns Response on success (including 4xx/5xx), None on error.

    Retries up to 3 times on network failure, matching bash --retry 3.
    """
    req = _make_request(url, headers)
    for attempt in range(_MAX_RETRIES):
        try:
            resp = opener.open(req, timeout=timeout)
            body = resp.read().decode("utf-8", errors="replace")
            return Response(resp.status, body, resp.url)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return Response(e.code, body, url)
        except (urllib.error.URLError, OSError, TimeoutError):
            if attempt == _MAX_RETRIES - 1:
                return None
            time.sleep(_RETRY_DELAY)
    return None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler that prevents automatic redirect following (curl -s without -L)."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


def fetch_no_redirect(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = TIMEOUT,
) -> Response | None:
    """GET a URL without following redirects (faithful to curl -s without -L).

    Builds a one-off opener that inherits the source-address-bound handlers
    from the original opener but adds _NoRedirectHandler to suppress redirects.
    Retries up to 3 times on network failure.
    """
    req = _make_request(url, headers)

    # Build a new opener with the same handlers + no-redirect handler
    no_redir_opener = urllib.request.build_opener(
        *[h for h in opener.handlers if not isinstance(h, urllib.request.HTTPRedirectHandler)],
        _NoRedirectHandler,
    )
    for attempt in range(_MAX_RETRIES):
        try:
            resp = no_redir_opener.open(req, timeout=timeout)
            body = resp.read().decode("utf-8", errors="replace")
            return Response(resp.status, body, resp.url)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return Response(e.code, body, url)
        except (urllib.error.URLError, OSError, TimeoutError):
            if attempt == _MAX_RETRIES - 1:
                return None
            time.sleep(_RETRY_DELAY)
    return None


def check_connectivity(opener: urllib.request.OpenerDirector) -> bool:
    resp = fetch(opener, "https://www.google.com/generate_204", timeout=5)
    return resp is not None


def get_ip_info(opener: urllib.request.OpenerDirector) -> IPInfo:
    info = IPInfo()
    resp = fetch(opener, "https://api64.ipify.org", timeout=5)
    if resp is None:
        return info
    info.ip = resp.text.strip()
    resp2 = fetch(opener, f"https://api.ip.sb/geoip/{info.ip}", timeout=5)
    if resp2 is not None:
        try:
            data = json.loads(resp2.text)
            info.isp = data.get("isp", "")
            info.country = data.get("country", "")
        except (json.JSONDecodeError, KeyError):
            pass
    return info


# ── Platform Checks ───────────────────────────────────────────────────────────
# Each function faithfully replicates the corresponding bash function in
# check.sh, including all headers, cookies, URLs, and response parsing logic.

# --------------------------------------------------------------------------- #
# 1. WebTest_Reddit (check.sh L3701)
# --------------------------------------------------------------------------- #
def check_reddit(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_Reddit.

    Bash: curl -fsL 'https://www.reddit.com/' -w %{http_code} -o /dev/null
    Only checks HTTP status code. IPv6 not supported.
    """
    name = "Reddit"
    if ctx.is_ipv6:
        return CheckResult(name, CheckStatus.WARNING, detail="IPv6 not supported")
    resp = fetch(ctx.opener, "https://www.reddit.com/")
    if resp is None:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    match resp.status_code:
        case 200:
            return CheckResult(name, CheckStatus.OK)
        case 403:
            return CheckResult(name, CheckStatus.NO)
        case _:
            return CheckResult(name, CheckStatus.FAILED, detail=f"Error: {resp.status_code}")


# --------------------------------------------------------------------------- #
# 2. MediaUnlockTest_YouTube_Premium (check.sh L1694)
# --------------------------------------------------------------------------- #
def check_youtube_premium(ctx: CheckContext) -> CheckResult:
    """Faithful port of MediaUnlockTest_YouTube_Premium.

    Bash: curl -sL 'https://www.youtube.com/premium'
          with accept-language and specific cookies.
    Checks: google.cn → CN, 'Premium is not available' → No,
            'ad-free' → Yes, else PAGE ERROR.
    Region from INNERTUBE_CONTEXT_GL.
    """
    name = "YouTube Premium"
    headers = {
        "accept-language": "en-US,en;q=0.9",
        "cookie": (
            "YSC=FSCWhKo2Zgw; "
            "VISITOR_PRIVACY_METADATA=CgJERRIEEgAgYQ%3D%3D; "
            "PREF=f7=4000; "
            "__Secure-YEC=CgtRWTBGTFExeV9Iayjele2yBjIKCgJERRIEEgAgYQ%3D%3D; "
            "SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY; "
            "VISITOR_INFO1_LIVE=Di84mAIbgKY; "
            "__Secure-BUCKET=CGQ"
        ),
    }
    resp = fetch(ctx.opener, "https://www.youtube.com/premium", headers=headers)
    if resp is None or not resp.text:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    text = resp.text

    # Check CN redirect
    if "www.google.cn" in text:
        return CheckResult(name, CheckStatus.NO, region="CN")

    # Extract region: grep -woP '"INNERTUBE_CONTEXT_GL"\s*:\s*"\K[^"]+'
    m = re.search(r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([^"]+)"', text)
    region = m.group(1) if m else ""

    # Check not available
    if re.search(r"Premium is not available in your country", text, re.IGNORECASE):
        return CheckResult(name, CheckStatus.NO, region=region)

    # Check available
    if not region:
        region = "UNKNOWN"
    if re.search(r"ad-free", text, re.IGNORECASE):
        return CheckResult(name, CheckStatus.OK, region=region)

    return CheckResult(name, CheckStatus.FAILED, detail="PAGE ERROR")


# --------------------------------------------------------------------------- #
# 3. RegionTest_Apple (check.sh L1738)
# --------------------------------------------------------------------------- #
def check_apple_region(ctx: CheckContext) -> CheckResult:
    """Faithful port of RegionTest_Apple.

    Bash: curl -sL 'https://gspe1-ssl.ls.apple.com/pep/gcc'
    Simply returns the response text as the region.
    Empty → Failed, otherwise shows the result.
    """
    name = "Apple Region"
    # Bash uses curl -sL WITHOUT --user-agent, so curl sends its default UA.
    # We replicate this by sending a curl-like User-Agent, not the browser UA.
    resp = fetch(
        ctx.opener,
        "https://gspe1-ssl.ls.apple.com/pep/gcc",
        headers={"User-Agent": "curl/8.7.1"},
    )
    if resp is None:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    result = resp.text.strip()
    if not result:
        return CheckResult(name, CheckStatus.FAILED)
    return CheckResult(name, CheckStatus.OK, region=result)


# --------------------------------------------------------------------------- #
# 4. WebTest_OpenAI / ChatGPT (check.sh L4510)
# --------------------------------------------------------------------------- #
def check_chatgpt(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_OpenAI.

    Makes two requests:
      1) GET https://api.openai.com/compliance/cookie_requirements
      2) GET https://ios.chat.openai.com/

    Logic:
      result1 = grep 'unsupported_country' in resp1
      result2 = grep 'VPN' in resp2
      !result1 && !result2 → Yes
      result1 && result2 → No
      !result1 && result2 → No (Only Available with Web Browser)
      result1 && !result2 → No (Only Available with Mobile APP)
    """
    name = "ChatGPT"
    headers1 = {
        "authority": "api.openai.com",
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "authorization": "Bearer null",
        "content-type": "application/json",
        "origin": "https://platform.openai.com",
        "referer": "https://platform.openai.com/",
        "sec-ch-ua": UA_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
    }
    headers2 = {
        "authority": "ios.chat.openai.com",
        "accept": "*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": UA_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    }

    # Bash uses curl -s (no -L), so no redirect following for both requests.
    resp1 = fetch_no_redirect(ctx.opener, "https://api.openai.com/compliance/cookie_requirements", headers=headers1)
    if resp1 is None or not resp1.text:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    resp2 = fetch_no_redirect(ctx.opener, "https://ios.chat.openai.com/", headers=headers2)
    if resp2 is None or not resp2.text:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    # grep -i 'unsupported_country'
    has_unsupported = bool(re.search(r"unsupported_country", resp1.text, re.IGNORECASE))
    # grep -i 'VPN'
    has_vpn = bool(re.search(r"VPN", resp2.text))

    if not has_unsupported and not has_vpn:
        return CheckResult(name, CheckStatus.OK)
    if has_unsupported and has_vpn:
        return CheckResult(name, CheckStatus.NO)
    if not has_unsupported and has_vpn:
        return CheckResult(name, CheckStatus.WARNING, detail="Only Available with Web Browser")
    if has_unsupported and not has_vpn:
        return CheckResult(name, CheckStatus.WARNING, detail="Only Available with Mobile APP")

    return CheckResult(name, CheckStatus.FAILED, detail="Unknown")


# --------------------------------------------------------------------------- #
# 5. WebTest_Gemini (check.sh L4544)
# --------------------------------------------------------------------------- #
def check_gemini(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_Gemini.

    Bash: curl -sL "https://gemini.google.com"
    Checks: if response starts with "curl" → network error.
    grep -q '45631641,null,true' → available.
    grep -o ',2,1,200,"[A-Z]{3}"' → extract country code.
    """
    name = "Google Gemini"
    resp = fetch(ctx.opener, "https://gemini.google.com")
    if resp is None:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    text = resp.text

    # Bash: if [[ "$tmpresult" = "curl"* ]]
    if text.startswith("curl"):
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    # grep -q '45631641,null,true'
    is_available = "45631641,null,true" in text

    # grep -o ',2,1,200,"[A-Z]{3}"' | sed 's/,2,1,200,"//;s/"//'
    m = re.search(r',2,1,200,"([A-Z]{3})"', text)
    countrycode = m.group(1) if m else ""

    if is_available and countrycode:
        return CheckResult(name, CheckStatus.OK, region=countrycode)
    elif is_available:
        return CheckResult(name, CheckStatus.OK)
    else:
        return CheckResult(name, CheckStatus.NO)


# --------------------------------------------------------------------------- #
# 6. WebTest_Claude (check.sh L4564)
# --------------------------------------------------------------------------- #
def check_claude(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_Claude.

    Bash: curl -s -L -o /dev/null -w '%{url_effective}' "https://claude.ai/"
    Checks final redirect URL:
      "https://claude.ai/" → Yes
      "https://www.anthropic.com/app-unavailable-in-region" → No
      else → Unknown (url)
    """
    name = "Claude"
    resp = fetch(ctx.opener, "https://claude.ai/")
    if resp is None:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    final_url = resp.url
    if not final_url:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    if final_url == "https://claude.ai/":
        return CheckResult(name, CheckStatus.OK)
    elif final_url == "https://www.anthropic.com/app-unavailable-in-region":
        return CheckResult(name, CheckStatus.NO)
    else:
        return CheckResult(name, CheckStatus.WARNING, detail=f"Unknown ({final_url})")


# --------------------------------------------------------------------------- #
# 7. WebTest_GoogleSearchCAPTCHA (check.sh L1789)
# --------------------------------------------------------------------------- #
def check_google_captcha(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_GoogleSearchCAPTCHA.

    Bash: curl -sL with full Google search URL and extensive headers.
    Checks:
      grep -iE 'unusual traffic from|is blocked|unaddressed abuse' → No
      grep -i 'curl' → Yes
      neither → PAGE ERROR
    """
    name = "Google CAPTCHA Free"
    url = (
        "https://www.google.com/search?"
        "q=curl&oq=curl"
        "&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBBzg1MmowajGoAgCwAgE"
        "&sourceid=chrome&ie=UTF-8"
    )
    headers = {
        "accept": "*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": UA_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-model": '""',
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-ch-ua-wow64": "?0",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    }
    resp = fetch(ctx.opener, url, headers=headers)
    if resp is None or not resp.text:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    text = resp.text

    # grep -iE 'unusual traffic from|is blocked|unaddressed abuse'
    is_blocked = bool(re.search(r"unusual traffic from|is blocked|unaddressed abuse", text, re.IGNORECASE))
    # grep -i 'curl'
    is_ok = bool(re.search(r"curl", text, re.IGNORECASE))

    if not is_blocked and not is_ok:
        return CheckResult(name, CheckStatus.FAILED, detail="PAGE ERROR")
    if is_blocked:
        return CheckResult(name, CheckStatus.NO)
    if is_ok:
        return CheckResult(name, CheckStatus.OK)

    return CheckResult(name, CheckStatus.FAILED, detail="Unknown")


# ── Check Registry ────────────────────────────────────────────────────────────

CheckFn = Callable[[CheckContext], CheckResult]

ALL_CHECKS: list[CheckFn] = [
    check_reddit,
    check_youtube_premium,
    check_apple_region,
    check_chatgpt,
    check_gemini,
    check_claude,
    check_google_captcha,
]


# ── Output Rendering (ANSI) ──────────────────────────────────────────────────

STATUS_MAP: dict[CheckStatus, tuple[str, str]] = {
    CheckStatus.OK:      ("✅", C_GREEN),
    CheckStatus.NO:      ("❌", C_RED),
    CheckStatus.FAILED:  ("⚠️ ", C_DIM),
    CheckStatus.WARNING: ("⚡", C_YELLOW),
}


def format_status(r: CheckResult) -> str:
    icon, color = STATUS_MAP[r.status]

    match r.status:
        case CheckStatus.OK:
            label = "Yes"
            if r.region:
                label += f" (Region: {r.region})"
        case CheckStatus.NO:
            label = "No"
            if r.region:
                label += f" (Region: {r.region})"
            elif r.detail:
                label += f" ({r.detail})"
        case CheckStatus.FAILED:
            label = "Failed"
            if r.detail:
                label += f" ({r.detail})"
        case CheckStatus.WARNING:
            label = r.detail if r.detail else "Warning"

    return f"{color}{icon} {label}{C_RESET}"


def _display_width(s: str) -> int:
    """Calculate terminal display width of a string.

    Emojis and wide characters occupy 2 columns but len() counts them as 1.
    Variation selectors and combining marks occupy 0 columns.
    A character followed by U+FE0F (emoji presentation selector) is forced
    to 2 columns wide, even if its East Asian Width is Narrow.
    """
    w = 0
    chars = list(s)
    i = 0
    while i < len(chars):
        ch = chars[i]
        cat = unicodedata.category(ch)
        # Zero-width: combining marks, format chars (includes variation selectors)
        if cat.startswith("M") or cat == "Cf":
            i += 1
            continue
        # Check if next char is U+FE0F (emoji presentation selector)
        has_vs16 = (i + 1 < len(chars) and chars[i + 1] == "\uFE0F")
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ("W", "F") or has_vs16:
            w += 2
        else:
            w += 1
        i += 1
    return w


def render_results(
    results: list[CheckResult],
    ip_info: IPInfo,
    version: int,
) -> None:
    W = 62
    BAR = "─" * (W - 2)

    # Header box
    net_label = f"{ip_info.isp} ({ip_info.masked})" if ip_info.isp else ip_info.masked
    lines = [
        f"  🌐  Network:  {net_label}",
    ]
    if ip_info.country:
        lines.append(f"  🏳️   Country:  {ip_info.country}")
    lines.append(f"  📡  Protocol: IPv{version}")

    title = f" VPS Unlock Checker \u2014 IPv{version} "
    title_w = _display_width(title)
    pad = W - 2 - title_w
    left = pad // 2
    right = pad - left

    print(f"\n{C_CYAN}╭{'─' * left}{C_BOLD}{title}{C_RESET}{C_CYAN}{'─' * right}╮{C_RESET}")
    for line in lines:
        vis_w = _display_width(line)
        padding = W - 2 - vis_w
        print(f"{C_CYAN}│{C_RESET}{line}{' ' * max(padding, 0)}{C_CYAN}│{C_RESET}")
    print(f"{C_CYAN}╰{BAR}╯{C_RESET}\n")

    # Results table
    col1 = 28
    print(f"  {C_BOLD}{'Platform':<{col1}} {'Result'}{C_RESET}")
    print(f"  {'─' * (W - 4)}")
    for r in results:
        print(f"  {r.name:<{col1}} {format_status(r)}")
    print()


# ── CLI & Main ─────────────────────────────────────────────────────────────────



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VPS Service Unlock Checker (stdlib, zero dependencies)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-4", "--ipv4", action="store_true", help="Test IPv4 only")
    group.add_argument("-6", "--ipv6", action="store_true", help="Test IPv6 only")
    parser.add_argument(
        "-I", "--interface",
        help="Bind to network interface name or IP address",
    )
    return parser.parse_args()


def determine_versions(args: argparse.Namespace) -> list[int]:
    if args.ipv4:
        return [4]
    if args.ipv6:
        return [6]
    return [4, 6]


def run_checks(ctx: CheckContext) -> list[CheckResult]:
    """Run all checks concurrently using threads."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(check, ctx) for check in ALL_CHECKS]
        return [f.result() for f in futures]


def main() -> None:
    args = parse_args()

    print(f"\n{C_BOLD}{C_CYAN}VPS Unlock Checker{C_RESET}")
    print()

    versions = determine_versions(args)

    for version in versions:
        ipv6 = version == 6

        if args.interface:
            local_addr = resolve_interface(args.interface, ipv6)
        else:
            local_addr = "::" if ipv6 else "0.0.0.0"

        opener = create_opener(local_addr)

        print(f"{C_DIM}Checking IPv{version} connectivity…{C_RESET}", end=" ", flush=True)
        if not check_connectivity(opener):
            print(f"{C_YELLOW}No IPv{version} connectivity, skipping.{C_RESET}")
            print()
            continue
        print(f"{C_DIM}ok.{C_RESET}")

        print(f"{C_DIM}Fetching IPv{version} info…{C_RESET}", end=" ", flush=True)
        ip_info = get_ip_info(opener)
        print(f"{C_DIM}done.{C_RESET}")

        ctx = CheckContext(opener=opener, is_ipv6=ipv6)

        print(f"{C_DIM}Running {len(ALL_CHECKS)} checks…{C_RESET}", flush=True)
        results = run_checks(ctx)

        render_results(results, ip_info, version)


if __name__ == "__main__":
    main()
