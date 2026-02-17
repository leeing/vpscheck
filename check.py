#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx", "rich"]
# ///
"""VPS Service Unlock Checker.

Checks whether a VPS can access major services without restrictions.
Supports dual-stack IPv4/IPv6 testing.

Usage:
    uv run check.py          # test both IPv4 and IPv6
    uv run check.py -4       # IPv4 only
    uv run check.py -6       # IPv6 only
    uv run check.py -I eth0  # bind to specific interface
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import re
import socket
import subprocess
import sys
from collections.abc import Awaitable
from dataclasses import dataclass
from enum import Enum
from typing import Callable

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ── Constants ──────────────────────────────────────────────────────────────────

UA_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
UA_SEC_CH_UA = '"Chromium";v="125", "Not-A.Brand";v="24"'

DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=10.0)


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
    client: httpx.AsyncClient
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


# ── HTTP & Network ─────────────────────────────────────────────────────────────

def create_client(local_address: str) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport(local_address=local_address, retries=2)
    return httpx.AsyncClient(
        transport=transport,
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": UA_BROWSER},
    )


async def check_connectivity(client: httpx.AsyncClient) -> bool:
    try:
        await client.get("https://www.google.com/generate_204", timeout=5)
        return True
    except httpx.HTTPError:
        return False


async def get_ip_info(client: httpx.AsyncClient) -> IPInfo:
    info = IPInfo()
    try:
        resp = await client.get("https://api64.ipify.org", timeout=5)
        info.ip = resp.text.strip()
    except httpx.HTTPError:
        return info
    try:
        resp = await client.get(f"https://api.ip.sb/geoip/{info.ip}", timeout=5)
        data = resp.json()
        info.isp = data.get("isp", "")
        info.country = data.get("country", "")
    except (httpx.HTTPError, ValueError):
        pass
    return info


# ── Platform Checks ───────────────────────────────────────────────────────────
# Each function faithfully replicates the corresponding bash function in
# check.sh, including all headers, cookies, URLs, and response parsing logic.

# --------------------------------------------------------------------------- #
# 1. WebTest_Reddit (check.sh L3701)
# --------------------------------------------------------------------------- #
async def check_reddit(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_Reddit.

    Bash: curl -fsL 'https://www.reddit.com/' -w %{http_code} -o /dev/null
    Only checks HTTP status code. IPv6 not supported.
    """
    name = "Reddit"
    if ctx.is_ipv6:
        return CheckResult(name, CheckStatus.WARNING, detail="IPv6 not supported")
    try:
        resp = await ctx.client.get("https://www.reddit.com/")
    except httpx.HTTPError:
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
async def check_youtube_premium(ctx: CheckContext) -> CheckResult:
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
    try:
        resp = await ctx.client.get("https://www.youtube.com/premium", headers=headers)
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    text = resp.text
    if not text:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    # Check CN redirect
    if "www.google.cn" in text:
        return CheckResult(name, CheckStatus.NO, region="CN")

    # Extract region: grep -woP '"INNERTUBE_CONTEXT_GL"\s*:\s*"\K[^"]+'
    m = re.search(r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([^"]+)"', text)
    region = m.group(1) if m else ""

    # Check not available
    is_not_available = re.search(r"Premium is not available in your country", text, re.IGNORECASE)
    if is_not_available:
        return CheckResult(name, CheckStatus.NO, region=region)

    # Check available
    if not region:
        region = "UNKNOWN"
    is_available = re.search(r"ad-free", text, re.IGNORECASE)
    if is_available:
        return CheckResult(name, CheckStatus.OK, region=region)

    return CheckResult(name, CheckStatus.FAILED, detail="PAGE ERROR")


# --------------------------------------------------------------------------- #
# 3. RegionTest_Apple (check.sh L1738)
# --------------------------------------------------------------------------- #
async def check_apple_region(ctx: CheckContext) -> CheckResult:
    """Faithful port of RegionTest_Apple.

    Bash: curl -sL 'https://gspe1-ssl.ls.apple.com/pep/gcc'
    Simply returns the response text as the region.
    Empty → Failed, otherwise shows the result.
    """
    name = "Apple Region"
    try:
        resp = await ctx.client.get("https://gspe1-ssl.ls.apple.com/pep/gcc")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    result = resp.text.strip()
    if not result:
        return CheckResult(name, CheckStatus.FAILED)
    return CheckResult(name, CheckStatus.OK, region=result)


# --------------------------------------------------------------------------- #
# 4. WebTest_OpenAI / ChatGPT (check.sh L4510)
# --------------------------------------------------------------------------- #
async def check_chatgpt(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_OpenAI.

    Makes two requests:
      1) GET https://api.openai.com/compliance/cookie_requirements
         with authority, authorization, content-type, origin, referer,
         sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-* headers.
      2) GET https://ios.chat.openai.com/
         with authority, accept, accept-language, sec-ch-ua, sec-ch-ua-mobile,
         sec-ch-ua-platform, sec-fetch-*, upgrade-insecure-requests headers.

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

    try:
        resp1 = await ctx.client.get(
            "https://api.openai.com/compliance/cookie_requirements",
            headers=headers1,
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    try:
        resp2 = await ctx.client.get(
            "https://ios.chat.openai.com/",
            headers=headers2,
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    text1 = resp1.text
    text2 = resp2.text
    if not text1 or not text2:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    # grep -i 'unsupported_country'
    has_unsupported = bool(re.search(r"unsupported_country", text1, re.IGNORECASE))
    # grep -i 'VPN'
    has_vpn = bool(re.search(r"VPN", text2))

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
async def check_gemini(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_Gemini.

    Bash: curl -sL "https://gemini.google.com"
    Checks: if response starts with "curl" → network error.
    grep -q '45631641,null,true' → available.
    grep -o ',2,1,200,"[A-Z]{3}"' → extract country code.
    """
    name = "Google Gemini"
    try:
        resp = await ctx.client.get("https://gemini.google.com")
    except httpx.HTTPError:
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
async def check_claude(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_Claude.

    Bash: curl -s -L -o /dev/null -w '%{url_effective}' "https://claude.ai/"
    Checks final redirect URL:
      "https://claude.ai/" → Yes
      "https://www.anthropic.com/app-unavailable-in-region" → No
      else → Unknown (url)
    """
    name = "Claude"
    try:
        resp = await ctx.client.get("https://claude.ai/", follow_redirects=True)
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    final_url = str(resp.url)
    if not final_url:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    if final_url == "https://claude.ai/":
        return CheckResult(name, CheckStatus.OK)
    elif final_url == "https://www.anthropic.com/app-unavailable-in-region":
        return CheckResult(name, CheckStatus.NO)
    else:
        return CheckResult(name, CheckStatus.WARNING, detail=f"Unknown ({final_url})")


# --------------------------------------------------------------------------- #
# 7. WebTest_GooglePlayStore (check.sh L1727)
# --------------------------------------------------------------------------- #
async def check_google_play(ctx: CheckContext) -> CheckResult:
    """Faithful port of WebTest_GooglePlayStore.

    Bash: curl -sL 'https://play.google.com/' with extensive headers,
          then grep -oP '<div class="yVZQTb">\\K[^<(]+'
    Shows the extracted region name, or Failed if empty.
    """
    name = "Google Play Store"
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US;q=0.9",
        "priority": "u=0, i",
        "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    }
    try:
        resp = await ctx.client.get("https://play.google.com/", headers=headers)
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    text = resp.text
    # grep -oP '<div class="yVZQTb">\K[^<(]+'
    m = re.search(r'<div class="yVZQTb">([^<(]+)', text)
    result = m.group(1).strip() if m else ""

    if not result:
        return CheckResult(name, CheckStatus.FAILED)
    return CheckResult(name, CheckStatus.OK, region=result)


# --------------------------------------------------------------------------- #
# 8. WebTest_GoogleSearchCAPTCHA (check.sh L1789)
# --------------------------------------------------------------------------- #
async def check_google_captcha(ctx: CheckContext) -> CheckResult:
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
    try:
        resp = await ctx.client.get(url, headers=headers)
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

    text = resp.text
    if not text:
        return CheckResult(name, CheckStatus.FAILED, detail="Network Connection")

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

CheckFn = Callable[[CheckContext], Awaitable[CheckResult]]

ALL_CHECKS: list[CheckFn] = [
    check_reddit,
    check_youtube_premium,
    check_apple_region,
    check_chatgpt,
    check_gemini,
    check_claude,
    check_google_play,
    check_google_captcha,
]


# ── Output Rendering ──────────────────────────────────────────────────────────

STATUS_STYLE = {
    CheckStatus.OK: ("✅", "green"),
    CheckStatus.NO: ("❌", "red"),
    CheckStatus.FAILED: ("⚠️ ", "dim red"),
    CheckStatus.WARNING: ("⚡", "yellow"),
}


def format_status(r: CheckResult) -> Text:
    icon, color = STATUS_STYLE[r.status]
    parts: list[str] = [icon]

    match r.status:
        case CheckStatus.OK:
            parts.append("Yes")
            if r.region:
                parts.append(f"(Region: {r.region})")
        case CheckStatus.NO:
            parts.append("No")
            if r.region:
                parts.append(f"(Region: {r.region})")
            elif r.detail:
                parts.append(f"({r.detail})")
        case CheckStatus.FAILED:
            parts.append("Failed")
            if r.detail:
                parts.append(f"({r.detail})")
        case CheckStatus.WARNING:
            if r.detail:
                parts.append(r.detail)
            else:
                parts.append("Warning")

    return Text(" ".join(parts), style=color)


def render_results(
    console: Console,
    results: list[CheckResult],
    ip_info: IPInfo,
    version: int,
) -> None:
    header_lines = []
    net_label = f"{ip_info.isp} ({ip_info.masked})" if ip_info.isp else ip_info.masked
    header_lines.append(f"🌐  Network: {net_label}")
    if ip_info.country:
        header_lines.append(f"🏳️   Country: {ip_info.country}")
    header_lines.append(f"📡  Protocol: IPv{version}")

    console.print(Panel(
        "\n".join(header_lines),
        title=f"[bold cyan]VPS Unlock Checker — IPv{version}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    table = Table(
        show_header=True,
        header_style="bold white",
        border_style="dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Platform", style="bold", ratio=2)
    table.add_column("Result", ratio=3)

    for r in results:
        table.add_row(r.name, format_status(r))

    console.print(table)
    console.print()


# ── CLI & Main ─────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VPS Service Unlock Checker",
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


async def run_checks(ctx: CheckContext) -> list[CheckResult]:
    coros = [check(ctx) for check in ALL_CHECKS]
    results: list[CheckResult] = list(await asyncio.gather(*coros))
    return results


async def main() -> None:
    args = parse_args()
    console = Console()

    console.print("[bold cyan]VPS Unlock Checker[/bold cyan]")
    console.print()

    versions = determine_versions(args)

    for version in versions:
        ipv6 = version == 6

        if args.interface:
            local_addr = resolve_interface(args.interface, ipv6)
        else:
            local_addr = "::" if ipv6 else "0.0.0.0"

        async with create_client(local_addr) as client:
            console.print(f"[dim]Checking IPv{version} connectivity…[/dim]", end=" ")
            if not await check_connectivity(client):
                console.print(f"[yellow]No IPv{version} connectivity, skipping.[/yellow]")
                console.print()
                continue
            console.print("[dim]ok.[/dim]")

            console.print(f"[dim]Fetching IPv{version} info…[/dim]", end=" ")
            ip_info = await get_ip_info(client)
            console.print("[dim]done.[/dim]")

            ctx = CheckContext(client=client, is_ipv6=ipv6)

            console.print(f"[dim]Running {len(ALL_CHECKS)} checks…[/dim]")
            results = await run_checks(ctx)

            console.print()
            render_results(console, results, ip_info, version)


if __name__ == "__main__":
    asyncio.run(main())
