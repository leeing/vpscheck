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

async def check_reddit(ctx: CheckContext) -> CheckResult:
    name = "Reddit"
    if ctx.is_ipv6:
        return CheckResult(name, CheckStatus.WARNING, detail="IPv6 not supported")
    try:
        resp = await ctx.client.get("https://www.reddit.com/")
        match resp.status_code:
            case 200:
                return CheckResult(name, CheckStatus.OK)
            case 403:
                return CheckResult(name, CheckStatus.NO)
            case _:
                return CheckResult(name, CheckStatus.FAILED, detail=f"HTTP {resp.status_code}")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")


async def check_youtube_premium(ctx: CheckContext) -> CheckResult:
    name = "YouTube Premium"
    try:
        resp = await ctx.client.get("https://www.youtube.com/premium")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    if not text:
        return CheckResult(name, CheckStatus.FAILED, detail="Empty response")

    if "www.google.cn" in text:
        return CheckResult(name, CheckStatus.NO, region="CN")

    m = re.search(r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([^"]+)"', text)
    region = m.group(1) if m else ""

    if re.search(r"Premium is not available in your country", text, re.IGNORECASE):
        return CheckResult(name, CheckStatus.NO, region=region)

    if "ad-free" in text.lower():
        return CheckResult(name, CheckStatus.OK, region=region)

    return CheckResult(name, CheckStatus.FAILED, detail="Page error")


async def check_apple_region(ctx: CheckContext) -> CheckResult:
    name = "Apple Region"
    try:
        resp = await ctx.client.get("https://gspe1-ssl.ls.apple.com/pep/gcc")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    region = resp.text.strip().upper()
    if region and len(region) == 2:
        return CheckResult(name, CheckStatus.OK, region=region)
    return CheckResult(name, CheckStatus.FAILED, detail="Invalid response")


async def check_chatgpt(ctx: CheckContext) -> CheckResult:
    name = "ChatGPT"
    headers = {
        "authority": "api.openai.com",
        "authorization": "Bearer null",
        "content-type": "application/json",
        "origin": "https://platform.openai.com",
        "referer": "https://platform.openai.com/",
        "sec-ch-ua": UA_SEC_CH_UA,
    }
    try:
        r1 = await ctx.client.get("https://api.openai.com/compliance/cookie_requirements", headers=headers)
        r2 = await ctx.client.get("https://ios.chat.openai.com/", headers={
            "sec-ch-ua": UA_SEC_CH_UA,
            "sec-fetch-dest": "document",
        })
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    has_unsupported = "unsupported_country" in r1.text.lower()
    has_vpn = "VPN" in r2.text

    if not has_unsupported and not has_vpn:
        return CheckResult(name, CheckStatus.OK)
    if has_unsupported and has_vpn:
        return CheckResult(name, CheckStatus.NO)
    if not has_unsupported and has_vpn:
        return CheckResult(name, CheckStatus.WARNING, detail="Web Only")
    return CheckResult(name, CheckStatus.WARNING, detail="APP Only")


async def check_gemini(ctx: CheckContext) -> CheckResult:
    name = "Google Gemini"
    try:
        resp = await ctx.client.get("https://gemini.google.com")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    available = "45631641,null,true" in text
    m = re.search(r",2,1,200,\"([A-Z]{3})\"", text)
    region = m.group(1) if m else ""

    if available:
        return CheckResult(name, CheckStatus.OK, region=region)
    return CheckResult(name, CheckStatus.NO)


async def check_claude(ctx: CheckContext) -> CheckResult:
    name = "Claude"
    try:
        resp = await ctx.client.get("https://claude.ai/", follow_redirects=True)
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    final_url = str(resp.url)
    if final_url.rstrip("/") == "https://claude.ai":
        return CheckResult(name, CheckStatus.OK)
    if "app-unavailable-in-region" in final_url:
        return CheckResult(name, CheckStatus.NO)
    return CheckResult(name, CheckStatus.WARNING, detail=f"Redirect: {final_url}")


async def check_google_play(ctx: CheckContext) -> CheckResult:
    name = "Google Play Store"
    try:
        resp = await ctx.client.get("https://play.google.com/")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    m = re.search(r'gl=([A-Z]{2})', text)
    if not m:
        m = re.search(r'"yVZQTb"[^>]*>([^<(]+)', text)
    region = m.group(1).strip() if m else ""

    if region:
        return CheckResult(name, CheckStatus.OK, region=region)
    return CheckResult(name, CheckStatus.FAILED, detail="Region not found")


async def check_google_captcha(ctx: CheckContext) -> CheckResult:
    name = "Google CAPTCHA Free"
    headers = {
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": UA_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    try:
        resp = await ctx.client.get(
            "https://www.google.com/search?q=curl",
            headers=headers,
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    is_blocked = bool(re.search(r"unusual traffic from|is blocked|unaddressed abuse", text, re.IGNORECASE))
    has_results = "curl" in text.lower()

    if is_blocked:
        return CheckResult(name, CheckStatus.NO)
    if has_results:
        return CheckResult(name, CheckStatus.OK)
    return CheckResult(name, CheckStatus.FAILED, detail="Page error")


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
                parts.append(f"({r.region})")
            elif r.detail:
                parts.append(f"— {r.detail}")
        case CheckStatus.NO:
            parts.append("No")
            if r.detail:
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

    console.print(
        "[bold cyan]VPS Unlock Checker[/bold cyan]"
    )
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
