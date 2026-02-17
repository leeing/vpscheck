#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx", "rich"]
# ///
"""VPS Streaming & Service Unlock Checker.

A Python rewrite of RegionRestrictionCheck/check.sh — supports 17 platform
checks with async HTTP, dual-stack IPv4/IPv6, and pretty Rich output.

Usage:
    uv run check.py          # test both IPv4 and IPv6
    uv run check.py -4       # IPv4 only
    uv run check.py -6       # IPv6 only
    uv run check.py -I eth0  # bind to specific interface
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import re
import socket
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from enum import Enum
from collections.abc import Awaitable, Coroutine, Sequence
from typing import Callable
from urllib.parse import urlparse

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

NETFLIX_COOKIE = (
    "flwssn=d2c72c47-49e9-48da-b7a2-2dc6d7ca9fcf; "
    "nfvdid=BQFmAAEBEMZa4XMYVzVGf9-kQ1HXumtAKsCyuBZU4QStC6CGEGIVznjNuuTerLAG8v2-"
    "9V_kYhg5uxTB5_yyrmqc02U5l1Ts74Qquezc9AE-LZKTo3kY3g%3D%3D; "
    "SecureNetflixId=v%3D3%26mac%3DAQEAEQABABSQHKcR1d0sLV0WTu0lL-BO63TKCCHAkeY."
    "%26dt%3D1745376277212; "
    "NetflixId=v%3D3%26ct%3DBgjHlOvcAxLAAZuNS4_CJHy9NKJPzUV-9gElzTlTsmDS1B59TycR-"
    "fue7f6q7X9JQAOLttD7OnlldUtnYWXL7VUfu9q4pA0gruZKVIhScTYI1GKbyiEqKaULAXOt0PHQzg"
    "RLVTNVoXkxcbu7MYG4wm1870fZkd5qrDOEseZv2WIVk4xIeNL87EZh1vS3RZU3e-qWy2tSmfSNUC-"
    "FVDGwxbI6-hk3Zg2MbcWYd70-ghohcCSZp5WHAGXg_xWVC7FHM3aOUVTGwRCU1RgGIg4KDKGr_wsTR"
    "Rw6HWKqeA..; "
    "gsid=09bb180e-fbb1-4bf6-adcb-a3fa1236e323"
)

IATA_URL_1 = "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt"
IATA_URL_2 = "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode2.txt"

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
    iata_raw1: str = ""
    iata_raw2: str = ""


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


def find_iata_location(iata: str, raw1: str, raw2: str) -> str | None:
    """Look up IATA airport code → city/location name."""
    pat = re.compile(rf"\b{re.escape(iata)}\b", re.IGNORECASE)
    for line in raw1.splitlines():
        if pat.search(line):
            parts = line.split("|")
            if len(parts) >= 3:
                return parts[0].strip()
    for line in raw2.splitlines():
        if pat.search(line):
            parts = line.split(",")
            if len(parts) >= 2:
                return parts[1].strip().title()
    return None


def dns_resolve(host: str, ipv6: bool) -> str | None:
    """Resolve hostname to IP address using the system resolver."""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    try:
        results = socket.getaddrinfo(host, None, family)
        if results:
            return str(results[0][4][0])
    except socket.gaierror:
        pass
    return None


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


async def download_iata_data(client: httpx.AsyncClient) -> tuple[str, str]:
    raw1 = raw2 = ""
    try:
        r1 = await client.get(IATA_URL_1, timeout=10)
        raw1 = r1.text
    except httpx.HTTPError:
        pass
    try:
        r2 = await client.get(IATA_URL_2, timeout=10)
        raw2 = r2.text
    except httpx.HTTPError:
        pass
    return raw1, raw2


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


async def check_netflix(ctx: CheckContext) -> CheckResult:
    name = "Netflix"
    headers = {
        "Cookie": NETFLIX_COOKIE,
        "sec-ch-ua": UA_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        r1 = await ctx.client.get("https://www.netflix.com/title/81280792", headers=headers)
        r2 = await ctx.client.get("https://www.netflix.com/title/70143836", headers=headers)
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    t1, t2 = r1.text, r2.text
    if not t1 or not t2:
        return CheckResult(name, CheckStatus.FAILED, detail="Empty response")

    blocked1 = "Oh no!" in t1
    blocked2 = "Oh no!" in t2

    if blocked1 and blocked2:
        return CheckResult(name, CheckStatus.WARNING, detail="Originals Only")

    # Extract region — try multiple patterns
    region = ""
    # Pattern 1: "currentCountry":"XX"
    m = re.search(r'"currentCountry"\s*:\s*"([A-Z]{2})"', t1)
    if m:
        region = m.group(1)
    if not region:
        # Pattern 2: "country":"xx" near geo context
        m = re.search(r'"country"\s*:\s*"([a-zA-Z]{2})"', t1)
        if m:
            region = m.group(1).upper()
    if not region:
        # Pattern 3: original bash pattern — "id" near "countryName"
        # But filter out likely language codes (2-char lowercase like "zh","en")
        for m_iter in re.finditer(r'"id"\s*:\s*"([^"]+)"[^}]*"countryName"\s*:\s*"([^"]+)"', t1):
            candidate = m_iter.group(1)
            # Country codes from Netflix are typically 2 uppercase letters
            if len(candidate) == 2 and candidate.isalpha():
                region = candidate.upper()
                break
    return CheckResult(name, CheckStatus.OK, region=region)


async def check_youtube_premium(ctx: CheckContext) -> CheckResult:
    name = "YouTube Premium"
    try:
        resp = await ctx.client.get("https://www.youtube.com/premium")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    if not text:
        return CheckResult(name, CheckStatus.FAILED, detail="Empty response")

    # Extract region
    m = re.search(r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([^"]+)"', text)
    region = m.group(1) if m else ""

    if "ad-free" in text.lower() or "Premium" in text:
        return CheckResult(name, CheckStatus.OK, region=region)
    return CheckResult(name, CheckStatus.NO, region=region)


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


async def check_youtube_cdn(ctx: CheckContext) -> CheckResult:
    name = "YouTube CDN"
    try:
        resp = await ctx.client.get("https://redirector.googlevideo.com/report_mapping")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    if not text:
        return CheckResult(name, CheckStatus.FAILED, detail="Empty response")

    # Extract IATA from lines with '=>'
    # Bash: awk '{print $3}' | cut -f2 -d'-' | cut -c 1-3
    # Note: bash `cut -f2 -d'-'` splits on EACH '-' (no collapsing),
    # which is different from Python split('-').
    iata = ""
    for line in text.splitlines():
        if "=>" in line:
            parts = line.split()
            if len(parts) >= 3:
                word = parts[2]
                # Replicate bash `cut -f2 -d'-'`: split on '-', keep 2nd field
                dash_parts = word.split("-")
                # Skip empty fields from consecutive dashes
                non_empty = [p for p in dash_parts if p]
                if len(non_empty) >= 2:
                    raw = non_empty[1]
                    iata = raw[:3].upper()
                elif len(non_empty) == 1:
                    iata = non_empty[0][:3].upper()
                break

    if not iata:
        return CheckResult(name, CheckStatus.FAILED, detail="No IATA code")

    location = find_iata_location(iata, ctx.iata_raw1, ctx.iata_raw2)
    if not location:
        return CheckResult(name, CheckStatus.OK, detail=f"CDN: {iata}")

    is_idc = "router" in text
    if is_idc:
        return CheckResult(name, CheckStatus.OK, detail=location)

    # Third-party CDN — extract ISP from first line
    first_line_parts = text.splitlines()[0].split() if text.splitlines() else []
    cdn_isp = first_line_parts[2].split("-")[0].upper() if len(first_line_parts) >= 3 else "Unknown"
    return CheckResult(name, CheckStatus.OK, detail=f"[{cdn_isp}] in [{location}]")


async def check_netflix_cdn(ctx: CheckContext) -> CheckResult:
    name = "Netflix CDN"
    try:
        resp = await ctx.client.get(
            "https://api.fast.com/netflix/speedtest/v2",
            params={"https": "true", "token": "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm", "urlCount": "1"},
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    if resp.status_code == 403:
        return CheckResult(name, CheckStatus.FAILED, detail="IP Banned")

    try:
        data = resp.json()
    except ValueError:
        return CheckResult(name, CheckStatus.FAILED, detail="Parse error")

    # Extract CDN URL
    targets = data.get("targets", [])
    if not targets:
        url_match = re.search(r'"url"\s*:\s*"([^"]+)"', resp.text)
        cdn_url = url_match.group(1) if url_match else ""
    else:
        cdn_url = targets[0].get("url", "")

    if not cdn_url:
        return CheckResult(name, CheckStatus.FAILED, detail="No CDN URL")

    cdn_domain = urlparse(cdn_url).hostname or ""
    if not cdn_domain:
        return CheckResult(name, CheckStatus.FAILED, detail="Parse error")

    # DNS resolve
    cdn_ip = dns_resolve(cdn_domain, ctx.is_ipv6)
    if not cdn_ip:
        return CheckResult(name, CheckStatus.FAILED, detail="DNS failed")

    # Check if private IP
    try:
        is_private = ipaddress.ip_address(cdn_ip).is_private
    except ValueError:
        is_private = False

    cdn_isp = "Hidden by a VPN"
    if not is_private:
        try:
            geo_resp = await ctx.client.get(f"https://api.ip.sb/geoip/{cdn_ip}", timeout=5)
            geo_data = geo_resp.json()
            cdn_isp = geo_data.get("isp", "Unknown")
        except (httpx.HTTPError, ValueError):
            return CheckResult(name, CheckStatus.FAILED, detail="ISP lookup failed")

    # Extract IATA from domain
    parts = cdn_domain.split("-")
    if len(parts) >= 3:
        raw = parts[2]
        iata = raw[:-3].upper() if len(raw) > 3 else raw.upper()
    else:
        return CheckResult(name, CheckStatus.FAILED, detail="IATA parse error")

    location = find_iata_location(iata, ctx.iata_raw1, ctx.iata_raw2)
    if not location:
        return CheckResult(name, CheckStatus.FAILED, detail="IATA not found")

    if cdn_isp == "Netflix Streaming Services":
        return CheckResult(name, CheckStatus.OK, detail=location)
    return CheckResult(name, CheckStatus.WARNING, detail=f"[{cdn_isp}] in [{location}]")


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
        return CheckResult(name, CheckStatus.WARNING, detail="Web Browser Only")
    return CheckResult(name, CheckStatus.WARNING, detail="Mobile APP Only")


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
    name = "Google Play"
    try:
        resp = await ctx.client.get("https://play.google.com/")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    # Extract region from yVZQTb class or gl= param
    m = re.search(r'gl=([A-Z]{2})', text)
    if not m:
        m = re.search(r'"yVZQTb"[^>]*>([^<]+)', text)
    region = m.group(1).strip() if m else ""

    if region:
        return CheckResult(name, CheckStatus.OK, region=region)
    return CheckResult(name, CheckStatus.FAILED, detail="Region not found")


async def check_google_captcha(ctx: CheckContext) -> CheckResult:
    name = "Google CAPTCHA"
    try:
        resp = await ctx.client.get("https://www.google.com/search?q=curl")
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    if "unusual traffic" in text.lower() or "captcha" in text.lower():
        return CheckResult(name, CheckStatus.NO, detail="CAPTCHA triggered")
    return CheckResult(name, CheckStatus.OK, detail="No CAPTCHA")


async def check_hbo_max(ctx: CheckContext) -> CheckResult:
    name = "HBO Max"
    try:
        # Use follow_redirects=False so we can read Set-Cookie headers
        resp = await ctx.client.get("https://www.max.com/", follow_redirects=False)
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    # countryCode is in Set-Cookie headers and/or response body
    region = ""
    # Check headers first (Set-Cookie: countryCode=XX)
    for val in resp.headers.get_list("set-cookie"):
        m = re.search(r"countryCode=([A-Z]{2})", val)
        if m:
            region = m.group(1)
            break

    # Fallback: follow redirect and check body
    text = resp.text
    if not region:
        # Follow redirects manually to get full body
        if resp.is_redirect:
            try:
                resp2 = await ctx.client.get(str(resp.headers.get("location", "https://www.max.com/")))
                text = resp2.text
                for val in resp2.headers.get_list("set-cookie"):
                    m = re.search(r"countryCode=([A-Z]{2})", val)
                    if m:
                        region = m.group(1)
                        break
            except httpx.HTTPError:
                pass

    if not region:
        m = re.search(r"countryCode=([A-Z]{2})", text)
        region = m.group(1) if m else ""

    if not region:
        return CheckResult(name, CheckStatus.FAILED, detail="Country code not found")

    # Extract available country list from body
    countries = set(re.findall(r'"url":"/([a-z]{2})/[a-z]{2}"', text))
    countries = {c.upper() for c in countries}
    countries.add("US")

    if region in countries:
        return CheckResult(name, CheckStatus.OK, region=region)
    return CheckResult(name, CheckStatus.NO)


async def check_discovery_plus(ctx: CheckContext) -> CheckResult:
    name = "Discovery+"
    if ctx.is_ipv6:
        return CheckResult(name, CheckStatus.WARNING, detail="IPv6 not supported")

    headers = {
        "origin": "https://www.discoveryplus.com",
        "referer": "https://www.discoveryplus.com/",
        "sec-ch-ua": UA_SEC_CH_UA,
        "x-disco-client": "WEB:UNKNOWN:dplus_us:2.46.0",
        "x-disco-params": "bid=dplus,hn=www.discoveryplus.com",
    }

    # Step 1: Bootstrap
    try:
        resp = await ctx.client.get("https://global-prod.disco-api.com/bootstrapInfo", headers=headers)
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    base_url = data.get("data", {}).get("attributes", {}).get("baseApiUrl", "")
    realm = data.get("data", {}).get("attributes", {}).get("realm", "")

    if not base_url or not realm:
        # Try flat structure
        base_url = data.get("baseApiUrl", "")
        realm = data.get("realm", "")

    if not base_url or not realm:
        return CheckResult(name, CheckStatus.FAILED, detail="Bootstrap error")

    if realm == "dplusapac":
        return CheckResult(name, CheckStatus.NO, detail="Not available in Asia Pacific")

    # Step 2: Token
    device_id = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()
    try:
        token_resp = await ctx.client.get(
            f"{base_url}/token",
            params={"deviceId": device_id, "realm": realm, "shortlived": "true"},
            headers={**headers, "x-device-info": f"dplus_us/2.46.0 (desktop/desktop; Windows/NT 10.0; {device_id})"},
        )
        token_data = token_resp.json()
    except (httpx.HTTPError, ValueError):
        return CheckResult(name, CheckStatus.FAILED, detail="Token error")

    token = token_data.get("data", {}).get("attributes", {}).get("token", "")
    if not token:
        m = re.search(r'"token"\s*:\s*"([^"]+)"', token_resp.text)
        token = m.group(1) if m else ""
    if not token:
        return CheckResult(name, CheckStatus.FAILED, detail="No token")

    # Step 3: CMS routes
    try:
        cms_resp = await ctx.client.get(
            f"{base_url}/cms/routes/tabbed-home",
            params={"include": "default", "decorators": "viewingHistory,isFavorite,playbackAllowed,contentAction"},
            headers={**headers, "x-disco-params": f"realm=dplay,bid=dplus,hn=www.discoveryplus.com"},
            cookies={"st": token},
        )
        cms_text = cms_resp.text
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="CMS error")

    if re.search(r"is unavailable in your|not yet available", cms_text, re.IGNORECASE):
        return CheckResult(name, CheckStatus.NO)

    if "relationships" in cms_text.lower():
        m = re.search(r'"mainTerritoryCode"\s*:\s*"([^"]+)"', cms_text)
        region = m.group(1).upper() if m else ""
        return CheckResult(name, CheckStatus.OK, region=region)

    return CheckResult(name, CheckStatus.FAILED, detail="Unknown response")


async def check_hulu(ctx: CheckContext) -> CheckResult:
    name = "Hulu"

    HULU_COOKIE = (
        "_hulu_at=eyJhbGciOiJSUzI1NiJ9.eyJhc3NpZ25tZW50cyI6ImV5SjJNU0k2VzExOSIsInJlZnJlc2hfaW50ZXJ2YWwiOjg2NDAwMDAwLCJ0b2tlbl9pZCI6IjQyZDk0YzA5LWYyZTEtNDdmNC1iYzU4LWUwNTA2NGNhYTdhZCIsImFub255bW91c19pZCI6IjYzNDUzMjA2LWFmYzgtNDU4Yi1iODBkLWNiMzk2MmYzZGQyZCIsImlzc3VlZF9hdCI6MTcwNjYwOTUzODc5MiwidHRsIjozMTUzNjAwMDAwMCwiZGV2aWNlX3VwcGVyIjoxfQ"
        ".e7sRCOndgn1j30XYkenLcLSQ7vwc2PXk-gFHMIF2gu_3UNEJ3pp3xNOZMN0n7DQRw5Jv68WiGxIvf65s8AetOoD4NLt4sZUDDz9HCRmFHzpmAJdtXWZ-HZ4fYucENuqDDDrsdQ"
        "-FCc0mgIe2IXkmQJ6tpIN3Zgcgmpmbeoq6jYyLlqg6f8eMsI1bNAsBGGj-9DXw2PMotlYHWB22pw2NRfJw1TjWXwywRBodAOve7rsu2Vhx-A2-OH4GplRvxLqzCpl2pcjkYg9at"
        "mUB7jnNIf_jHqlek4oRRawahWq-2vWnWmb1eMQcH-v2IHs3YdVk7I-t4iS19auPQrdgo6jPaA; "
        "_hulu_assignments=eyJ2MSI6W119; "
        "XSRF-TOKEN=bcfa1766-1f73-442d-a71b-e1cf6c275f45; "
        "_customer_type=anonymous; "
        "guid=B26515EB8A7952D4D35F374465362A72"
    )

    HULU_RECAPTCHA = (
        "03AFcWeA6UFet_b_82RUmGfFWJCWuqy6kIn854Rhqjwd7vrkjH6Vku1wBZy8-FBA3Efx1p2cuNnKeJRuk7yJWm-xZgFfUx0Wdj2OAhiGvIdWrcpfeuQSXEqaXH4FKdmAHVZ3EqHwe5"
        "-h_zgtcyIxq-Nn1-sjeUfx1Y7QyVkb_GWJcr0GLoKgTFLzbF4kmJ8Qsi4IFx9hyYo9TFbBqtYdgxCI2q9DnEzOHrxK-987PEY8qzsR08Hrb9oDvumqLp1gs4uEVTwDKWt37aNB3CMV"
        "BKL2lHj7n768kXpgkXFDIhcM2eiJJ-H22qxKzNUpg-Q_N1xzkYsavCJG3ckQgsCTRRP2NU3nIERTWDTVXRBEq52-_ZQWu_Ds4W4UZyP0hEhCD2gambN4YJqEzaeHdGPwOR943nFbG6GI"
        "LBx4vY-UUc7zjMf2HRjkNPvPpQiHMIYo21JXq6l8-IWyTeHY26NU6M4vCCbzwZEsdSln48rXM_fdBcDHC-8AxUFuBR8j3DMsB6Q3xMS2EHeGVrmhDY1izDNJZsVC_cN0W2tRneOJmni"
        "7ZU1iAYoBAGBBM5FDTE4UbYUTnuUn-htm9Q0RzukpYTumF_WwQ3HnEL0JK1Q1xea-hteI8lB4oAkhVOBOHVPii9atdZR9ZLpxRh1pdy3Lwmr1ltsubxE05wqmrmt33P2WsvH_3nBJXC_Fh"
        "TD06BxT60RuiGtFr2gscHjjl_NCa1F-Dv9Hgi5ek2nLHK37a84bRSoKwLL3Lnpi9byuBntlpf-UXj7nveawKZmZTUBOSc7j6Vmmf124DTPJXsFeofMfUXkqTauPTWJBOz0OdKnLKDHMSs"
        "k7oSJVKsDUEeq0iKMdtCMBPvQBaPYAb79LDRwv_ereqyklKcUKQxeZRZmEXLKIWp8BS4U9uTXA2w8hwZWe7goLnUBQATIwojeHKpypSLnzQBu9JCwMU4aXfKIplL8sXuAx3QFD52eGZSCE"
        "yuFXP3ACN53QOlTAjjlP2eDT9fEwWHT4o8eJfviyjvm8xDmzKtq4F3u5XB3tL86-dK40XYbGcTI0Irw1nz1UTcxplFgHQgb6i8WEAqb69CQkpGWAUlmnknBirRAv2adqPaW2d_lv6L3E"
        "o-ZupWcZ9Cu4PibM5BruVNXifBwPNPXHKw-sWBj-UP1g9VtxHVEVwoTXrbB-lT8EvjDEDQKrvOwnri4_tzVzn6YKvQMELbxSegvmc2w7xypT2qFzKRFXqwTMLT9d0rf2p9tbwbe39REMR8"
        "oI7wPfbjyJjK2XF4DmEAyVvBMuJlBaBsKBs5VynITHFWs4xvkAOe4jO_fzkKXzB6F6DB03ldasxbrNK_cepUOF6FD39-pHvbAGcoTrDrx6FSfecYXwSvc3GxM3IHSKwISKWav2iqPMtIt6"
        "ClCgUPgTCBDng2ZptXeVG8FckGIGMEdVlgGt5DG2tdMO2p8Hs5tKXuu8anc_csaaSfLIQ1_kav0dp8vpSXhCxeg899o5coXderUoIBcUsfaBJJm80YnCAc4LaM8HmYtJBcKqCC_uwCckPDOu"
        "C0SQy3d07LEi6wyifvY0Kv_-ER6wXvhNWnDZIXJNlH2369X7y8o3y2HMisOwAhfmKN7_ZAaODEOO-5x9JHocAYnt4a8_focwU9JQ_hUQgtdzYpP1ACEqxVjJb0A0NlABpm-CG8V9n9y6Xp"
        "ZkGQiMYJIH3jr6VilHSEM9rQSEv6LN8NFigl3-5Y4Ri7W4joz3LUMQcjFj3qXd3AXonarXhwglVNB9BYquCdA5eq4wVUeAkm3R-e56TK5IZwpb5wNJDO3PhuXHSMwv1k-NEAIfI9_w"
    )

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Cookie": HULU_COOKIE,
        "Origin": "https://www.hulu.com",
        "Referer": "https://www.hulu.com/welcome",
        "sec-ch-ua": UA_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    form_data = (
        "user_email=me%40jamchoi.cc"
        "&password=Jam0.5cm~"
        "&recaptcha_type=web_invisible"
        f"&rrventerprise={HULU_RECAPTCHA}"
        "&scenario=web_password_login"
        "&csrf=c2c20e89ce4e314771dcda79994b2cd020b9c30fc25faccdc1ebef3351a5b36b"
    )
    try:
        resp = await ctx.client.post(
            "https://auth.hulu.com/v4/web/password/authenticate",
            headers=headers,
            content=form_data,
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    try:
        data = resp.json()
        result_name = data.get("name", "")
    except ValueError:
        m = re.search(r'"name"\s*:\s*"([^"]+)"', resp.text)
        result_name = m.group(1) if m else ""

    match result_name:
        case "LOGIN_FORBIDDEN":
            return CheckResult(name, CheckStatus.OK)
        case "GEO_BLOCKED":
            return CheckResult(name, CheckStatus.NO)
        case "":
            return CheckResult(name, CheckStatus.FAILED, detail="Parse error")
        case _:
            return CheckResult(name, CheckStatus.FAILED, detail=result_name)


async def check_bbc_iplayer(ctx: CheckContext) -> CheckResult:
    name = "BBC iPLAYER"
    if ctx.is_ipv6:
        return CheckResult(name, CheckStatus.WARNING, detail="IPv6 not supported")
    try:
        resp = await ctx.client.get(
            "https://open.live.bbc.co.uk/mediaselector/6/select/version/2.0"
            "/mediaset/pc/vpid/bbc_one_london/format/json/jsfunc/JS_callbacks0"
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    text = resp.text
    if "geolocation" in text.lower():
        return CheckResult(name, CheckStatus.NO)
    if "vs-hls-push-uk" in text.lower():
        return CheckResult(name, CheckStatus.OK)
    return CheckResult(name, CheckStatus.FAILED, detail="Unknown response")


async def check_bilibili_hkmc_tw(ctx: CheckContext) -> CheckResult:
    name = "Bilibili HK/MC/TW"
    if ctx.is_ipv6:
        return CheckResult(name, CheckStatus.WARNING, detail="IPv6 not supported")

    session = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()
    try:
        resp = await ctx.client.get(
            "https://api.bilibili.com/pgc/player/web/playurl",
            params={
                "avid": "18281381", "cid": "29892777", "qn": "0",
                "type": "", "otype": "json", "ep_id": "364789",
                "fourk": "1", "fnver": "0", "fnval": "16",
                "session": session, "module": "bangumi",
            },
            headers={"Referer": "https://www.bilibili.com"},
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    try:
        data = resp.json()
        code = data.get("code", -1)
    except ValueError:
        return CheckResult(name, CheckStatus.FAILED, detail="Parse error")

    if code == 0:
        return CheckResult(name, CheckStatus.OK)
    if code == -10403:
        return CheckResult(name, CheckStatus.NO)
    return CheckResult(name, CheckStatus.FAILED, detail=f"Code: {code}")


async def check_bilibili_tw(ctx: CheckContext) -> CheckResult:
    name = "Bilibili TW Only"
    if ctx.is_ipv6:
        return CheckResult(name, CheckStatus.WARNING, detail="IPv6 not supported")

    session = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()
    try:
        resp = await ctx.client.get(
            "https://api.bilibili.com/pgc/player/web/playurl",
            params={
                "avid": "50762638", "cid": "100279344", "qn": "0",
                "type": "", "otype": "json", "ep_id": "268176",
                "fourk": "1", "fnver": "0", "fnval": "16",
                "session": session, "module": "bangumi",
            },
            headers={"Referer": "https://www.bilibili.com"},
        )
    except httpx.HTTPError:
        return CheckResult(name, CheckStatus.FAILED, detail="Network")

    try:
        data = resp.json()
        code = data.get("code", -1)
    except ValueError:
        return CheckResult(name, CheckStatus.FAILED, detail="Parse error")

    if code == 0:
        return CheckResult(name, CheckStatus.OK)
    if code == -10403:
        return CheckResult(name, CheckStatus.NO)
    return CheckResult(name, CheckStatus.FAILED, detail=f"Code: {code}")


# ── Check Registry ────────────────────────────────────────────────────────────

CheckFn = Callable[[CheckContext], Awaitable[CheckResult]]

ALL_CHECKS: list[CheckFn] = [
    check_reddit,
    check_netflix,
    check_youtube_premium,
    check_apple_region,
    check_youtube_cdn,
    check_netflix_cdn,
    check_chatgpt,
    check_gemini,
    check_claude,
    check_google_play,
    check_google_captcha,
    check_hbo_max,
    check_discovery_plus,
    check_hulu,
    check_bbc_iplayer,
    check_bilibili_hkmc_tw,
    check_bilibili_tw,
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
    # Header panel
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

    # Results table
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
        description="VPS Streaming & Service Unlock Checker",
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
        "[bold cyan]VPS Unlock Checker[/bold cyan] — "
        "[dim]Python rewrite · github.com/lmc999/RegionRestrictionCheck[/dim]"
    )
    console.print()

    # Download IATA data once
    console.print("[dim]Downloading IATA data…[/dim]", end=" ")
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as setup_client:
        iata1, iata2 = await download_iata_data(setup_client)
    console.print("[dim]done.[/dim]")

    versions = determine_versions(args)

    for version in versions:
        ipv6 = version == 6

        # Determine local address
        if args.interface:
            local_addr = resolve_interface(args.interface, ipv6)
        else:
            local_addr = "::" if ipv6 else "0.0.0.0"

        async with create_client(local_addr) as client:
            # Check connectivity
            console.print(f"[dim]Checking IPv{version} connectivity…[/dim]", end=" ")
            if not await check_connectivity(client):
                console.print(f"[yellow]No IPv{version} connectivity, skipping.[/yellow]")
                console.print()
                continue
            console.print("[dim]ok.[/dim]")

            # Get IP info
            console.print(f"[dim]Fetching IPv{version} info…[/dim]", end=" ")
            ip_info = await get_ip_info(client)
            console.print("[dim]done.[/dim]")

            # Create context
            ctx = CheckContext(
                client=client,
                is_ipv6=ipv6,
                iata_raw1=iata1,
                iata_raw2=iata2,
            )

            # Run all checks concurrently
            console.print(f"[dim]Running {len(ALL_CHECKS)} checks…[/dim]")
            results = await run_checks(ctx)

            # Render
            console.print()
            render_results(console, results, ip_info, version)


if __name__ == "__main__":
    asyncio.run(main())
