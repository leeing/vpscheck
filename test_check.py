"""Unit tests for check.py — VPS Service Unlock Checker."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from check import (
    CheckContext,
    CheckResult,
    CheckStatus,
    IPInfo,
    Response,
    _display_width,
    check_apple_region,
    check_chatgpt,
    check_claude,
    check_gemini,
    check_google_captcha,
    check_reddit,
    check_youtube_premium,
    determine_versions,
    format_status,
)

# ── Data Model Tests ──────────────────────────────────────────────────────────


class TestIPInfo(unittest.TestCase):
    """Test IPInfo.masked property."""

    def test_masked_ipv4(self) -> None:
        info = IPInfo(ip="1.2.3.4")
        assert info.masked == "1.2.*.*"

    def test_masked_ipv6(self) -> None:
        info = IPInfo(ip="2001:db8:85a3::8a2e:370:7334")
        assert info.masked == "2001:db8:85a3:*:*"

    def test_masked_empty(self) -> None:
        info = IPInfo()
        assert info.masked == "Unknown"


class TestCheckResult(unittest.TestCase):
    """Test CheckResult dataclass defaults."""

    def test_defaults(self) -> None:
        r = CheckResult(name="Test", status=CheckStatus.OK)
        assert r.region == ""
        assert r.detail == ""


class TestCheckStatus(unittest.TestCase):
    """Test CheckStatus enum values."""

    def test_values(self) -> None:
        assert CheckStatus.OK.value == "ok"
        assert CheckStatus.NO.value == "no"
        assert CheckStatus.FAILED.value == "failed"
        assert CheckStatus.WARNING.value == "warning"


# ── Utility Tests ─────────────────────────────────────────────────────────────


class TestDisplayWidth(unittest.TestCase):
    """Test _display_width for ASCII and wide chars."""

    def test_ascii(self) -> None:
        assert _display_width("hello") == 5

    def test_wide_chars(self) -> None:
        # CJK characters are 2 columns wide
        assert _display_width("你好") == 4

    def test_empty(self) -> None:
        assert _display_width("") == 0


class TestDetermineVersions(unittest.TestCase):
    """Test CLI version selection logic."""

    def test_default_both(self) -> None:
        args = MagicMock(ipv4=False, ipv6=False)
        assert determine_versions(args) == [4, 6]

    def test_ipv4_only(self) -> None:
        args = MagicMock(ipv4=True, ipv6=False)
        assert determine_versions(args) == [4]

    def test_ipv6_only(self) -> None:
        args = MagicMock(ipv4=False, ipv6=True)
        assert determine_versions(args) == [6]


class TestFormatStatus(unittest.TestCase):
    """Test format_status produces expected label text."""

    def test_ok_no_region(self) -> None:
        r = CheckResult("Test", CheckStatus.OK)
        result = format_status(r)
        assert "Yes" in result

    def test_ok_with_region(self) -> None:
        r = CheckResult("Test", CheckStatus.OK, region="US")
        result = format_status(r)
        assert "US" in result

    def test_no_status(self) -> None:
        r = CheckResult("Test", CheckStatus.NO)
        result = format_status(r)
        assert "No" in result

    def test_failed(self) -> None:
        r = CheckResult("Test", CheckStatus.FAILED, detail="Timeout")
        result = format_status(r)
        assert "Timeout" in result


# ── Platform Check Tests (mocked HTTP) ────────────────────────────────────────


def _make_ctx(*, ipv6: bool = False) -> CheckContext:
    """Create a CheckContext with a mock opener."""
    return CheckContext(opener=MagicMock(), is_ipv6=ipv6)


class TestCheckReddit(unittest.TestCase):
    """Test check_reddit with mocked responses."""

    def test_ipv6_not_supported(self) -> None:
        ctx = _make_ctx(ipv6=True)
        r = check_reddit(ctx)
        assert r.status == CheckStatus.WARNING
        assert "IPv6" in r.detail

    @patch("check.fetch")
    def test_ok(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "", "https://www.reddit.com/")
        r = check_reddit(_make_ctx())
        assert r.status == CheckStatus.OK

    @patch("check.fetch")
    def test_blocked(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(403, "", "https://www.reddit.com/")
        r = check_reddit(_make_ctx())
        assert r.status == CheckStatus.NO

    @patch("check.fetch")
    def test_network_error(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = None
        r = check_reddit(_make_ctx())
        assert r.status == CheckStatus.FAILED


class TestCheckYouTubePremium(unittest.TestCase):
    """Test check_youtube_premium with mocked responses."""

    @patch("check.fetch")
    def test_cn_redirect(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "redirect to www.google.cn", "")
        r = check_youtube_premium(_make_ctx())
        assert r.status == CheckStatus.NO
        assert r.region == "CN"

    @patch("check.fetch")
    def test_available(self, mock_fetch: MagicMock) -> None:
        body = '"INNERTUBE_CONTEXT_GL":"US" ad-free experience'
        mock_fetch.return_value = Response(200, body, "")
        r = check_youtube_premium(_make_ctx())
        assert r.status == CheckStatus.OK
        assert r.region == "US"

    @patch("check.fetch")
    def test_not_available(self, mock_fetch: MagicMock) -> None:
        body = '"INNERTUBE_CONTEXT_GL":"XX" Premium is not available in your country'
        mock_fetch.return_value = Response(200, body, "")
        r = check_youtube_premium(_make_ctx())
        assert r.status == CheckStatus.NO

    @patch("check.fetch")
    def test_network_error(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = None
        r = check_youtube_premium(_make_ctx())
        assert r.status == CheckStatus.FAILED


class TestCheckAppleRegion(unittest.TestCase):
    """Test check_apple_region."""

    @patch("check.fetch")
    def test_ok(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "US", "")
        r = check_apple_region(_make_ctx())
        assert r.status == CheckStatus.OK
        assert r.region == "US"

    @patch("check.fetch")
    def test_empty_response(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "", "")
        r = check_apple_region(_make_ctx())
        assert r.status == CheckStatus.FAILED


class TestCheckChatGPT(unittest.TestCase):
    """Test check_chatgpt."""

    @patch("check.fetch_no_redirect")
    def test_ok(self, mock_fetch: MagicMock) -> None:
        mock_fetch.side_effect = [
            Response(200, "cookie compliance ok", ""),
            Response(200, "welcome to chat", ""),
        ]
        r = check_chatgpt(_make_ctx())
        assert r.status == CheckStatus.OK

    @patch("check.fetch_no_redirect")
    def test_blocked(self, mock_fetch: MagicMock) -> None:
        mock_fetch.side_effect = [
            Response(200, "unsupported_country", ""),
            Response(200, "VPN detected", ""),
        ]
        r = check_chatgpt(_make_ctx())
        assert r.status == CheckStatus.NO


class TestCheckGemini(unittest.TestCase):
    """Test check_gemini."""

    @patch("check.fetch")
    def test_available(self, mock_fetch: MagicMock) -> None:
        body = '45631641,null,true and ,2,1,200,"USA"'
        mock_fetch.return_value = Response(200, body, "")
        r = check_gemini(_make_ctx())
        assert r.status == CheckStatus.OK
        assert r.region == "USA"

    @patch("check.fetch")
    def test_not_available(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "no marker here", "")
        r = check_gemini(_make_ctx())
        assert r.status == CheckStatus.NO


class TestCheckClaude(unittest.TestCase):
    """Test check_claude."""

    @patch("check.fetch")
    def test_ok(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "", "https://claude.ai/")
        r = check_claude(_make_ctx())
        assert r.status == CheckStatus.OK

    @patch("check.fetch")
    def test_blocked(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "", "https://www.anthropic.com/app-unavailable-in-region")
        r = check_claude(_make_ctx())
        assert r.status == CheckStatus.NO


class TestCheckGoogleCaptcha(unittest.TestCase):
    """Test check_google_captcha."""

    @patch("check.fetch")
    def test_ok(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "curl download page", "")
        r = check_google_captcha(_make_ctx())
        assert r.status == CheckStatus.OK

    @patch("check.fetch")
    def test_blocked(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = Response(200, "unusual traffic from your network", "")
        r = check_google_captcha(_make_ctx())
        assert r.status == CheckStatus.NO


class TestCheckChatGPTEdgeCases(unittest.TestCase):
    """Edge cases for check_chatgpt."""

    @patch("check.fetch_no_redirect")
    def test_vpn_case_insensitive(self, mock_fetch: MagicMock) -> None:
        """Upstream bash uses grep -i 'VPN' (case-insensitive)."""
        mock_fetch.side_effect = [
            Response(200, "cookie compliance ok", ""),
            Response(200, "vpn detected lowercase", ""),
        ]
        r = check_chatgpt(_make_ctx())
        assert r.status == CheckStatus.WARNING
        assert "Web Browser" in r.detail


class TestCheckGoogleCaptchaEdgeCases(unittest.TestCase):
    """Edge cases for check_google_captcha."""

    @patch("check.fetch")
    def test_both_blocked_and_ok(self, mock_fetch: MagicMock) -> None:
        """When both 'curl' and 'unusual traffic' appear, blocked takes priority."""
        mock_fetch.return_value = Response(200, "curl page with unusual traffic from your network", "")
        r = check_google_captcha(_make_ctx())
        assert r.status == CheckStatus.NO


class TestCheckYouTubePremiumEdgeCases(unittest.TestCase):
    """Edge cases for check_youtube_premium."""

    @patch("check.fetch")
    def test_not_available_with_region(self, mock_fetch: MagicMock) -> None:
        """Region is captured even when premium is not available."""
        body = '"INNERTUBE_CONTEXT_GL":"JP" Premium is not available in your country'
        mock_fetch.return_value = Response(200, body, "")
        r = check_youtube_premium(_make_ctx())
        assert r.status == CheckStatus.NO
        assert r.region == "JP"


class TestResolveInterface(unittest.TestCase):
    """Tests for resolve_interface."""

    def test_direct_ip(self) -> None:
        """An IP address string is returned as-is."""
        from check import resolve_interface

        assert resolve_interface("192.168.1.1", ipv6=False) == "192.168.1.1"

    def test_direct_ipv6(self) -> None:
        """An IPv6 address string is returned as-is."""
        from check import resolve_interface

        assert resolve_interface("::1", ipv6=True) == "::1"

    @patch("check.subprocess.run")
    def test_file_not_found(self, mock_run: MagicMock) -> None:
        """When 'ip' command is not found, exits gracefully."""
        from check import resolve_interface

        mock_run.side_effect = FileNotFoundError
        with self.assertRaises(SystemExit):
            resolve_interface("eth0", ipv6=False)


if __name__ == "__main__":
    unittest.main()
