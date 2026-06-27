import unittest
from unittest.mock import patch

import doh_http_proxy


class TrafficStatsTests(unittest.TestCase):
    def test_record_sent_and_received_accumulate(self) -> None:
        stats = doh_http_proxy.TrafficStats()

        stats.record_sent(100)
        stats.record_sent(0)
        stats.record_received(250)
        stats.record_received(-5)

        self.assertEqual(stats.snapshot(), (100, 250))

    def test_format_byte_count_uses_human_readable_units(self) -> None:
        self.assertEqual(doh_http_proxy.format_byte_count(999), "999 B")
        self.assertEqual(doh_http_proxy.format_byte_count(1536), "1.5 KB")

    def test_render_proxy_session_screen_clears_and_rewrites_full_page(self) -> None:
        class FakeStdout:
            def __init__(self) -> None:
                self.parts: list[str] = []

            def isatty(self) -> bool:
                return True

            def write(self, text: str) -> int:
                self.parts.append(text)
                return len(text)

            def flush(self) -> None:
                pass

        stats = doh_http_proxy.TrafficStats()
        stats.record_sent(1024)
        stats.record_received(2048)

        fake_stdout = FakeStdout()
        config = doh_http_proxy.StartupConfig()

        with patch("doh_http_proxy.sys.stdout", fake_stdout), patch(
            "doh_http_proxy.enable_ansi_colors"
        ):
            doh_http_proxy.render_proxy_session_screen(
                config=config,
                doh_urls=["https://example.com/dns-query"],
                hosts_manager=None,
                optimize_dns_report_store=None,
                stats=stats,
                clear=True,
            )

        output = "".join(fake_stdout.parts)
        self.assertIn("\033[2J\033[H", output)
        self.assertIn("Local HTTP proxy: http://0.0.0.0:8080", output)
        self.assertIn("DoH endpoints:", output)
        self.assertIn("Sent: 1.0 KB", output)
        self.assertIn("Received: 2.0 KB", output)


if __name__ == "__main__":
    unittest.main()
