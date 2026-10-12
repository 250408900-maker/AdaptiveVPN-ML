import time
import unittest

from src.monitor.path_scorer_v2 import PathMetrics, recommend


class TestPathScorerV2(unittest.TestCase):

    def make_path(self, name, latency, age=10, method="tcp_connect"):
        return PathMetrics(
            name=name,
            latency_ms=latency,
            failure_pct=0,
            jitter_ms=5,
            samples=10,
            measured_at=time.time() - age,
            method=method,
            target="1.1.1.1:443",
        )

    def test_stale_current_path(self):
        paths = [self.make_path("OpenVPN", 250, age=3600)]
        action, _, _ = recommend(paths, "OpenVPN")
        self.assertEqual(action, "MONITOR")

    def test_fresh_better_alternative(self):
        paths = [
            self.make_path("OpenVPN", 250),
            self.make_path("WireGuard", 40),
        ]
        action, _, _ = recommend(paths, "OpenVPN")
        self.assertEqual(action, "SWITCH_RECOMMENDED")

    def test_stale_alternative_excluded(self):
        paths = [
            self.make_path("OpenVPN", 250),
            self.make_path("WireGuard", 40, age=3600),
        ]
        action, _, ranking = recommend(paths, "OpenVPN")
        self.assertEqual(action, "MONITOR")
        self.assertNotIn("WireGuard", dict(ranking))

    def test_incomparable_method_excluded(self):
        paths = [
            self.make_path("OpenVPN", 250),
            self.make_path("VLESS", 40, method="https_total"),
        ]
        action, _, ranking = recommend(paths, "OpenVPN")
        self.assertEqual(action, "MONITOR")
        self.assertNotIn("VLESS", dict(ranking))


if __name__ == "__main__":
    unittest.main()
