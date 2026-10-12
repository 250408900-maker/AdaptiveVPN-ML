import time
import unittest

from src.monitor.adaptive_controller_v2 import AdaptiveVPNControllerV2
from src.monitor.path_scorer_v2 import PathMetrics


class TestControllerV2(unittest.TestCase):

    def setUp(self):
        self.controller = AdaptiveVPNControllerV2()
        now = time.time()

        self.current = PathMetrics(
            "OpenVPN", 260, 5, 25, 10,
            measured_at=now - 10,
            method="tcp_connect",
            target="1.1.1.1:443",
        )

        self.better = PathMetrics(
            "WireGuard", 45, 0, 5, 10,
            measured_at=now - 10,
            method="tcp_connect",
            target="1.1.1.1:443",
        )

    def evaluate_three(self, paths):
        results = []

        for _ in range(3):
            results.append(
                self.controller.evaluate(
                    prediction="HIGH_LATENCY",
                    vote_share=0.85,
                    tcp_mean_ms=260,
                    current_path="OpenVPN",
                    measured_paths=paths,
                )
            )

        return results

    def test_fresh_alternative(self):
        results = self.evaluate_three(
            [self.current, self.better]
        )

        self.assertEqual(results[0][0], "MONITOR")
        self.assertEqual(results[1][0], "MONITOR")
        self.assertEqual(
            results[2][0],
            "SWITCH_RECOMMENDED",
        )

    def test_stale_alternative(self):
        stale = PathMetrics(
            "WireGuard", 45, 0, 5, 10,
            measured_at=time.time() - 3600,
            method="tcp_connect",
            target="1.1.1.1:443",
        )

        results = self.evaluate_three(
            [self.current, stale]
        )

        self.assertEqual(results[2][0], "MONITOR")

    def test_incomparable_alternative(self):
        incompatible = PathMetrics(
            "VLESS", 45, 0, 5, 10,
            measured_at=time.time() - 10,
            method="https_total",
            target="example.com:443",
        )

        results = self.evaluate_three(
            [self.current, incompatible]
        )

        self.assertEqual(results[2][0], "MONITOR")


if __name__ == "__main__":
    unittest.main()
