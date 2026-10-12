import unittest

from src.monitor.adaptive_controller import AdaptiveVPNController
from src.monitor.path_scorer import PathMetrics


class TestAdaptiveController(unittest.TestCase):

    def setUp(self):
        self.controller = AdaptiveVPNController()
        self.paths = [
            PathMetrics("OpenVPN", 260, 5, 25, 10),
            PathMetrics("WireGuard", 45, 0, 5, 10),
        ]

    def degraded(self, paths=None):
        return self.controller.evaluate(
            prediction="HIGH_LATENCY",
            vote_share=0.85,
            tcp_mean_ms=260,
            current_path="OpenVPN",
            measured_paths=self.paths if paths is None else paths,
        )

    def test_requires_three_windows(self):
        self.assertEqual(self.degraded()[0], "MONITOR")
        self.assertEqual(self.degraded()[0], "MONITOR")
        self.assertEqual(self.degraded()[0], "SWITCH_RECOMMENDED")

    def test_healthy_window_resets_streak(self):
        self.degraded()
        self.degraded()

        action, _, _ = self.controller.evaluate(
            prediction="NORMAL",
            vote_share=0.99,
            tcp_mean_ms=35,
            current_path="OpenVPN",
            measured_paths=self.paths,
        )

        self.assertEqual(action, "KEEP")
        self.assertEqual(self.degraded()[0], "MONITOR")

    def test_missing_alternative(self):
        self.degraded()
        self.degraded()
        action, _, _ = self.degraded(paths=[self.paths[0]])
        self.assertEqual(action, "MONITOR")

    def test_no_repeated_switch_recommendation(self):
        for _ in range(3):
            self.degraded()

        action, _, _ = self.degraded()
        self.assertEqual(action, "MONITOR")


if __name__ == "__main__":
    unittest.main()
