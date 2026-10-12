import math
import unittest

from src.monitor.path_scorer import (
    PathMetrics,
    recommend,
    rank_paths,
)


class TestPathScorer(unittest.TestCase):

    def test_keep_current_path(self):
        paths = [
            PathMetrics("OpenVPN", 60, 0, 9, 10),
            PathMetrics("WireGuard", 45, 0, 5, 10),
        ]
        action, _, _ = recommend(paths, "OpenVPN")
        self.assertEqual(action, "KEEP")

    def test_switch_to_better_path(self):
        paths = [
            PathMetrics("OpenVPN", 250, 5, 30, 10),
            PathMetrics("WireGuard", 40, 0, 4, 10),
        ]
        action, reason, _ = recommend(paths, "OpenVPN")
        self.assertEqual(action, "SWITCH_RECOMMENDED")
        self.assertIn("WireGuard", reason)

    def test_missing_alternative(self):
        paths = [PathMetrics("OpenVPN", 60, 0, 9, 10)]
        action, _, _ = recommend(paths, "OpenVPN")
        self.assertEqual(action, "MONITOR")

    def test_invalid_measurements(self):
        paths = [
            PathMetrics("OpenVPN", 60, 0, 9, 10),
            PathMetrics("WireGuard", math.nan, 0, 4, 10),
        ]
        action, _, ranking = recommend(paths, "OpenVPN")
        self.assertEqual(action, "MONITOR")
        self.assertTrue(math.isinf(dict(ranking)["WireGuard"]))

    def test_unstable_path_penalized(self):
        paths = [
            PathMetrics("OpenVPN", 60, 0, 5, 10),
            PathMetrics("WireGuard", 40, 20, 5, 10),
        ]
        ranking = rank_paths(paths, "OpenVPN")
        self.assertEqual(ranking[0][0], "OpenVPN")

    def test_insufficient_samples(self):
        paths = [
            PathMetrics("OpenVPN", 60, 0, 5, 10),
            PathMetrics("WireGuard", 20, 0, 2, 2),
        ]
        action, _, _ = recommend(paths, "OpenVPN")
        self.assertEqual(action, "MONITOR")


if __name__ == "__main__":
    unittest.main()
