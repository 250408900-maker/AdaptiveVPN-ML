"""Simulation-only controller for adaptive VPN recommendations."""

from src.monitor.decision_engine import DecisionEngine
from src.monitor.path_scorer import PathMetrics, recommend


class AdaptiveVPNController:
    def __init__(self):
        self.engine = DecisionEngine()

    def evaluate(
        self,
        prediction,
        vote_share,
        tcp_mean_ms,
        current_path,
        measured_paths,
    ):
        action, reason = self.engine.decide(
            prediction,
            vote_share,
            tcp_mean_ms=tcp_mean_ms,
        )

        if action != "EVALUATE_ALTERNATIVES":
            return action, reason, []

        recommendation, explanation, ranking = recommend(
            measured_paths,
            current_path,
        )

        return recommendation, explanation, ranking


if __name__ == "__main__":
    controller = AdaptiveVPNController()

    # Synthetic test data, not actual VPN measurements.
    paths = [
        PathMetrics("OpenVPN", 260, 5, 25, 10),
        PathMetrics("WireGuard", 45, 0, 5, 10),
        PathMetrics("VLESS", 90, 0, 12, 10),
    ]

    for window in range(1, 4):
        action, reason, ranking = controller.evaluate(
            prediction="HIGH_LATENCY",
            vote_share=0.85,
            tcp_mean_ms=260,
            current_path="OpenVPN",
            measured_paths=paths,
        )

        print(f"Window {window}: {action} | {reason}")

        for name, score in ranking:
            print(f"  {name}: {score:.2f}")
