"""Adaptive VPN controller V2. Simulation only."""

from src.monitor.decision_engine import DecisionEngine
from src.monitor.path_scorer_v2 import recommend


class AdaptiveVPNControllerV2:
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

        return recommend(measured_paths, current_path)
