from src.monitor.decision_engine import DecisionEngine
from src.monitor.route_comparator import RouteComparator


class AdaptiveRoutingController:
    """Recommendation-only adaptive routing controller."""

    def __init__(self, required_windows=3, min_improvement=0.15):
        self.decision_engine = DecisionEngine(
            required_windows=required_windows
        )
        self.comparator = RouteComparator(
            min_improvement=min_improvement
        )

    def evaluate(
        self,
        prediction,
        confidence,
        current_route,
        alternatives,
    ):
        action, reason = self.decision_engine.decide(
            prediction=prediction,
            vote_share=confidence,
            tcp_mean_ms=current_route.latency_ms,
        )

        if action != "EVALUATE_ALTERNATIVES":
            return action, current_route.name, reason

        route_action, selected_route, comparison_reason = (
            self.comparator.recommend(current_route, alternatives)
        )

        if route_action == "RECOMMEND_SWITCH":
            return (
                "RECOMMEND_SWITCH",
                selected_route,
                comparison_reason,
            )

        return (
            "KEEP",
            current_route.name,
            comparison_reason,
        )

    def evaluate_with_evidence(
        self,
        prediction,
        confidence,
        current_route,
        alternatives,
        path_evidence=None,
    ):
        """Do not recommend a switch without independently verified probes."""
        action, selected, reason = self.evaluate(
            prediction,
            confidence,
            current_route,
            alternatives,
        )

        if action != "RECOMMEND_SWITCH":
            return action, selected, reason

        # The existing route-inspection module reports route-selection
        # evidence only. That is NOT sufficient to verify VPN traffic.
        return (
            "MONITOR",
            current_route.name,
            "Switch blocked: actual probe-to-VPN-path verification "
            "has not been implemented",
        )
