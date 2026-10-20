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
