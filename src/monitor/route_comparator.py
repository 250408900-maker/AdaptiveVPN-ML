from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True)
class RouteMetrics:
    name: str
    latency_ms: float
    jitter_ms: float
    failure_pct: float

    def __post_init__(self):
        if not self.name.strip():
            raise ValueError("Route name is required")
        for value in (self.latency_ms, self.jitter_ms, self.failure_pct):
            if not isfinite(value) or value < 0:
                raise ValueError("Metrics must be finite and nonnegative")
        if self.failure_pct > 100:
            raise ValueError("Failure percentage cannot exceed 100")


class RouteComparator:
    def __init__(self, min_improvement=0.15):
        if not 0 <= min_improvement < 1:
            raise ValueError("min_improvement must be between 0 and 1")
        self.min_improvement = min_improvement

    @staticmethod
    def score(route):
        return (
            route.latency_ms
            + 2 * route.jitter_ms
            + 10 * route.failure_pct
        )

    def recommend(self, current, alternatives):
        if not alternatives:
            return "KEEP", current.name, "No alternative route measured"

        candidates = [r for r in alternatives if r.name != current.name]
        if not candidates:
            return "KEEP", current.name, "No distinct alternative route"

        best = min(candidates, key=self.score)
        current_score = self.score(current)
        best_score = self.score(best)

        if current_score == 0 or best_score >= current_score * (1 - self.min_improvement):
            return "KEEP", current.name, "Insufficient measured improvement"

        return (
            "RECOMMEND_SWITCH",
            best.name,
            f"Estimated score improvement: {(1 - best_score / current_score):.1%}"
        )
