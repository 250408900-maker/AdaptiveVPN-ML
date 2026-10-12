from src.monitor.measurement_validation import validate_measurement, comparable
"""Experimental VPN path ranking. Does not switch VPNs."""

from dataclasses import dataclass
import math
import time


@dataclass(frozen=True)
class PathMetrics:
    name: str
    latency_ms: float
    failure_pct: float
    jitter_ms: float
    samples: int
    measured_at: float = 0.0
    method: str = 'tcp_connect'
    target: str = '1.1.1.1:443'


def score_path(path: PathMetrics, current_path: str) -> float:
    """Lower score is better. Return infinity for invalid metrics."""
    values = (
        path.latency_ms,
        path.failure_pct,
        path.jitter_ms,
    )

    if (
        path.samples < 5
        or not all(math.isfinite(v) for v in values)
        or any(v < 0 for v in values)
        or path.failure_pct > 100
    ):
        return math.inf

    latency_cost = path.latency_ms
    failure_cost = path.failure_pct * 15.0
    jitter_cost = path.jitter_ms * 2.0
    switch_cost = 25.0 if path.name != current_path else 0.0

    return (
        latency_cost
        + failure_cost
        + jitter_cost
        + switch_cost
    )


def rank_paths(paths, current_path):
    """Rank measured paths; do not invent missing measurements."""
    names = [p.name for p in paths]

    if len(names) != len(set(names)):
        raise ValueError("Duplicate path names")

    now = time.time()
    current = next((p for p in paths if p.name == current_path), None)

    if current is None:
        return []

    current_valid, _ = validate_measurement(current, now)

    if not current_valid:
        return []

    paths = [
        p for p in paths
        if validate_measurement(p, now)[0]
        and comparable(p, current)
    ]

    results = [
        (p.name, score_path(p, current_path))
        for p in paths
    ]

    return sorted(results, key=lambda item: item[1])


def recommend(paths, current_path, min_improvement=15.0):
    """Recommend switching only with a meaningful score improvement."""
    ranked = rank_paths(paths, current_path)
    if not ranked:
        return "MONITOR", "No fresh comparable measurements", []

    scores = dict(ranked)

    if current_path not in scores:
        return "MONITOR", "Current path has no measurement", ranked

    current_score = scores[current_path]

    if not math.isfinite(current_score):
        return "MONITOR", "Current path metrics are invalid", ranked

    valid_alternatives = [
        (name, score)
        for name, score in ranked
        if name != current_path and math.isfinite(score)
    ]

    if not valid_alternatives:
        return "MONITOR", "No measured alternatives", ranked

    best_name, best_score = valid_alternatives[0]

    if current_score - best_score >= min_improvement:
        return (
            "SWITCH_RECOMMENDED",
            f"{best_name} has a lower measured path cost",
            ranked,
        )

    return "KEEP", "No alternative clears the improvement threshold", ranked


if __name__ == "__main__":
    # Synthetic values for a functionality test, NOT live VPN measurements.
    example_paths = [
        PathMetrics("WireGuard", 45, 0, 5, 10),
        PathMetrics("OpenVPN", 60, 0, 9, 10),
        PathMetrics("VLESS", 85, 0, 12, 10),
    ]

    action, reason, ranking = recommend(
        example_paths,
        current_path="OpenVPN",
    )

    print("ACTION:", action)
    print("REASON:", reason)
    print("RANKING (lower is better):")

    for name, score in ranking:
        print(f"  {name}: {score:.2f}")



