from dataclasses import dataclass
from typing import Optional

from src.monitor.path_scorer_v2 import PathMetrics, recommend


@dataclass(frozen=True)
class VerifiedPath:
    metrics: PathMetrics
    observed_interface: Optional[str] = None
    expected_interface: Optional[str] = None
    verification_method: str = ""

    @property
    def verified(self):
        return (
            bool(self.observed_interface)
            and bool(self.expected_interface)
            and self.observed_interface == self.expected_interface
            and self.verification_method in {
                "os_route_lookup",
                "bound_interface_probe",
            }
        )


def recommend_verified(paths, current_path, min_improvement=15.0):
    verified = [
        item.metrics
        for item in paths
        if item.verified
    ]

    if current_path not in {p.name for p in verified}:
        return "MONITOR", "Current path not verified", []

    if len(verified) < 2:
        return "MONITOR", "No verified alternative path", []

    return recommend(
        verified,
        current_path=current_path,
        min_improvement=min_improvement,
    )
