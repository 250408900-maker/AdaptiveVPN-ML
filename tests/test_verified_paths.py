import time

from src.monitor.path_scorer_v2 import PathMetrics
from src.monitor.verified_paths import VerifiedPath, recommend_verified


def make_path(name, latency):
    return PathMetrics(
        name=name,
        latency_ms=latency,
        failure_pct=0,
        jitter_ms=2,
        samples=20,
        measured_at=time.time(),
    )


def test_rejects_unverified_alternative():
    current = VerifiedPath(
        make_path("direct", 250),
        observed_interface="Wi-Fi",
        expected_interface="Wi-Fi",
        verification_method="os_route_lookup",
    )

    alternative = VerifiedPath(
        make_path("WireGuard", 50)
    )

    action, _, _ = recommend_verified(
        [current, alternative],
        "direct",
    )

    assert action == "MONITOR"


def test_rejects_unverified_current_path():
    current = VerifiedPath(make_path("direct", 250))

    action, _, _ = recommend_verified(
        [current],
        "direct",
    )

    assert action == "MONITOR"


def test_verified_paths_can_be_compared():
    current = VerifiedPath(
        make_path("direct", 250),
        observed_interface="Wi-Fi",
        expected_interface="Wi-Fi",
        verification_method="os_route_lookup",
    )

    alternative = VerifiedPath(
        make_path("WireGuard", 50),
        observed_interface="wg0",
        expected_interface="wg0",
        verification_method="os_route_lookup",
    )

    action, _, _ = recommend_verified(
        [current, alternative],
        "direct",
    )

    assert action == "SWITCH_RECOMMENDED"
