from src.monitor.adaptive_routing import AdaptiveRoutingController
from src.monitor.route_comparator import RouteMetrics


def test_unverified_paths_never_trigger_switch():
    controller = AdaptiveRoutingController(required_windows=3)

    current = RouteMetrics(
        name="direct",
        latency_ms=300,
        jitter_ms=10,
        failure_pct=0,
    )

    alternative = RouteMetrics(
        name="WireGuard",
        latency_ms=40,
        jitter_ms=2,
        failure_pct=0,
    )

    results = [
        controller.evaluate_with_evidence(
            prediction="HIGH_LATENCY",
            confidence=0.95,
            current_route=current,
            alternatives=[alternative],
        )
        for _ in range(3)
    ]

    assert all(result[0] != "RECOMMEND_SWITCH" for result in results)
    assert results[-1][0] == "MONITOR"


def test_evidence_dictionary_cannot_override_missing_verification():
    controller = AdaptiveRoutingController(required_windows=3)

    current = RouteMetrics("direct", 300, 10, 0)
    alternative = RouteMetrics("WireGuard", 40, 2, 0)

    evidence = {
        "status": "ROUTE_OBSERVED",
        "interface": "Wi-Fi",
        "vpn_path_verified": True,
        "switch_allowed": True,
    }

    results = [
        controller.evaluate_with_evidence(
            "HIGH_LATENCY",
            0.95,
            current,
            [alternative],
            path_evidence=evidence,
        )
        for _ in range(3)
    ]

    assert all(action != "RECOMMEND_SWITCH" for action, _, _ in results)
