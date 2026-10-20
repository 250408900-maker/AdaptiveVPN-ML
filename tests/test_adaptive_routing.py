from src.monitor.adaptive_routing import AdaptiveRoutingController
from src.monitor.route_comparator import RouteMetrics


def test_waits_for_sustained_degradation():
    controller = AdaptiveRoutingController()
    current = RouteMetrics("direct", 250, 15, 5)
    alternative = RouteMetrics("wireguard", 60, 5, 0)

    assert controller.evaluate("HIGH_LATENCY", 0.9, current, [alternative])[0] == "MONITOR"
    assert controller.evaluate("HIGH_LATENCY", 0.9, current, [alternative])[0] == "MONITOR"

    action, selected, _ = controller.evaluate(
        "HIGH_LATENCY", 0.9, current, [alternative]
    )
    assert action == "RECOMMEND_SWITCH"
    assert selected == "wireguard"


def test_does_not_switch_without_alternative():
    controller = AdaptiveRoutingController()
    current = RouteMetrics("direct", 250, 15, 5)

    for _ in range(2):
        controller.evaluate("HIGH_LATENCY", 0.9, current, [])

    action, selected, _ = controller.evaluate(
        "HIGH_LATENCY", 0.9, current, []
    )
    assert action == "KEEP"
    assert selected == "direct"


def test_recovery_resets_degradation():
    controller = AdaptiveRoutingController()
    current = RouteMetrics("direct", 250, 15, 5)
    healthy = RouteMetrics("direct", 20, 2, 0)
    alternative = RouteMetrics("wireguard", 60, 5, 0)

    controller.evaluate("HIGH_LATENCY", 0.9, current, [alternative])
    controller.evaluate("HIGH_LATENCY", 0.9, current, [alternative])

    assert controller.evaluate("NORMAL", 0.99, healthy, [alternative])[0] == "KEEP"

    assert controller.evaluate("HIGH_LATENCY", 0.9, current, [alternative])[0] == "MONITOR"
