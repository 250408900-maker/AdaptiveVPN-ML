from src.monitor.route_comparator import RouteMetrics, RouteComparator


def test_recommends_better_route():
    current = RouteMetrics("direct", 250, 15, 5)
    vpn = RouteMetrics("wireguard", 60, 5, 0)
    assert RouteComparator().recommend(current, [vpn])[0] == "RECOMMEND_SWITCH"


def test_avoids_small_improvement():
    current = RouteMetrics("direct", 100, 5, 0)
    vpn = RouteMetrics("wireguard", 95, 5, 0)
    assert RouteComparator().recommend(current, [vpn])[0] == "KEEP"


def test_no_alternative():
    current = RouteMetrics("direct", 100, 5, 0)
    assert RouteComparator().recommend(current, [])[0] == "KEEP"


def test_rejects_invalid_metrics():
    import pytest
    with pytest.raises(ValueError):
        RouteMetrics("direct", -1, 5, 0)
