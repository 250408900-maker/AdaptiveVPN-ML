from src.monitor.reachability import assess_reachability


def test_complete_outage():
    assert assess_reachability(float("nan"), 100) == "PATH_UNREACHABLE"


def test_healthy_connection():
    assert assess_reachability(25, 0) == "REACHABLE"


def test_partial_failure():
    assert assess_reachability(100, 40) == "DEGRADED_CONNECTIVITY"


def test_missing_latency_without_failures():
    assert assess_reachability(float("nan"), 0) == "INVALID_MEASUREMENT"


def test_inconsistent_total_failure():
    assert assess_reachability(25, 100) == "INVALID_MEASUREMENT"
