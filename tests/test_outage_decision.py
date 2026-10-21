from src.monitor.outage_decision import OutageDecisionTracker


def test_three_consecutive_outages_trigger_evaluation():
    tracker = OutageDecisionTracker(required_windows=3)

    assert tracker.evaluate("PATH_UNREACHABLE")[0] == "MONITOR"
    assert tracker.evaluate("PATH_UNREACHABLE")[0] == "MONITOR"
    assert tracker.evaluate("PATH_UNREACHABLE")[0] == "EVALUATE_ALTERNATIVES"


def test_no_repeated_evaluation_during_same_outage():
    tracker = OutageDecisionTracker(required_windows=3)

    actions = [
        tracker.evaluate("PATH_UNREACHABLE")[0]
        for _ in range(12)
    ]

    assert actions.count("EVALUATE_ALTERNATIVES") == 1


def test_recovery_resets_outage_counter():
    tracker = OutageDecisionTracker(required_windows=3)

    tracker.evaluate("PATH_UNREACHABLE")
    tracker.evaluate("PATH_UNREACHABLE")
    tracker.evaluate("REACHABLE")

    assert tracker.evaluate("PATH_UNREACHABLE")[0] == "MONITOR"


def test_invalid_measurement_does_not_trigger_evaluation():
    tracker = OutageDecisionTracker(required_windows=3)

    for _ in range(5):
        assert tracker.evaluate("INVALID_MEASUREMENT")[0] == "MONITOR"
