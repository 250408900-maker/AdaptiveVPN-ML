from src.monitor.decision_engine import DecisionEngine

engine = DecisionEngine()

for i in range(1, 6):
    action, reason = engine.decide(
        prediction="NORMAL",
        vote_share=0.88,
        tcp_mean_ms=200.65,
    )
    print(f"Window {i}: {action} | {reason}")

print("\nRecovery:")
print(engine.decide("NORMAL", 0.88, tcp_mean_ms=0.65))

def test_normal_prediction_with_persistent_latency():
    from src.monitor.decision_engine import DecisionEngine

    engine = DecisionEngine()
    actions = [
        engine.decide("NORMAL", 0.88, tcp_mean_ms=200.65)[0]
        for _ in range(3)
    ]
    assert actions == [
        "MONITOR",
        "MONITOR",
        "EVALUATE_ALTERNATIVES",
    ]


def test_recovery_resets_latency_streak():
    from src.monitor.decision_engine import DecisionEngine

    engine = DecisionEngine()
    engine.decide("NORMAL", 0.88, tcp_mean_ms=200.65)
    engine.decide("NORMAL", 0.88, tcp_mean_ms=200.65)

    assert engine.decide("NORMAL", 0.88, tcp_mean_ms=0.65)[0] == "KEEP"
    assert engine.degraded_count == 0
