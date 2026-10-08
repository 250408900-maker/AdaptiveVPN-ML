
import math


class DecisionEngine:
    """
    Experimental decision engine.

    Confirms persistent measured degradation even when
    ML predictions alternate between degraded classes.

    Does not switch or reroute any VPN connection.
    """

    def __init__(
        self,
        required_windows=3,
        min_vote=0.65,
        high_latency_ms=200.0,
    ):
        self.required_windows = required_windows
        self.min_vote = min_vote
        self.high_latency_ms = high_latency_ms
        self.degraded_count = 0
        self.recommendation_issued = False

    def reset(self):
        self.degraded_count = 0
        self.recommendation_issued = False

    def decide(
        self,
        prediction,
        vote_share,
        tcp_mean_ms=None,
    ):
        valid_latency = (
            tcp_mean_ms is not None
            and math.isfinite(float(tcp_mean_ms))
        )

        measured_high_latency = (
            valid_latency
            and float(tcp_mean_ms) >= self.high_latency_ms
        )

        degraded_prediction = prediction in (
            "HIGH_LATENCY",
            "PACKET_LOSS",
        )

        # For now, require both measured high latency
        # and a degraded ML prediction.
        # The model vote is logged, but it cannot veto
        # repeated objective latency measurements.
        if measured_high_latency and degraded_prediction:
            self.degraded_count += 1

            if self.degraded_count < self.required_windows:
                return (
                    "MONITOR",
                    "Confirming degradation: "
                    f"{self.degraded_count}/{self.required_windows}",
                )

            if not self.recommendation_issued:
                self.recommendation_issued = True
                return (
                    "EVALUATE_ALTERNATIVES",
                    "Persistent high TCP latency; "
                    "compare available VPN paths",
                )

            return (
                "MONITOR",
                "Recommendation already issued",
            )

        # A healthy reading clears the streak.
        self.reset()

        if (
            prediction == "NORMAL"
            and vote_share >= self.min_vote
            and valid_latency
            and not measured_high_latency
        ):
            return "KEEP", "Network appears healthy"

        return "MONITOR", "Degradation not confirmed"


if __name__ == "__main__":
    engine = DecisionEngine()

    samples = [
        ("PACKET_LOSS", 0.63, 657.4),
        ("HIGH_LATENCY", 0.75, 468.1),
        ("PACKET_LOSS", 0.68, 594.5),
        ("HIGH_LATENCY", 0.87, 508.5),
        ("NORMAL", 0.99, 18.0),
    ]

    for index, (prediction, vote, latency) in enumerate(
        samples, start=1
    ):
        action, reason = engine.decide(
            prediction,
            vote,
            tcp_mean_ms=latency,
        )
        print(
            f"Window {index}: {prediction} "
            f"-> {action} | {reason}"
        )
