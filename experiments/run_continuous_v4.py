"""Continuous live monitoring with V4 inference. No VPN switching."""

import argparse
import csv
import math
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

from experiments.collect_windows_live import measure_window
from src.monitor.decision_engine import DecisionEngine
from src.monitor.reachability import assess_reachability


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows", type=int, default=6)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--attempts", type=int, default=5)
    args = parser.parse_args()

    if args.windows < 1 or args.seconds <= 0 or args.attempts < 1:
        parser.error("All numeric arguments must be positive")

    bundle = joblib.load("models/v4_random_forest_candidate.joblib")
    model = bundle["model"]
    features = list(bundle["features"])
    engine = DecisionEngine(required_windows=3)

    output_dir = Path("data/processed/live")
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output = output_dir / f"continuous_v4_{stamp}.csv"

    fields = [
        "timestamp_utc", "tcp_connect_mean_ms",
        "tcp_connect_std_ms", "tcp_failure_pct",
        "icmp_nonresponse_pct", "interface_before",
        "interface_after", "route_stable",
        "reachability", "prediction", "confidence", "routing_action",
        "reason", "vpn_path_verified",
    ]

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for index in range(args.windows):
            measurement = measure_window(
                "1.1.1.1", 443, args.seconds, args.attempts
            )

            values = [float(measurement[name]) for name in features]

            reachability = assess_reachability(
                measurement["tcp_connect_mean_ms"],
                measurement["tcp_failure_pct"],
            )

            if reachability == "PATH_UNREACHABLE":
                prediction = "NOT_EVALUATED"
                confidence = 0.0
                action = "MONITOR"
                reason = "Observed TCP outage; ML inference skipped"
                engine = DecisionEngine(required_windows=3)
            elif not all(math.isfinite(value) for value in values):
                prediction = "INVALID_MEASUREMENT"
                confidence = 0.0
                action = "MONITOR"
                reason = "Insufficient valid network measurements"
                engine = DecisionEngine(required_windows=3)
            else:
                frame = pd.DataFrame([values], columns=features)
                prediction = str(model.predict(frame)[0])
                confidence = float(max(model.predict_proba(frame)[0]))

                action, reason = engine.decide(
                    prediction=prediction,
                    vote_share=confidence,
                    tcp_mean_ms=measurement["tcp_connect_mean_ms"],
                )

            # An evaluation request is NOT permission to switch.
            row = {
                **{key: measurement[key] for key in fields if key in measurement},
                "reachability": reachability,
                "prediction": prediction,
                "confidence": round(confidence, 4),
                "routing_action": action,
                "reason": reason,
                "vpn_path_verified": False,
            }
            writer.writerow(row)
            file.flush()

            print(
                f"[{index + 1}/{args.windows}] "
                f"TCP={measurement['tcp_connect_mean_ms']}ms | "
                f"ML={prediction} ({confidence:.1%}) | "
                f"Decision={action} | "
                f"Interface={measurement['interface_after'] or 'unknown'}"
            )

    print(f"\nSaved: {output}")
    print("Automatic VPN switching: DISABLED")


if __name__ == "__main__":
    main()
