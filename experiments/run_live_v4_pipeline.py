"""Run V4 inference and routing decisions on recorded live measurements."""

import argparse
import csv
import math
from pathlib import Path

import joblib
import pandas as pd

from src.monitor.decision_engine import DecisionEngine


MODEL_PATH = Path("models/v4_random_forest_candidate.joblib")
FEATURES = [
    "tcp_connect_mean_ms",
    "tcp_connect_std_ms",
    "tcp_failure_pct",
    "icmp_nonresponse_pct",
]


def run_pipeline(input_csv, output_csv, model_path=MODEL_PATH):
    bundle = joblib.load(model_path)
    model = bundle["model"]

    expected = list(bundle["features"])
    if expected != FEATURES:
        raise ValueError(
            f"Unexpected model features: {expected}"
        )

    data = pd.read_csv(input_csv)

    missing = [feature for feature in FEATURES if feature not in data.columns]
    if missing:
        raise ValueError(f"Missing features: {missing}")

    engine = DecisionEngine(required_windows=3)
    results = []

    for _, row in data.iterrows():
        values = [float(row[feature]) for feature in FEATURES]

        # Do not pass invalid measurements to the model.
        if not all(math.isfinite(value) for value in values):
            results.append({
                "timestamp_utc": row["timestamp_utc"],
                "prediction": "INVALID_MEASUREMENT",
                "confidence": 0.0,
                "routing_action": "MONITOR",
                "reason": "Non-finite network measurements",
            })
            continue

        frame = pd.DataFrame(
            [values],
            columns=FEATURES,
        )

        prediction = str(model.predict(frame)[0])
        probabilities = model.predict_proba(frame)[0]
        confidence = float(max(probabilities))

        action, reason = engine.decide(
            prediction=prediction,
            vote_share=confidence,
            tcp_mean_ms=float(row["tcp_connect_mean_ms"]),
        )

        results.append({
            "timestamp_utc": row["timestamp_utc"],
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "routing_action": action,
            "reason": reason,
        })

    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    with output_csv.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp_utc",
                "prediction",
                "confidence",
                "routing_action",
                "reason",
            ],
        )
        writer.writeheader()
        writer.writerows(results)

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    results = run_pipeline(args.input, args.output)

    for index, result in enumerate(results, start=1):
        print(
            f"Window {index}: "
            f"{result['prediction']} | "
            f"confidence={result['confidence']:.2f} | "
            f"action={result['routing_action']}"
        )

    print(f"\nSaved predictions to: {args.output}")
    print("VPN switching: DISABLED")


if __name__ == "__main__":
    main()
