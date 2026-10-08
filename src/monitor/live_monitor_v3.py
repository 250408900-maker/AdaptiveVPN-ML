
import argparse
import socket
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from decision_engine import DecisionEngine


ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "models" / "v3_random_forest.joblib"

TARGET = "1.1.1.1"
TCP_PORT = 443
WINDOW_SECONDS = 10


def probe_once():
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", TARGET],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.5,
            check=False,
        )
        icmp_ok = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        icmp_ok = False

    started = time.perf_counter()

    try:
        with socket.create_connection(
            (TARGET, TCP_PORT),
            timeout=2.0,
        ):
            pass

        tcp_ms = (time.perf_counter() - started) * 1000
        tcp_ok = True

    except OSError:
        tcp_ms = None
        tcp_ok = False

    return icmp_ok, tcp_ok, tcp_ms


def collect_window():
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        start = time.monotonic()

        for i in range(WINDOW_SECONDS):
            wait = start + i - time.monotonic()

            if wait > 0:
                time.sleep(wait)

            futures.append(executor.submit(probe_once))

        for future in futures:
            results.append(future.result())

    tcp_times = [
        tcp_ms
        for _, tcp_ok, tcp_ms in results
        if tcp_ok and tcp_ms is not None
    ]

    total = len(results)
    tcp_successes = len(tcp_times)
    icmp_successes = sum(int(r[0]) for r in results)

    return {
        "tcp_connect_mean_ms": (
            statistics.mean(tcp_times)
            if tcp_times else np.nan
        ),
        "tcp_connect_std_ms": (
            statistics.stdev(tcp_times)
            if len(tcp_times) >= 2 else np.nan
        ),
        "tcp_failure_pct": (
            100 * (total - tcp_successes) / total
        ),
        "icmp_nonresponse_pct": (
            100 * (total - icmp_successes) / total
        ),
    }


def format_ms(value):
    if pd.isna(value):
        return "N/A"
    return f"{value:.1f} ms"


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--windows",
        type=int,
        default=5,
    )

    args = parser.parse_args()

    if args.windows < 1:
        parser.error("--windows must be at least 1")

    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    features = bundle["features"]

    engine = DecisionEngine(
    required_windows=3,
    min_vote=0.65,
    high_latency_ms=200.0,
)

    print("\n======================================")
    print(" AdaptiveVPN-ML LIVE DECISION SYSTEM")
    print("======================================")
    print(f"Target: {TARGET}:{TCP_PORT}")
    print(f"Windows: {args.windows}")
    print("Mode: SIMULATION ONLY")
    print("No VPN changes will be made.")
    print("======================================")

    for index in range(1, args.windows + 1):
        print(
            f"\nCollecting window "
            f"{index}/{args.windows}..."
        )

        measurements = collect_window()

        X = pd.DataFrame(
            [measurements],
            columns=features,
        )

        prediction = model.predict(X)[0]

        probabilities = model.predict_proba(X)[0]
        vote_share = float(max(probabilities))

        action, reason = engine.decide(
            prediction,
            vote_share,
            tcp_mean_ms=measurements["tcp_connect_mean_ms"],
        )

        print("--------------------------------------")
        print(
            "TCP mean:",
            format_ms(
                measurements["tcp_connect_mean_ms"]
            ),
        )
        print(
            "TCP std:",
            format_ms(
                measurements["tcp_connect_std_ms"]
            ),
        )
        print(
            "TCP failures:",
            f'{measurements["tcp_failure_pct"]:.1f}%',
        )
        print(
            "ICMP nonresponse:",
            f'{measurements["icmp_nonresponse_pct"]:.1f}%',
        )
        print("ML prediction:", prediction)
        print("Model vote:", f"{vote_share * 100:.1f}%")
        print("VPN ACTION:", action)
        print("Reason:", reason)
        print("--------------------------------------")

    print("\nLIVE DECISION TEST COMPLETE")


if __name__ == "__main__":
    main()
